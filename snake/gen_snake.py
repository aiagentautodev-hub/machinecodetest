#!/usr/bin/env python3
"""Generate a Snake game PE exe from raw machine code.
   Runs in Windows console. Uses kernel32 Console API."""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000
BSS_RVA    = 0x3000   # uninitialized data (snake body array, game state)

# Game constants
BOARD_W = 40
BOARD_H = 20
MAX_SNAKE = 800  # max snake length (x,y pairs = 1600 bytes)

# ============================================================
# Mini assembler
# ============================================================
class Asm:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []

    def pos(self):
        return len(self.code)

    def emit(self, bs):
        self.code.extend(bs)

    def label(self, name):
        self.labels[name] = self.pos()

    def emit_u32(self, val):
        self.emit(struct.pack('<I', val))

    def emit_u16(self, val):
        self.emit(struct.pack('<H', val))

    def jmp(self, label):
        self.emit(b'\xEB')
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    def jmp32(self, label):
        self.emit(b'\xE9')
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')

    def jcc(self, opcode, label):
        self.emit(bytes([opcode]))
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    def jcc32(self, opcode2, label):
        """0F 8x near conditional jump"""
        self.emit(bytes([0x0F, opcode2]))
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')

    def call_local(self, label):
        self.emit(b'\xE8')
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')

    def call_iat(self, addr):
        self.emit(b'\xFF\x15')
        self.emit_u32(addr)

    def jmp_iat(self, addr):
        self.emit(b'\xFF\x25')
        self.emit_u32(addr)

    def resolve(self):
        for off, size, lbl, relative in self.fixups:
            assert lbl in self.labels, f"undefined label: {lbl}"
            target = self.labels[lbl]
            if relative:
                disp = target - (off + size)
                if size == 1:
                    assert -128 <= disp <= 127, f"jump to {lbl} too far: {disp} at code offset {off}"
                    self.code[off] = disp & 0xFF
                else:
                    struct.pack_into('<i', self.code, off, disp)
            else:
                struct.pack_into('<I', self.code, off, target)

    def bytes(self):
        self.resolve()
        return bytes(self.code)

# ============================================================
# .rdata: imports + string data
# ============================================================
def hint_name(hint, name):
    b = struct.pack('<H', hint) + name.encode() + b'\x00'
    if len(b) % 2: b += b'\x00'
    return b

kernel32_funcs = [
    "GetStdHandle",                # 0
    "SetConsoleCursorPosition",    # 1
    "WriteConsoleA",               # 2
    "ReadConsoleInputA",           # 3
    "GetNumberOfConsoleInputEvents", # 4
    "SetConsoleMode",              # 5
    "Sleep",                       # 6
    "ExitProcess",                 # 7
    "GetTickCount",                # 8
    "FillConsoleOutputCharacterA", # 9
    "SetConsoleTitleA",            # 10
]

k32_hns = [hint_name(0, f) for f in kernel32_funcs]
kernel32_name = b"kernel32.dll\x00"

# Build rdata
rdata = bytearray(0x600)

IDT_OFF = 0x00  # 2 entries (1 + null) = 40 bytes

K32_ILT_OFF = 0x30
K32_ILT_SIZE = (len(kernel32_funcs) + 1) * 4
K32_IAT_OFF = K32_ILT_OFF + K32_ILT_SIZE
K32_IAT_SIZE = K32_ILT_SIZE

k32_name_off = K32_IAT_OFF + K32_IAT_SIZE
k32_name_off = (k32_name_off + 3) & ~3
rdata[k32_name_off:k32_name_off+len(kernel32_name)] = kernel32_name

hn_off = (k32_name_off + len(kernel32_name) + 3) & ~3
k32_hn_rvas = []
for hn in k32_hns:
    k32_hn_rvas.append(RDATA_RVA + hn_off)
    rdata[hn_off:hn_off+len(hn)] = hn
    hn_off += len(hn)

# ILT & IAT
for i, rva in enumerate(k32_hn_rvas):
    struct.pack_into('<I', rdata, K32_ILT_OFF + i*4, rva)
    struct.pack_into('<I', rdata, K32_IAT_OFF + i*4, rva)

# IDT
struct.pack_into('<IIIII', rdata, IDT_OFF,
    RDATA_RVA + K32_ILT_OFF, 0, 0, RDATA_RVA + k32_name_off, RDATA_RVA + K32_IAT_OFF)
rdata[20:40] = b'\x00' * 20

# String data
str_off = (hn_off + 3) & ~3

# Border characters and game strings
title_str = b"Snake - Machine Code Edition\x00"
title_rva = RDATA_RVA + str_off
rdata[str_off:str_off+len(title_str)] = title_str
str_off += len(title_str)
str_off = (str_off + 3) & ~3

gameover_str = b" GAME OVER! Press any key... \x00"
gameover_rva = RDATA_RVA + str_off
rdata[str_off:str_off+len(gameover_str)] = gameover_str
str_off += len(gameover_str)
str_off = (str_off + 3) & ~3

# Score label
score_str = b"Score: \x00"
score_rva = RDATA_RVA + str_off
rdata[str_off:str_off+len(score_str)] = score_str
str_off += len(score_str)
str_off = (str_off + 3) & ~3

print(f"rdata used: {hex(str_off)} / 0x600")

IAT = {}
for i, name in enumerate(kernel32_funcs):
    IAT[name] = IMAGE_BASE + RDATA_RVA + K32_IAT_OFF + i * 4

# BSS layout (RVA 0x3000):
# 0x000: snake_x[MAX_SNAKE]  (byte array)
# 0x320: snake_y[MAX_SNAKE]  (byte array)
# 0x640: snake_len (dword)
# 0x644: dir_x (dword, signed)
# 0x648: dir_y (dword, signed)
# 0x64C: food_x (dword)
# 0x650: food_y (dword)
# 0x654: score (dword)
# 0x658: rng_state (dword)
# 0x65C: head_idx (dword) - ring buffer head
# 0x660: tail_idx (dword) - ring buffer tail
# 0x680: char_buf (16 bytes) - temp for WriteConsole
# 0x690: input_rec (32 bytes) - INPUT_RECORD
# 0x6B0: num_events (dword)
# 0x6B4: num_written (dword)

BSS_ABS = IMAGE_BASE + BSS_RVA
SNAKE_X   = BSS_ABS + 0x000
SNAKE_Y   = BSS_ABS + 0x320
SNAKE_LEN = BSS_ABS + 0x640
DIR_X     = BSS_ABS + 0x644
DIR_Y     = BSS_ABS + 0x648
FOOD_X    = BSS_ABS + 0x64C
FOOD_Y    = BSS_ABS + 0x650
SCORE     = BSS_ABS + 0x654
RNG       = BSS_ABS + 0x658
HEAD_IDX  = BSS_ABS + 0x65C
TAIL_IDX  = BSS_ABS + 0x660
CHAR_BUF  = BSS_ABS + 0x680
INPUT_REC = BSS_ABS + 0x690
NUM_EVENTS= BSS_ABS + 0x6B0
NUM_WRITTEN=BSS_ABS + 0x6B4

# ============================================================
# Machine code
# ============================================================
a = Asm()

# Jump to main
a.jmp32('main')

# ============================================================
# set_cursor(x in cl, y in ch) - SetConsoleCursorPosition
# Uses global stdout handle at [HANDLE_LOC]
# COORD is packed as (X:u16, Y:u16) = little endian DWORD
# ============================================================
STDOUT_HANDLE = BSS_ABS + 0x6C0

a.label('set_cursor')
a.emit(b'\x0F\xB6\xC1')              # movzx eax, cl  (x)
a.emit(b'\x0F\xB6\xD5')              # movzx edx, ch  (y)
a.emit(b'\xC1\xE2\x10')              # shl edx, 16
a.emit(b'\x09\xD0')                   # or eax, edx  (COORD packed)
a.emit(b'\x50')                        # push eax (COORD as dword)
a.emit(b'\xFF\x35')                    # push [STDOUT_HANDLE]
a.emit_u32(STDOUT_HANDLE)
a.call_iat(IAT['SetConsoleCursorPosition'])
a.emit(b'\xC3')                        # ret

# ============================================================
# write_char(al = char) - write single char at current cursor
# ============================================================
a.label('write_char')
a.emit(b'\xA2')                        # mov [CHAR_BUF], al
a.emit_u32(CHAR_BUF)
a.emit(b'\x6A\x00')                   # push 0 (reserved)
a.emit(b'\x68')                        # push &NUM_WRITTEN
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x6A\x01')                   # push 1 (nChars)
a.emit(b'\x68')                        # push CHAR_BUF
a.emit_u32(CHAR_BUF)
a.emit(b'\xFF\x35')                    # push [STDOUT_HANDLE]
a.emit_u32(STDOUT_HANDLE)
a.call_iat(IAT['WriteConsoleA'])
a.emit(b'\xC3')                        # ret

# ============================================================
# write_str(esi = ptr to null-terminated string)
# ============================================================
a.label('write_str')
a.emit(b'\x56')                        # push esi (save)
a.label('write_str_loop')
a.emit(b'\x8A\x06')                   # mov al, [esi]
a.emit(b'\x84\xC0')                   # test al, al
a.jcc(0x74, 'write_str_done')         # jz done
a.call_local('write_char')
a.emit(b'\x46')                        # inc esi
a.jmp('write_str_loop')
a.label('write_str_done')
a.emit(b'\x5E')                        # pop esi
a.emit(b'\xC3')                        # ret

# ============================================================
# write_num(eax = number) - write decimal number
# ============================================================
a.label('write_num')
a.emit(b'\x53')                        # push ebx
a.emit(b'\x31\xC9')                    # xor ecx, ecx
a.emit(b'\xBB\x0A\x00\x00\x00')       # mov ebx, 10
a.label('wn_div')
a.emit(b'\x31\xD2')                    # xor edx, edx
a.emit(b'\xF7\xF3')                    # div ebx
a.emit(b'\x52')                        # push edx
a.emit(b'\x41')                        # inc ecx
a.emit(b'\x85\xC0')                    # test eax, eax
a.jcc(0x75, 'wn_div')                 # jnz
a.label('wn_write')
a.emit(b'\x58')                        # pop eax
a.emit(b'\x04\x30')                    # add al, '0'
a.call_local('write_char')
a.emit(b'\x49')                        # dec ecx
a.jcc(0x75, 'wn_write')               # jnz
a.emit(b'\x5B')                        # pop ebx
a.emit(b'\xC3')                        # ret

# ============================================================
# rand() -> eax = pseudo-random number (LCG)
# ============================================================
a.label('rand')
a.emit(b'\xA1')                        # mov eax, [RNG]
a.emit_u32(RNG)
a.emit(b'\x69\xC0\xFD\x43\x03\x00')  # imul eax, eax, 214013
a.emit(b'\x05\xC3\x9E\x26\x00')      # add eax, 2531011
a.emit(b'\xA3')                        # mov [RNG], eax
a.emit_u32(RNG)
a.emit(b'\xC1\xE8\x10')              # shr eax, 16
a.emit(b'\xC3')                        # ret

# ============================================================
# place_food() - random position not on snake
# ============================================================
a.label('place_food')
a.emit(b'\x60')                        # pushad

a.label('pf_retry')
# x = rand() % (BOARD_W - 2) + 1
a.call_local('rand')
a.emit(b'\x31\xD2')                    # xor edx, edx
a.emit(b'\xBB')                        # mov ebx, BOARD_W-2
a.emit_u32(BOARD_W - 2)
a.emit(b'\xF7\xF3')                    # div ebx
a.emit(b'\x42')                        # inc edx
a.emit(b'\x89\x15')                    # mov [FOOD_X], edx
a.emit_u32(FOOD_X)

# y = rand() % (BOARD_H - 2) + 1
a.call_local('rand')
a.emit(b'\x31\xD2')
a.emit(b'\xBB')
a.emit_u32(BOARD_H - 2)
a.emit(b'\xF7\xF3')
a.emit(b'\x42')
a.emit(b'\x89\x15')
a.emit_u32(FOOD_Y)

# Check not on snake - iterate from tail to head
# Simple: check all slots. For small snake this is fine.
a.emit(b'\xA1')                        # mov eax, [TAIL_IDX]
a.emit_u32(TAIL_IDX)
a.emit(b'\x8B\x0D')                   # mov ecx, [HEAD_IDX]
a.emit_u32(HEAD_IDX)

a.label('pf_check_loop')
a.emit(b'\x39\xC8')                   # cmp eax, ecx
a.jcc(0x74, 'pf_ok')                  # je -> not on snake, ok

a.emit(b'\x0F\xB6\x90')              # movzx edx, byte [SNAKE_X + eax]
a.emit_u32(SNAKE_X)
a.emit(b'\x3B\x15')                   # cmp edx, [FOOD_X]
a.emit_u32(FOOD_X)
a.jcc(0x75, 'pf_next')                # jne -> not same x

a.emit(b'\x0F\xB6\x90')              # movzx edx, byte [SNAKE_Y + eax]
a.emit_u32(SNAKE_Y)
a.emit(b'\x3B\x15')                   # cmp edx, [FOOD_Y]
a.emit_u32(FOOD_Y)
a.jcc(0x74, 'pf_retry')               # je -> on snake, retry

a.label('pf_next')
a.emit(b'\x40')                        # inc eax
a.emit(b'\x25')                        # and eax, MAX_SNAKE-1  (ring buffer wrap)
a.emit_u32(MAX_SNAKE - 1)
a.jmp('pf_check_loop')

a.label('pf_ok')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# draw_border()
# ============================================================
a.label('draw_border')
a.emit(b'\x60')                        # pushad

# Top border: row 0
a.emit(b'\x31\xC9')                   # xor ecx, ecx (x=0, y=0 already in ch=0)
a.label('db_top')
a.call_local('set_cursor')
a.emit(b'\xB0\x23')                   # mov al, '#'
a.call_local('write_char')
a.emit(b'\xFE\xC1')                   # inc cl
a.emit(b'\x80\xF9')                   # cmp cl, BOARD_W
a.emit(bytes([BOARD_W]))
a.jcc(0x72, 'db_top')                 # jb

# Bottom border: row BOARD_H-1
a.emit(b'\xB5')                        # mov ch, BOARD_H-1
a.emit(bytes([BOARD_H - 1]))
a.emit(b'\x30\xC9')                   # xor cl, cl
a.label('db_bottom')
a.call_local('set_cursor')
a.emit(b'\xB0\x23')
a.call_local('write_char')
a.emit(b'\xFE\xC1')
a.emit(b'\x80\xF9')
a.emit(bytes([BOARD_W]))
a.jcc(0x72, 'db_bottom')

# Left & right borders
a.emit(b'\xB5\x01')                   # mov ch, 1
a.label('db_sides')
a.emit(b'\x30\xC9')                   # xor cl, cl (x=0)
a.call_local('set_cursor')
a.emit(b'\xB0\x23')
a.call_local('write_char')
a.emit(b'\xB1')                        # mov cl, BOARD_W-1
a.emit(bytes([BOARD_W - 1]))
a.call_local('set_cursor')
a.emit(b'\xB0\x23')
a.call_local('write_char')
a.emit(b'\xFE\xC5')                   # inc ch
a.emit(b'\x80\xFD')                   # cmp ch, BOARD_H-1
a.emit(bytes([BOARD_H - 1]))
a.jcc(0x72, 'db_sides')               # jb

a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# draw_score()
# ============================================================
a.label('draw_score')
a.emit(b'\x60')                        # pushad
# cursor at (0, BOARD_H)
a.emit(b'\x31\xC9')                   # xor ecx, ecx
a.emit(b'\xB5')                        # mov ch, BOARD_H
a.emit(bytes([BOARD_H]))
a.call_local('set_cursor')
a.emit(b'\xBE')                        # mov esi, score_str
a.emit_u32(IMAGE_BASE + score_rva)
a.call_local('write_str')
a.emit(b'\xA1')                        # mov eax, [SCORE]
a.emit_u32(SCORE)
a.call_local('write_num')
a.emit(b'\xB0\x20')                   # mov al, ' '
a.call_local('write_char')
a.call_local('write_char')            # extra spaces to clear old digits
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# MAIN
# ============================================================
a.label('main')
a.emit(b'\x55')                        # push ebp
a.emit(b'\x89\xE5')                    # mov ebp, esp
a.emit(b'\x83\xEC\x20')               # sub esp, 32

# Get stdout handle
a.emit(b'\x6A\xF5')                   # push -11 (STD_OUTPUT_HANDLE)
a.call_iat(IAT['GetStdHandle'])
a.emit(b'\xA3')                        # mov [STDOUT_HANDLE], eax
a.emit_u32(STDOUT_HANDLE)

# Get stdin handle
a.emit(b'\x6A\xF6')                   # push -10 (STD_INPUT_HANDLE)
a.call_iat(IAT['GetStdHandle'])
# Store stdin handle
STDIN_HANDLE = BSS_ABS + 0x6C4
a.emit(b'\xA3')
a.emit_u32(STDIN_HANDLE)

# SetConsoleMode(stdin, ENABLE_EXTENDED_FLAGS=0x0080) - disable line input & echo
a.emit(b'\x68\x80\x00\x00\x00')       # push 0x0080
a.emit(b'\x50')                        # push eax (stdin)
a.call_iat(IAT['SetConsoleMode'])

# Set console title
a.emit(b'\x68')
a.emit_u32(IMAGE_BASE + title_rva)
a.call_iat(IAT['SetConsoleTitleA'])

# Seed RNG with GetTickCount
a.call_iat(IAT['GetTickCount'])
a.emit(b'\xA3')
a.emit_u32(RNG)

# Clear screen: FillConsoleOutputCharacterA(handle, ' ', nLength, COORD(0,0), &written)
# stdcall push right-to-left: &written, COORD, nLength, char, handle
total_cells = (BOARD_W) * (BOARD_H + 2)
a.emit(b'\x68')                        # push &NUM_WRITTEN
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x6A\x00')                   # push COORD(0,0)
a.emit(b'\x68')                        # push total cells
a.emit_u32(total_cells)
a.emit(b'\x6A\x20')                   # push ' ' (cCharacter)
a.emit(b'\xFF\x35')                    # push [STDOUT_HANDLE]
a.emit_u32(STDOUT_HANDLE)
a.call_iat(IAT['FillConsoleOutputCharacterA'])

# Initialize snake: start at center, going right
# head_idx = 3, tail_idx = 0, length = 3
center_x = BOARD_W // 2
center_y = BOARD_H // 2

a.emit(b'\xC7\x05')                   # mov dword [HEAD_IDX], 3
a.emit_u32(HEAD_IDX)
a.emit_u32(3)

a.emit(b'\xC7\x05')                   # mov dword [TAIL_IDX], 0
a.emit_u32(TAIL_IDX)
a.emit_u32(0)

a.emit(b'\xC7\x05')                   # mov dword [SNAKE_LEN], 3
a.emit_u32(SNAKE_LEN)
a.emit_u32(3)

# Snake body: positions 0,1,2 = tail to head
for i in range(3):
    # snake_x[i] = center_x - 2 + i
    a.emit(b'\xC6\x05')               # mov byte [SNAKE_X+i], val
    a.emit_u32(SNAKE_X + i)
    a.emit(bytes([center_x - 2 + i]))
    # snake_y[i] = center_y
    a.emit(b'\xC6\x05')
    a.emit_u32(SNAKE_Y + i)
    a.emit(bytes([center_y]))

# Direction: right (dx=1, dy=0)
a.emit(b'\xC7\x05')
a.emit_u32(DIR_X)
a.emit_u32(1)
a.emit(b'\xC7\x05')
a.emit_u32(DIR_Y)
a.emit_u32(0)

# Score = 0
a.emit(b'\xC7\x05')
a.emit_u32(SCORE)
a.emit_u32(0)

# Draw border
a.call_local('draw_border')

# Place first food
a.call_local('place_food')

# Draw food
a.emit(b'\xA1')                        # mov eax, [FOOD_X]
a.emit_u32(FOOD_X)
a.emit(b'\x88\xC1')                   # mov cl, al
a.emit(b'\xA1')
a.emit_u32(FOOD_Y)
a.emit(b'\x88\xC5')                   # mov ch, al
a.call_local('set_cursor')
a.emit(b'\xB0\x40')                   # mov al, '@' (food)
a.call_local('write_char')

# Draw initial snake
a.emit(b'\xBB\x00\x00\x00\x00')       # mov ebx, 0 (index)
a.label('init_draw_snake')
a.emit(b'\x0F\xB6\x8B')              # movzx ecx, byte [SNAKE_X + ebx]
a.emit_u32(SNAKE_X)
a.emit(b'\x0F\xB6\xAB')              # movzx ebp_tmp... no, use different approach
# Actually ch needs snake_y. Let me use a different register scheme.
# movzx eax, byte [SNAKE_Y + ebx]
a.emit(b'\x0F\xB6\x83')
a.emit_u32(SNAKE_Y)
a.emit(b'\x88\xC5')                   # mov ch, al
a.call_local('set_cursor')
a.emit(b'\xB0\x4F')                   # mov al, 'O' (snake body)
a.call_local('write_char')
a.emit(b'\x43')                        # inc ebx
a.emit(b'\x83\xFB\x03')              # cmp ebx, 3
a.jcc(0x72, 'init_draw_snake')        # jb

a.call_local('draw_score')

# ============================================================
# GAME LOOP
# ============================================================
a.label('game_loop')

# Sleep(100) - game speed
a.emit(b'\x68\x64\x00\x00\x00')       # push 100
a.call_iat(IAT['Sleep'])

# --- Read keyboard input (non-blocking) ---
# GetNumberOfConsoleInputEvents(stdin, &num)
a.emit(b'\x68')
a.emit_u32(NUM_EVENTS)
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_HANDLE)
a.call_iat(IAT['GetNumberOfConsoleInputEvents'])

# if num_events == 0, skip input
a.emit(b'\xA1')
a.emit_u32(NUM_EVENTS)
a.emit(b'\x85\xC0')                   # test eax, eax
a.jcc32(0x84, 'no_input')             # jz no_input (near jump)

# ReadConsoleInputA(stdin, &input_rec, 1, &num_events)
a.emit(b'\x68')
a.emit_u32(NUM_EVENTS)
a.emit(b'\x6A\x01')
a.emit(b'\x68')
a.emit_u32(INPUT_REC)
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_HANDLE)
a.call_iat(IAT['ReadConsoleInputA'])

# Check if it's a KEY_EVENT (EventType at offset 0 = 1) and bKeyDown (offset 4 = 1)
# INPUT_RECORD: EventType(WORD at 0), padding(WORD at 2), Event union at 4
# KEY_EVENT_RECORD: bKeyDown(BOOL at 4), wRepeatCount(WORD at 8),
#   wVirtualKeyCode(WORD at 10), wVirtualScanCode(WORD at 12), uChar(WORD at 14), dwControlKeyState(DWORD at 16)
a.emit(b'\x66\x83\x3D')              # cmp word [INPUT_REC], 1 (KEY_EVENT)
a.emit_u32(INPUT_REC)
a.emit(b'\x01')
a.jcc32(0x85, 'no_input')             # jne no_input

a.emit(b'\x83\x3D')                   # cmp dword [INPUT_REC+4], 0 (bKeyDown)
a.emit_u32(INPUT_REC + 4)
a.emit(b'\x00')
a.jcc32(0x84, 'no_input')             # je no_input

# Read wVirtualKeyCode at INPUT_REC + 10
a.emit(b'\x0F\xB7\x05')              # movzx eax, word [INPUT_REC+10]
a.emit_u32(INPUT_REC + 10)

# VK_LEFT=0x25, VK_UP=0x26, VK_RIGHT=0x27, VK_DOWN=0x28
# Also support WASD: W=0x57, A=0x41, S=0x53, D=0x44

# Check UP (0x26 or 'W'=0x57)
a.emit(b'\x3D\x26\x00\x00\x00')       # cmp eax, 0x26
a.jcc(0x74, 'dir_up')
a.emit(b'\x3D\x57\x00\x00\x00')       # cmp eax, 0x57
a.jcc(0x74, 'dir_up')

# Check DOWN (0x28 or 'S'=0x53)
a.emit(b'\x3D\x28\x00\x00\x00')
a.jcc(0x74, 'dir_down')
a.emit(b'\x3D\x53\x00\x00\x00')
a.jcc(0x74, 'dir_down')

# Check LEFT (0x25 or 'A'=0x41)
a.emit(b'\x3D\x25\x00\x00\x00')
a.jcc(0x74, 'dir_left')
a.emit(b'\x3D\x41\x00\x00\x00')
a.jcc(0x74, 'dir_left')

# Check RIGHT (0x27 or 'D'=0x44)
a.emit(b'\x3D\x27\x00\x00\x00')
a.jcc(0x74, 'dir_right')
a.emit(b'\x3D\x44\x00\x00\x00')
a.jcc(0x74, 'dir_right')

a.jmp32('no_input')

# Direction changes (prevent 180-degree turn)
a.label('dir_up')
a.emit(b'\x83\x3D')                   # cmp dword [DIR_Y], 1
a.emit_u32(DIR_Y)
a.emit(b'\x01')
a.jcc32(0x84, 'no_input')             # can't go up if going down
a.emit(b'\xC7\x05')
a.emit_u32(DIR_X)
a.emit_u32(0)
a.emit(b'\xC7\x05')
a.emit_u32(DIR_Y)
a.emit_u32(0xFFFFFFFF)                # -1
a.jmp32('no_input')

a.label('dir_down')
a.emit(b'\x83\x3D')
a.emit_u32(DIR_Y)
a.emit(b'\xFF')                        # cmp [DIR_Y], -1
a.jcc32(0x84, 'no_input')
a.emit(b'\xC7\x05')
a.emit_u32(DIR_X)
a.emit_u32(0)
a.emit(b'\xC7\x05')
a.emit_u32(DIR_Y)
a.emit_u32(1)
a.jmp32('no_input')

a.label('dir_left')
a.emit(b'\x83\x3D')
a.emit_u32(DIR_X)
a.emit(b'\x01')
a.jcc32(0x84, 'no_input')
a.emit(b'\xC7\x05')
a.emit_u32(DIR_X)
a.emit_u32(0xFFFFFFFF)
a.emit(b'\xC7\x05')
a.emit_u32(DIR_Y)
a.emit_u32(0)
a.jmp32('no_input')

a.label('dir_right')
a.emit(b'\x83\x3D')
a.emit_u32(DIR_X)
a.emit(b'\xFF')
a.jcc32(0x84, 'no_input')
a.emit(b'\xC7\x05')
a.emit_u32(DIR_X)
a.emit_u32(1)
a.emit(b'\xC7\x05')
a.emit_u32(DIR_Y)
a.emit_u32(0)

a.label('no_input')

# --- Move snake ---
# new_head = head position + direction
a.emit(b'\x8B\x1D')                   # mov ebx, [HEAD_IDX]
a.emit_u32(HEAD_IDX)
# Get current head position
# head_idx - 1 (with wrap) is actual head position since head_idx points past head
a.emit(b'\x8D\x43\xFF')              # lea eax, [ebx-1]
a.emit(b'\x25')                        # and eax, MAX_SNAKE-1
a.emit_u32(MAX_SNAKE - 1)

# new_x = snake_x[prev_head] + dir_x
a.emit(b'\x0F\xB6\x88')              # movzx ecx, byte [SNAKE_X + eax]
a.emit_u32(SNAKE_X)
a.emit(b'\x03\x0D')                   # add ecx, [DIR_X]
a.emit_u32(DIR_X)

# new_y = snake_y[prev_head] + dir_y
a.emit(b'\x0F\xB6\x90')              # movzx edx, byte [SNAKE_Y + eax]
a.emit_u32(SNAKE_Y)
a.emit(b'\x03\x15')                   # add edx, [DIR_Y]
a.emit_u32(DIR_Y)

# --- Wall collision ---
a.emit(b'\x85\xC9')                   # test ecx, ecx
a.jcc32(0x8E, 'game_over')            # jle game_over
a.emit(b'\x83\xF9')                   # cmp ecx, BOARD_W-1
a.emit(bytes([BOARD_W - 1]))
a.jcc32(0x8D, 'game_over')            # jge game_over
a.emit(b'\x85\xD2')                   # test edx, edx
a.jcc32(0x8E, 'game_over')            # jle game_over
a.emit(b'\x83\xFA')                   # cmp edx, BOARD_H-1
a.emit(bytes([BOARD_H - 1]))
a.jcc32(0x8D, 'game_over')            # jge game_over

# --- Self collision: check new pos against all snake segments ---
a.emit(b'\x50')                        # push eax (save prev head idx)
a.emit(b'\x51')                        # push ecx
a.emit(b'\x52')                        # push edx

a.emit(b'\x8B\x35')                   # mov esi, [TAIL_IDX]
a.emit_u32(TAIL_IDX)
a.emit(b'\x8B\x3D')                   # mov edi, [HEAD_IDX]
a.emit_u32(HEAD_IDX)

a.label('self_check')
a.emit(b'\x39\xFE')                   # cmp esi, edi
a.jcc(0x74, 'self_ok')                # je -> no collision

a.emit(b'\x0F\xB6\x86')              # movzx eax, byte [SNAKE_X + esi]
a.emit_u32(SNAKE_X)
a.emit(b'\x39\xC1')                   # cmp ecx, eax
a.jcc(0x75, 'self_next')              # jne

a.emit(b'\x0F\xB6\x86')              # movzx eax, byte [SNAKE_Y + esi]
a.emit_u32(SNAKE_Y)
a.emit(b'\x39\xC2')                   # cmp edx, eax
a.jcc(0x74, 'self_hit')               # je -> collision!

a.label('self_next')
a.emit(b'\x46')                        # inc esi
a.emit(b'\x81\xE6')                   # and esi, MAX_SNAKE-1
a.emit_u32(MAX_SNAKE - 1)
a.jmp('self_check')

a.label('self_hit')
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x59')                        # pop ecx
a.emit(b'\x58')                        # pop eax
a.jmp32('game_over')

a.label('self_ok')
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x59')                        # pop ecx
a.emit(b'\x58')                        # pop eax

# --- Place new head ---
# snake_x[head_idx] = new_x (cl), snake_y[head_idx] = new_y (dl)
a.emit(b'\x88\x8B')                   # mov [SNAKE_X + ebx], cl
a.emit_u32(SNAKE_X)
a.emit(b'\x88\x93')                   # mov [SNAKE_Y + ebx], dl
a.emit_u32(SNAKE_Y)

# Draw new head
a.emit(b'\x51')                        # push ecx
a.emit(b'\x52')                        # push edx
a.emit(b'\x88\xC1')                   # mov cl, al -> no, cl = new_x already from ecx
# ecx = new_x (low byte), edx = new_y (low byte)
# set_cursor wants cl=x, ch=y
a.emit(b'\x88\xD5')                   # mov ch, dl
a.call_local('set_cursor')
a.emit(b'\xB0\x4F')                   # mov al, 'O'
a.call_local('write_char')
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x59')                        # pop ecx

# Advance head_idx
a.emit(b'\x43')                        # inc ebx
a.emit(b'\x81\xE3')                   # and ebx, MAX_SNAKE-1
a.emit_u32(MAX_SNAKE - 1)
a.emit(b'\x89\x1D')                   # mov [HEAD_IDX], ebx
a.emit_u32(HEAD_IDX)

# --- Check food ---
a.emit(b'\x3B\x0D')                   # cmp ecx, [FOOD_X]
a.emit_u32(FOOD_X)
a.jcc32(0x85, 'no_eat')               # jne no_eat
a.emit(b'\x3B\x15')                   # cmp edx, [FOOD_Y]
a.emit_u32(FOOD_Y)
a.jcc32(0x85, 'no_eat')               # jne no_eat

# Ate food! Increase score, place new food (don't remove tail)
a.emit(b'\xFF\x05')                    # inc dword [SCORE]
a.emit_u32(SCORE)
a.emit(b'\xFF\x05')                    # inc dword [SNAKE_LEN]
a.emit_u32(SNAKE_LEN)

a.call_local('place_food')
# Draw new food
a.emit(b'\xA1')
a.emit_u32(FOOD_X)
a.emit(b'\x88\xC1')                   # mov cl, al
a.emit(b'\xA1')
a.emit_u32(FOOD_Y)
a.emit(b'\x88\xC5')                   # mov ch, al
a.call_local('set_cursor')
a.emit(b'\xB0\x40')                   # mov al, '@'
a.call_local('write_char')

a.call_local('draw_score')
a.jmp32('game_loop')

a.label('no_eat')

# --- Remove tail (erase old tail, advance tail_idx) ---
a.emit(b'\x8B\x35')                   # mov esi, [TAIL_IDX]
a.emit_u32(TAIL_IDX)

# Erase tail on screen
a.emit(b'\x0F\xB6\x8E')              # movzx ecx, byte [SNAKE_X + esi]
a.emit_u32(SNAKE_X)
a.emit(b'\x0F\xB6\xAE')              # movzx ebp, byte [SNAKE_Y + esi]  -- but we need ch
# Actually let me use a different register
a.emit_u32(SNAKE_Y)
# ebp has y value, but set_cursor needs ch. Let me just move it.
a.emit(b'\x89\xE8')                   # mov eax, ebp  (y in eax)
a.emit(b'\x88\xC5')                   # mov ch, al
a.call_local('set_cursor')
a.emit(b'\xB0\x20')                   # mov al, ' '
a.call_local('write_char')

# Advance tail
a.emit(b'\x46')                        # inc esi
a.emit(b'\x81\xE6')                   # and esi, MAX_SNAKE-1
a.emit_u32(MAX_SNAKE - 1)
a.emit(b'\x89\x35')                   # mov [TAIL_IDX], esi
a.emit_u32(TAIL_IDX)

a.jmp32('game_loop')

# ============================================================
# GAME OVER
# ============================================================
a.label('game_over')

# Show message at center
a.emit(b'\xB1')                        # mov cl, 5
a.emit(bytes([5]))
a.emit(b'\xB5')                        # mov ch, BOARD_H/2
a.emit(bytes([BOARD_H // 2]))
a.call_local('set_cursor')
a.emit(b'\xBE')
a.emit_u32(IMAGE_BASE + gameover_rva)
a.call_local('write_str')

# Wait for keypress: flush input then read one
# Flush by reading all pending
a.label('go_flush')
a.emit(b'\x68')
a.emit_u32(NUM_EVENTS)
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_HANDLE)
a.call_iat(IAT['GetNumberOfConsoleInputEvents'])
a.emit(b'\xA1')
a.emit_u32(NUM_EVENTS)
a.emit(b'\x85\xC0')
a.jcc(0x74, 'go_wait')                # no more events
# Read and discard
a.emit(b'\x68')
a.emit_u32(NUM_EVENTS)
a.emit(b'\x6A\x01')
a.emit(b'\x68')
a.emit_u32(INPUT_REC)
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_HANDLE)
a.call_iat(IAT['ReadConsoleInputA'])
a.jmp('go_flush')

a.label('go_wait')
# Now wait for a real keypress
a.emit(b'\x68')
a.emit_u32(NUM_EVENTS)
a.emit(b'\x6A\x01')
a.emit(b'\x68')
a.emit_u32(INPUT_REC)
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_HANDLE)
a.call_iat(IAT['ReadConsoleInputA'])

# Check if KEY_EVENT with bKeyDown
a.emit(b'\x66\x83\x3D')
a.emit_u32(INPUT_REC)
a.emit(b'\x01')
a.jcc(0x75, 'go_wait')
a.emit(b'\x83\x3D')
a.emit_u32(INPUT_REC + 4)
a.emit(b'\x00')
a.jcc(0x74, 'go_wait')

# Exit
a.emit(b'\x6A\x00')
a.call_iat(IAT['ExitProcess'])

# ============================================================
code_bytes = a.bytes()
print(f"Machine code: {len(code_bytes)} bytes")

# Pad text section (need enough space)
text_size = (len(code_bytes) + 0x1FF) & ~0x1FF  # round up to 0x200
text_section = code_bytes.ljust(text_size, b'\x00')
print(f"Text section: {hex(text_size)}")

# Pad rdata
rdata_size = 0x600
rdata = bytes(rdata[:rdata_size])

# BSS section (virtual only, no raw data)
bss_vsize = 0x1000

# ============================================================
# PE Headers
# ============================================================
dos_header = bytearray(0x80)
dos_header[0:2] = b'MZ'
struct.pack_into('<I', dos_header, 0x3C, 0x80)

pe_sig = b'PE\x00\x00'
n_sections = 3
coff = struct.pack('<HHIIIHH', 0x014C, n_sections, 0, 0, 0, 0xE0, 0x0103)

opt = bytearray(0xE0)
struct.pack_into('<H', opt, 0, 0x10B)
struct.pack_into('<B', opt, 2, 6)
struct.pack_into('<I', opt, 4, text_size)
struct.pack_into('<I', opt, 8, rdata_size)
struct.pack_into('<I', opt, 16, TEXT_RVA)
struct.pack_into('<I', opt, 20, TEXT_RVA)
struct.pack_into('<I', opt, 24, RDATA_RVA)
struct.pack_into('<I', opt, 28, IMAGE_BASE)
struct.pack_into('<I', opt, 32, 0x1000)
struct.pack_into('<I', opt, 36, 0x200)
struct.pack_into('<H', opt, 40, 4)
struct.pack_into('<H', opt, 48, 4)
# SizeOfImage: headers(0x1000) + .text(0x1000) + .rdata(0x1000) + .bss(0x1000)
struct.pack_into('<I', opt, 56, 0x5000)
struct.pack_into('<I', opt, 60, 0x200)
struct.pack_into('<H', opt, 68, 3)             # CONSOLE
struct.pack_into('<I', opt, 72, 0x100000)
struct.pack_into('<I', opt, 76, 0x1000)
struct.pack_into('<I', opt, 80, 0x100000)
struct.pack_into('<I', opt, 84, 0x1000)
struct.pack_into('<I', opt, 92, 16)

struct.pack_into('<II', opt, 96 + 8, RDATA_RVA, 40)
total_iat_off = K32_IAT_OFF
total_iat_size = K32_IAT_SIZE
struct.pack_into('<II', opt, 96 + 96, RDATA_RVA + total_iat_off, total_iat_size)

def section_hdr(name, vsize, rva, rawsize, rawptr, chars):
    h = bytearray(40)
    h[0:len(name)] = name
    struct.pack_into('<I', h, 8, vsize)
    struct.pack_into('<I', h, 12, rva)
    struct.pack_into('<I', h, 16, rawsize)
    struct.pack_into('<I', h, 20, rawptr)
    struct.pack_into('<I', h, 36, chars)
    return bytes(h)

text_raw_off = 0x200
rdata_raw_off = text_raw_off + text_size

text_hdr  = section_hdr(b'.text\x00\x00\x00', text_size, TEXT_RVA, text_size, text_raw_off, 0x60000020)
rdata_hdr = section_hdr(b'.rdata\x00\x00', rdata_size, RDATA_RVA, rdata_size, rdata_raw_off, 0x40000040)
bss_hdr   = section_hdr(b'.bss\x00\x00\x00\x00', bss_vsize, BSS_RVA, 0, 0, 0xC0000080)

headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + text_hdr + rdata_hdr + bss_hdr
headers = headers.ljust(0x200, b'\x00')

exe = headers + text_section + rdata

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snake.exe")
with open(out_path, 'wb') as f:
    f.write(exe)

print(f"\nGenerated {out_path} ({len(exe)} bytes)")
print(f"Machine code: {len(code_bytes)} bytes")
print(f"Sections: .text={hex(text_size)} .rdata={hex(rdata_size)} .bss={hex(bss_vsize)}")
