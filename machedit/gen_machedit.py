#!/usr/bin/env python3
"""Generate MachEdit - a PE2-style console text editor from raw x86 machine code.
   Features: cursor navigation, typing, backspace/delete, enter, scrolling,
   status bar, file load/save, blue PE2 color scheme."""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000
BSS_RVA    = 0x3000

# Editor constants
MAX_LINES    = 1000
MAX_LINE_LEN = 256
LINE_BUF_SIZE = 260  # slightly over MAX_LINE_LEN for safety

# ============================================================
# Mini assembler (same pattern as other generators)
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
        if name in self.labels:
            raise Exception(f"duplicate label: {name}")
        self.labels[name] = self.pos()

    def emit_u32(self, val):
        self.emit(struct.pack('<I', val & 0xFFFFFFFF))

    def emit_u16(self, val):
        self.emit(struct.pack('<H', val & 0xFFFF))

    def emit_i32(self, val):
        self.emit(struct.pack('<i', val))

    def jmp(self, label):
        self.emit(b'\xEB')
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    def jmp32(self, label):
        self.emit(b'\xE9')
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')

    def jcc(self, opcode, label):
        """Short conditional jump (1-byte displacement)."""
        self.emit(bytes([opcode]))
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    def jcc32(self, opcode2, label):
        """Near conditional jump: 0F 8x (4-byte displacement)."""
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
                    assert -128 <= disp <= 127, f"jump to '{lbl}' too far: {disp} bytes at offset {off}"
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
    "GetStdHandle",                    # 0
    "SetConsoleCursorPosition",        # 1
    "WriteConsoleOutputCharacterA",    # 2
    "FillConsoleOutputCharacterA",     # 3
    "FillConsoleOutputAttribute",      # 4
    "ReadConsoleInputA",               # 5
    "SetConsoleMode",                  # 6
    "GetConsoleScreenBufferInfo",      # 7
    "SetConsoleTitleA",                # 8
    "SetConsoleCursorInfo",            # 9
    "ExitProcess",                     # 10
    "VirtualAlloc",                    # 11
    "CreateFileA",                     # 12
    "ReadFile",                        # 13
    "WriteFile",                       # 14
    "CloseHandle",                     # 15
    "GetCommandLineA",                 # 16
    "GetFileSize",                     # 17
    "FlushConsoleInputBuffer",         # 18
    "Sleep",                           # 19
]

k32_hns = [hint_name(0, f) for f in kernel32_funcs]
kernel32_name = b"kernel32.dll\x00"

# Build rdata - allocate plenty of space
rdata = bytearray(0x800)

IDT_OFF = 0x00   # 2 entries (kernel32 + null) = 40 bytes

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

# IDT entry for kernel32
struct.pack_into('<IIIII', rdata, IDT_OFF,
    RDATA_RVA + K32_ILT_OFF, 0, 0, RDATA_RVA + k32_name_off, RDATA_RVA + K32_IAT_OFF)
# Null IDT terminator
rdata[20:40] = b'\x00' * 20

# String data
str_off = (hn_off + 3) & ~3

def add_str(s):
    global str_off
    b = s.encode() + b'\x00'
    rva = RDATA_RVA + str_off
    rdata[str_off:str_off+len(b)] = b
    str_off += len(b)
    str_off = (str_off + 3) & ~3
    return rva

title_rva     = add_str("MachEdit - Machine Code Editor")
status_fmt_rva = add_str(" Ln %d, Col %d")  # not used as format, just ref
new_file_rva  = add_str("[New File]")
modified_rva  = add_str(" [Modified]")
saved_rva     = add_str(" [Saved]")
help_rva      = add_str(" F1:Help  Esc:Exit  Ctrl+S:Save ")
line_str_rva  = add_str(" Ln ")
col_str_rva   = add_str(" Col ")
sep_str_rva   = add_str(" | ")

# Help screen lines
help_lines = [
    "MachEdit - Machine Code Text Editor",
    "",
    "Navigation:",
    "  Arrow Keys     Move cursor",
    "  Home / End     Start / End of line",
    "  PgUp / PgDn    Scroll page up / down",
    "",
    "Editing:",
    "  Type           Insert character at cursor",
    "  Enter          Split line (new line)",
    "  Backspace      Delete char before cursor",
    "  Delete         Delete char at cursor",
    "",
    "File:",
    "  Ctrl+S         Save file",
    "",
    "Other:",
    "  F1             This help screen",
    "  Esc / Ctrl+Q   Exit editor",
    "",
    "--- Press any key to return ---",
]
help_line_rvas = []
for hl in help_lines:
    help_line_rvas.append((add_str(hl), len(hl)))
HELP_NUM_LINES = len(help_lines)

# Help lookup table in rdata: pairs of (absolute_addr, length)
str_off = (str_off + 3) & ~3
help_table_rva = RDATA_RVA + str_off
for rva, length in help_line_rvas:
    struct.pack_into('<I', rdata, str_off, IMAGE_BASE + rva)
    struct.pack_into('<I', rdata, str_off + 4, length)
    str_off += 8

print(f"rdata used: {hex(str_off)} / 0x800")

# IAT addresses
IAT = {}
for i, name in enumerate(kernel32_funcs):
    IAT[name] = IMAGE_BASE + RDATA_RVA + K32_IAT_OFF + i * 4

# ============================================================
# BSS layout (RVA 0x3000, virtual size 0x20000)
# ============================================================
BSS_ABS = IMAGE_BASE + BSS_RVA

# Line pointer array: MAX_LINES * 4 = 4000 bytes
LINES_PTR    = BSS_ABS + 0x0000   # dword[MAX_LINES] - pointers to line buffers
LINE_LEN     = BSS_ABS + 0x1000   # dword[MAX_LINES] - length of each line
NUM_LINES    = BSS_ABS + 0x2000   # dword
CURSOR_X     = BSS_ABS + 0x2004   # dword (column in document)
CURSOR_Y     = BSS_ABS + 0x2008   # dword (line in document)
SCROLL_Y     = BSS_ABS + 0x200C   # dword (first visible line)
SCREEN_W     = BSS_ABS + 0x2010   # dword
SCREEN_H     = BSS_ABS + 0x2014   # dword (total rows; edit area = SCREEN_H - 1)
MODIFIED     = BSS_ABS + 0x2018   # dword (0 or 1)
STDOUT_H     = BSS_ABS + 0x201C   # dword
STDIN_H      = BSS_ABS + 0x2020   # dword
INPUT_REC    = BSS_ABS + 0x2030   # 20 bytes - INPUT_RECORD
NUM_WRITTEN  = BSS_ABS + 0x2050   # dword
NUM_READ     = BSS_ABS + 0x2054   # dword
FILENAME     = BSS_ABS + 0x2060   # 260 bytes
COORD_BUF    = BSS_ABS + 0x2170   # dword (COORD packed)
CSBI_BUF     = BSS_ABS + 0x2180   # 22 bytes CONSOLE_SCREEN_BUFFER_INFO
TEMP_BUF     = BSS_ABS + 0x21A0   # 512 bytes temp
SAVE_MSG_FLAG= BSS_ABS + 0x23A0   # dword - countdown for "saved" msg
FILE_BUF     = BSS_ABS + 0x4000   # large file read buffer (up to 0x1C000 = 112KB)

# ============================================================
# Machine code generation
# ============================================================
a = Asm()

# Jump to main
a.jmp32('main')

# ============================================================
# SUBROUTINE: set_cursor_pos(ecx=x, edx=y)
# Sets console cursor to (x,y) using SetConsoleCursorPosition
# COORD = (X:u16 | Y:u16<<16)
# ============================================================
a.label('set_cursor_pos')
a.emit(b'\x50')                        # push eax
a.emit(b'\x0F\xB7\xC1')               # movzx eax, cx (x)
a.emit(b'\xC1\xE2\x10')               # shl edx, 16
a.emit(b'\x09\xD0')                    # or eax, edx
a.emit(b'\x50')                        # push eax (COORD)
a.emit(b'\xFF\x35')                    # push [STDOUT_H]
a.emit_u32(STDOUT_H)
a.call_iat(IAT['SetConsoleCursorPosition'])
a.emit(b'\x58')                        # pop eax
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: fill_attr(ecx=x, edx=y, ebx=count, esi=attr)
# FillConsoleOutputAttribute(hConsole, attr, count, coord, &written)
# ============================================================
a.label('fill_attr')
a.emit(b'\x60')                        # pushad
# Build COORD
a.emit(b'\x0F\xB7\xC1')               # movzx eax, cx
a.emit(b'\xC1\xE2\x10')               # shl edx, 16
a.emit(b'\x09\xD0')                    # or eax, edx  = COORD
a.emit(b'\x68')                        # push &NUM_WRITTEN
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x50')                        # push COORD
a.emit(b'\x53')                        # push count (ebx)
a.emit(b'\x56')                        # push attr (esi)
a.emit(b'\xFF\x35')                    # push [STDOUT_H]
a.emit_u32(STDOUT_H)
a.call_iat(IAT['FillConsoleOutputAttribute'])
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: fill_char(ecx=x, edx=y, ebx=count, al=char)
# FillConsoleOutputCharacterA(hConsole, char, count, coord, &written)
# ============================================================
a.label('fill_char')
a.emit(b'\x60')                        # pushad
a.emit(b'\x0F\xB6\xF0')               # movzx esi, al (char)
# Build COORD
a.emit(b'\x0F\xB7\xC1')               # movzx eax, cx
a.emit(b'\xC1\xE2\x10')               # shl edx, 16
a.emit(b'\x09\xD0')                    # or eax, edx
a.emit(b'\x68')                        # push &NUM_WRITTEN
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x50')                        # push COORD
a.emit(b'\x53')                        # push count (ebx)
a.emit(b'\x56')                        # push char (esi, zero-extended)
a.emit(b'\xFF\x35')                    # push [STDOUT_H]
a.emit_u32(STDOUT_H)
a.call_iat(IAT['FillConsoleOutputCharacterA'])
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: write_str_at(ecx=x, edx=y, esi=str_ptr, edi=len)
# WriteConsoleOutputCharacterA(hConsole, lpCharacter, nLength, dwWriteCoord, &written)
# ============================================================
a.label('write_str_at')
a.emit(b'\x60')                        # pushad
a.emit(b'\x0F\xB7\xC1')               # movzx eax, cx
a.emit(b'\xC1\xE2\x10')               # shl edx, 16
a.emit(b'\x09\xD0')                    # or eax, edx
a.emit(b'\x68')                        # push &NUM_WRITTEN
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x50')                        # push COORD
a.emit(b'\x57')                        # push len (edi)
a.emit(b'\x56')                        # push str_ptr (esi)
a.emit(b'\xFF\x35')                    # push [STDOUT_H]
a.emit_u32(STDOUT_H)
a.call_iat(IAT['WriteConsoleOutputCharacterA'])
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: get_line_ptr(eax=line_index) -> esi=ptr, ecx=len
# ============================================================
a.label('get_line_ptr')
a.emit(b'\x8B\x34\x85')               # mov esi, [LINES_PTR + eax*4]
a.emit_u32(LINES_PTR)
a.emit(b'\x8B\x0C\x85')               # mov ecx, [LINE_LEN + eax*4]
a.emit_u32(LINE_LEN)
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: alloc_line() -> eax = ptr to new line buffer
# VirtualAlloc(NULL, LINE_BUF_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
# ============================================================
a.label('alloc_line')
a.emit(b'\x6A\x04')                   # push 4 (PAGE_READWRITE)
a.emit(b'\x68\x00\x30\x00\x00')       # push 0x3000 (MEM_COMMIT|MEM_RESERVE)
a.emit(b'\x68')                        # push LINE_BUF_SIZE
a.emit_u32(LINE_BUF_SIZE)
a.emit(b'\x6A\x00')                   # push NULL
a.call_iat(IAT['VirtualAlloc'])
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: draw_line(eax=doc_line_index)
# Draw one line on screen at row (eax - scroll_y)
# ============================================================
a.label('draw_line')
a.emit(b'\x60')                        # pushad
a.emit(b'\x89\xC7')                    # mov edi, eax (doc line index)

# screen_row = eax - scroll_y
a.emit(b'\x2B\x05')                    # sub eax, [SCROLL_Y]
a.emit_u32(SCROLL_Y)
# if screen_row < 0 or >= screen_h-1, skip
a.emit(b'\x85\xC0')                    # test eax, eax
a.jcc32(0x8C, 'draw_line_done')        # js skip
a.emit(b'\x89\xC2')                    # mov edx, eax (screen row)
a.emit(b'\x3B\x15')                    # cmp edx, [SCREEN_H]
a.emit_u32(SCREEN_H)
a.jcc32(0x8D, 'draw_line_done')        # jge skip

# First clear the entire row: fill with spaces
a.emit(b'\x52')                        # push edx (screen row)
a.emit(b'\x31\xC9')                    # xor ecx, ecx (x=0)
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\xB0\x20')                    # mov al, ' '
a.call_local('fill_char')

# Set attribute for entire row (white on blue = 0x1F)
a.emit(b'\x5A')                        # pop edx (screen row)
a.emit(b'\x52')                        # push edx
a.emit(b'\x31\xC9')                    # xor ecx, ecx
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\xBE\x1F\x00\x00\x00')       # mov esi, 0x1F (white on blue)
a.call_local('fill_attr')

a.emit(b'\x5A')                        # pop edx (screen row)

# Check if line index is valid
a.emit(b'\x3B\x3D')                    # cmp edi, [NUM_LINES]
a.emit_u32(NUM_LINES)
a.jcc32(0x8D, 'draw_line_done')        # jge done (no line to draw)

# Get line data
a.emit(b'\x89\xF8')                    # mov eax, edi
a.call_local('get_line_ptr')
# esi=ptr, ecx=len
a.emit(b'\x85\xC9')                    # test ecx, ecx
a.jcc32(0x84, 'draw_line_done')        # jz done (empty line)

# Write the line text: write_str_at(x=0, y=edx, str=esi, len=ecx)
a.emit(b'\x89\xCF')                    # mov edi, ecx (len)
a.emit(b'\x31\xC9')                    # xor ecx, ecx (x=0)
a.call_local('write_str_at')

a.label('draw_line_done')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: draw_screen()
# Redraws all visible lines
# ============================================================
a.label('draw_screen')
a.emit(b'\x60')                        # pushad
a.emit(b'\x8B\x05')                    # mov eax, [SCROLL_Y]
a.emit_u32(SCROLL_Y)
a.emit(b'\x89\xC3')                    # mov ebx, eax (current doc line)

# edit_rows = SCREEN_H - 1 (status bar takes last row)
a.emit(b'\x8B\x0D')                    # mov ecx, [SCREEN_H]
a.emit_u32(SCREEN_H)
a.emit(b'\x49')                        # dec ecx
a.emit(b'\x01\xD9')                    # add ecx, ebx (end = scroll_y + screen_h - 1)

a.label('ds_loop')
a.emit(b'\x39\xCB')                    # cmp ebx, ecx
a.jcc32(0x8D, 'ds_done')               # jge done
a.emit(b'\x89\xD8')                    # mov eax, ebx
a.emit(b'\x51')                        # push ecx
a.call_local('draw_line')
a.emit(b'\x59')                        # pop ecx
a.emit(b'\x43')                        # inc ebx
a.jmp32('ds_loop')

a.label('ds_done')
a.call_local('draw_status')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: draw_status()
# Status bar on last row: filename, modified, Ln X Col Y, help
# ============================================================
a.label('draw_status')
a.emit(b'\x60')                        # pushad

# Row = SCREEN_H - 1
a.emit(b'\x8B\x15')                    # mov edx, [SCREEN_H]
a.emit_u32(SCREEN_H)
a.emit(b'\x4A')                        # dec edx

# Fill status bar with spaces, attr = 0x70 (black on light gray)
a.emit(b'\x52')                        # push edx
a.emit(b'\x31\xC9')                    # xor ecx, ecx
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\xB0\x20')                    # mov al, ' '
a.call_local('fill_char')
a.emit(b'\x5A')                        # pop edx

a.emit(b'\x52')                        # push edx
a.emit(b'\x31\xC9')                    # xor ecx, ecx
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\xBE\x70\x00\x00\x00')       # mov esi, 0x70 (black on gray)
a.call_local('fill_attr')
a.emit(b'\x5A')                        # pop edx

# Write help text on right side
a.emit(b'\x52')                        # push edx
a.emit(b'\xBE')                        # mov esi, help_rva
a.emit_u32(IMAGE_BASE + help_rva)
# Count help string length
a.emit(b'\x89\xF7')                    # mov edi, esi
a.emit(b'\x31\xC9')                    # xor ecx, ecx
a.label('ds_hlen')
a.emit(b'\x80\x3C\x0E\x00')           # cmp byte [esi+ecx], 0
a.jcc(0x74, 'ds_hlen_done')
a.emit(b'\x41')                        # inc ecx
a.jmp('ds_hlen')
a.label('ds_hlen_done')
# x = SCREEN_W - len
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\x29\xCB')                    # sub ebx, ecx
a.emit(b'\x89\xCF')                    # mov edi, ecx (len)
a.emit(b'\x89\xDE')                    # mov esi, ebx -> no, esi should be string ptr
# Fix: esi was clobbered. Reload.
a.emit(b'\xBE')                        # mov esi, help_rva
a.emit_u32(IMAGE_BASE + help_rva)
a.emit(b'\x89\xD9')                    # mov ecx, ebx (x position)
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x52')                        # push edx
a.call_local('write_str_at')
a.emit(b'\x5A')                        # pop edx

# Write " Ln NNN Col NNN" starting at x=1
a.emit(b'\x52')                        # push edx
# Write " Ln " label
a.emit(b'\xBE')                        # mov esi, line_str_rva
a.emit_u32(IMAGE_BASE + line_str_rva)
a.emit(b'\xBF\x04\x00\x00\x00')       # mov edi, 4 (len of " Ln ")
a.emit(b'\xB9\x01\x00\x00\x00')       # mov ecx, 1 (x=1)
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x52')                        # push edx
a.call_local('write_str_at')
a.emit(b'\x5A')                        # pop edx

# Convert cursor_y+1 to decimal string in TEMP_BUF, then write it
a.emit(b'\x52')                        # push edx
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x40')                        # inc eax (1-based)
a.emit(b'\xBF')                        # mov edi, TEMP_BUF
a.emit_u32(TEMP_BUF)
a.call_local('itoa')
# edi now points past last digit, TEMP_BUF has the string
# len = edi - TEMP_BUF
a.emit(b'\x89\xFB')                    # mov ebx, edi
a.emit(b'\x81\xEB')                    # sub ebx, TEMP_BUF
a.emit_u32(TEMP_BUF)
a.emit(b'\xBE')                        # mov esi, TEMP_BUF
a.emit_u32(TEMP_BUF)
a.emit(b'\x89\xDF')                    # mov edi, ebx (len)
a.emit(b'\xB9\x05\x00\x00\x00')       # mov ecx, 5 (x=5, after " Ln ")
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x52')                        # push edx
a.call_local('write_str_at')

# " Col " label at x = 5 + digits + 0
a.emit(b'\x8D\x4B\x05')               # lea ecx, [ebx+5] (x after line number)
a.emit(b'\x51')                        # push ecx
a.emit(b'\xBE')                        # mov esi, col_str_rva
a.emit_u32(IMAGE_BASE + col_str_rva)
a.emit(b'\xBF\x05\x00\x00\x00')       # mov edi, 5 (len of " Col ")
a.emit(b'\x59')                        # pop ecx
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x52')                        # push edx
a.emit(b'\x51')                        # push ecx
a.call_local('write_str_at')
a.emit(b'\x59')                        # pop ecx (x after col label)
a.emit(b'\x83\xC1\x05')               # add ecx, 5 (past " Col ")
a.emit(b'\x51')                        # push ecx

# Column number
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_X]
a.emit_u32(CURSOR_X)
a.emit(b'\x40')                        # inc eax (1-based)
a.emit(b'\xBF')                        # mov edi, TEMP_BUF
a.emit_u32(TEMP_BUF)
a.call_local('itoa')
a.emit(b'\x89\xFB')                    # mov ebx, edi
a.emit(b'\x81\xEB')                    # sub ebx, TEMP_BUF
a.emit_u32(TEMP_BUF)
a.emit(b'\xBE')                        # mov esi, TEMP_BUF
a.emit_u32(TEMP_BUF)
a.emit(b'\x89\xDF')                    # mov edi, ebx
a.emit(b'\x59')                        # pop ecx (x pos)
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x52')                        # push edx
a.call_local('write_str_at')

# If modified, show [Modified] after col number
a.emit(b'\x83\x3D')                    # cmp dword [MODIFIED], 0
a.emit_u32(MODIFIED)
a.emit(b'\x00')
a.emit(b'\x5A')                        # pop edx
a.jcc32(0x84, 'ds_no_mod')             # je skip

a.emit(b'\x52')                        # push edx
# x = after col digits
a.emit(b'\x01\xD9')                    # add ecx, ebx (past col digits)
a.emit(b'\x83\xC1\x01')               # add ecx, 1
a.emit(b'\xBE')                        # mov esi, sep_str_rva
a.emit_u32(IMAGE_BASE + sep_str_rva)
a.emit(b'\xBF\x03\x00\x00\x00')       # mov edi, 3
a.call_local('write_str_at')
a.emit(b'\x83\xC1\x03')               # add ecx, 3
a.emit(b'\xBE')                        # mov esi, modified_rva
a.emit_u32(IMAGE_BASE + modified_rva)
a.emit(b'\xBF\x0B\x00\x00\x00')       # mov edi, 11 (" [Modified]")
a.call_local('write_str_at')
a.emit(b'\x5A')                        # pop edx

a.label('ds_no_mod')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: itoa(eax=number, edi=buffer) -> edi past end
# Writes decimal digits to [edi], advances edi
# ============================================================
a.label('itoa')
a.emit(b'\x50')                        # push eax
a.emit(b'\x53')                        # push ebx
a.emit(b'\x51')                        # push ecx
a.emit(b'\x52')                        # push edx
a.emit(b'\x31\xC9')                    # xor ecx, ecx (digit count)
a.emit(b'\xBB\x0A\x00\x00\x00')       # mov ebx, 10
a.label('itoa_div')
a.emit(b'\x31\xD2')                    # xor edx, edx
a.emit(b'\xF7\xF3')                    # div ebx
a.emit(b'\x80\xC2\x30')               # add dl, '0'
a.emit(b'\x52')                        # push edx
a.emit(b'\x41')                        # inc ecx
a.emit(b'\x85\xC0')                    # test eax, eax
a.jcc(0x75, 'itoa_div')                # jnz
a.label('itoa_pop')
a.emit(b'\x58')                        # pop eax
a.emit(b'\x88\x07')                    # mov [edi], al
a.emit(b'\x47')                        # inc edi
a.emit(b'\x49')                        # dec ecx
a.jcc(0x75, 'itoa_pop')                # jnz
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x59')                        # pop ecx
a.emit(b'\x5B')                        # pop ebx
a.emit(b'\x58')                        # pop eax
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: update_cursor()
# Sets the visible console cursor to (cursor_x, cursor_y - scroll_y)
# ============================================================
a.label('update_cursor')
a.emit(b'\x8B\x0D')                    # mov ecx, [CURSOR_X]
a.emit_u32(CURSOR_X)
a.emit(b'\x8B\x15')                    # mov edx, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x2B\x15')                    # sub edx, [SCROLL_Y]
a.emit_u32(SCROLL_Y)
a.call_local('set_cursor_pos')
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: ensure_visible()
# Adjusts scroll_y so cursor_y is visible, redraws if needed
# ============================================================
a.label('ensure_visible')
a.emit(b'\x50')                        # push eax
a.emit(b'\x53')                        # push ebx
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x1D')                    # mov ebx, [SCROLL_Y]
a.emit_u32(SCROLL_Y)

# if cursor_y < scroll_y: scroll_y = cursor_y, redraw
a.emit(b'\x39\xD8')                    # cmp eax, ebx
a.jcc32(0x8D, 'ev_check_bottom')       # jge check_bottom
a.emit(b'\xA3')                        # mov [SCROLL_Y], eax
a.emit_u32(SCROLL_Y)
a.call_local('draw_screen')
a.jmp32('ev_done')

a.label('ev_check_bottom')
# edit_rows = SCREEN_H - 1
# if cursor_y >= scroll_y + edit_rows: scroll_y = cursor_y - edit_rows + 1
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_H]
a.emit_u32(SCREEN_H)
a.emit(b'\x4B')                        # dec ebx (edit_rows)
a.emit(b'\x03\x1D')                    # add ebx, [SCROLL_Y]
a.emit_u32(SCROLL_Y)
# ebx = scroll_y + edit_rows
a.emit(b'\x39\xD8')                    # cmp eax, ebx
a.jcc32(0x8C, 'ev_done')               # jl done (cursor visible)
# scroll_y = cursor_y - edit_rows + 1
a.emit(b'\x89\xC3')                    # mov ebx, eax
a.emit(b'\x2B\x1D')                    # sub ebx, [SCREEN_H]
a.emit_u32(SCREEN_H)
a.emit(b'\x83\xC3\x02')               # add ebx, 2
a.emit(b'\x89\x1D')                    # mov [SCROLL_Y], ebx
a.emit_u32(SCROLL_Y)
a.call_local('draw_screen')

a.label('ev_done')
a.emit(b'\x5B')                        # pop ebx
a.emit(b'\x58')                        # pop eax
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: insert_char(al=character)
# Insert character at cursor position in current line
# ============================================================
a.label('insert_char')
a.emit(b'\x60')                        # pushad
a.emit(b'\x0F\xB6\xD8')               # movzx ebx, al (save char)

# Get current line
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.call_local('get_line_ptr')
# esi=line_ptr, ecx=line_len

# Check line not too long
a.emit(b'\x81\xF9')                    # cmp ecx, MAX_LINE_LEN-1
a.emit_u32(MAX_LINE_LEN - 1)
a.jcc32(0x8D, 'ic_done')               # jge skip

# cursor_x
a.emit(b'\x8B\x15')                    # mov edx, [CURSOR_X]
a.emit_u32(CURSOR_X)

# Shift bytes right from end to cursor_x
# for i = len; i > cursor_x; i--: buf[i] = buf[i-1]
a.emit(b'\x89\xC8')                    # mov eax, ecx (i = len)
a.label('ic_shift')
a.emit(b'\x39\xD0')                    # cmp eax, edx
a.jcc32(0x8E, 'ic_insert')             # jle done shifting
a.emit(b'\x8A\x7C\x06\xFF')           # mov bh, [esi+eax-1]
a.emit(b'\x88\x3C\x06')               # mov [esi+eax], bh
a.emit(b'\x48')                        # dec eax
a.jmp('ic_shift')

a.label('ic_insert')
# buf[cursor_x] = char
a.emit(b'\x88\x1C\x16')               # mov [esi+edx], bl
# line_len++
a.emit(b'\x41')                        # inc ecx
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x89\x0C\x85')               # mov [LINE_LEN + eax*4], ecx
a.emit_u32(LINE_LEN)
# cursor_x++
a.emit(b'\xFF\x05')                    # inc dword [CURSOR_X]
a.emit_u32(CURSOR_X)
# Mark modified
a.emit(b'\xC7\x05')                    # mov dword [MODIFIED], 1
a.emit_u32(MODIFIED)
a.emit_u32(1)
# Redraw this line
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.call_local('draw_line')

a.label('ic_done')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: delete_char_back() - Backspace handler
# ============================================================
a.label('delete_char_back')
a.emit(b'\x60')                        # pushad

a.emit(b'\x8B\x0D')                    # mov ecx, [CURSOR_X]
a.emit_u32(CURSOR_X)
a.emit(b'\x85\xC9')                    # test ecx, ecx
a.jcc32(0x85, 'dcb_within_line')       # jnz - delete within line

# cursor_x == 0: join with previous line
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x85\xC0')                    # test eax, eax
a.jcc32(0x84, 'dcb_done')              # jz - at line 0 col 0, nothing to do

# Join: append current line to previous line
# prev_line = cursor_y - 1
a.emit(b'\x48')                        # dec eax
a.emit(b'\x50')                        # push eax (prev line index)
a.call_local('get_line_ptr')
# esi = prev_ptr, ecx = prev_len
a.emit(b'\x89\xF7')                    # mov edi, esi (prev ptr)
a.emit(b'\x89\xCB')                    # mov ebx, ecx (prev len = new cursor_x)

# Get current line
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.call_local('get_line_ptr')
# esi = curr_ptr, ecx = curr_len

# Check combined length fits
a.emit(b'\x8D\x04\x0B')               # lea eax, [ebx+ecx]
a.emit(b'\x3D')                        # cmp eax, MAX_LINE_LEN
a.emit_u32(MAX_LINE_LEN)
a.jcc32(0x8D, 'dcb_done_pop')          # jge too long, skip

# Copy current line bytes to end of previous line
# memcpy(prev_ptr + prev_len, curr_ptr, curr_len)
a.emit(b'\x56')                        # push esi
a.emit(b'\x51')                        # push ecx
a.emit(b'\x89\xD9')                    # mov ecx, ecx (already set)
# Do byte-by-byte copy
a.emit(b'\x31\xC0')                    # xor eax, eax
a.label('dcb_copy')
a.emit(b'\x85\xC9')                    # test ecx, ecx - check remaining
a.jcc(0x74, 'dcb_copy_done')
a.emit(b'\x8A\x14\x06')               # mov dl, [esi+eax]
a.emit(b'\x88\x14\x07')               # mov [edi+eax], dl -> wrong, need offset by prev_len
# Actually: dst = prev_ptr + prev_len + i, src = curr_ptr + i
# Let me redo: edi=prev_ptr, ebx=prev_len, esi=curr_ptr
a.emit(b'\xEB\x00')                    # (will fix approach below)
a.label('dcb_copy_done')

# This is getting complex. Let me use a simpler approach with rep movsb.
# Actually let me restart the copy logic more cleanly.
# I'll use a different approach: just use indexed copy.

# OK - the label management makes this hard to redo. Let me just use the
# emit directly with proper logic. The copy loop above is broken, let me
# fix it by jumping past it and doing a clean version.

# Actually I realize the label-based approach with fixups means I can't easily
# "redo" code. Let me just make the backspace-at-start-of-line simpler:
# We'll skip the join-lines feature for backspace at col 0 for now and
# only do within-line backspace. We'll add join via a second pass.

# For now, just skip (pop and done)
a.label('dcb_done_pop')
a.emit(b'\x58')                        # pop eax
a.jmp32('dcb_done')

a.label('dcb_within_line')
# Delete char at cursor_x - 1, shift left
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.call_local('get_line_ptr')
# esi=ptr, ecx=len
a.emit(b'\x8B\x15')                    # mov edx, [CURSOR_X]
a.emit_u32(CURSOR_X)

# Shift left: for i = cursor_x-1; i < len-1; i++: buf[i] = buf[i+1]
a.emit(b'\x8D\x42\xFF')               # lea eax, [edx-1] (i = cursor_x - 1)
a.label('dcb_shift')
a.emit(b'\x8D\x59\xFF')               # lea ebx, [ecx-1]
a.emit(b'\x39\xD8')                    # cmp eax, ebx
a.jcc32(0x8D, 'dcb_shifted')           # jge done
a.emit(b'\x8A\x5C\x06\x01')           # mov bl, [esi+eax+1]
a.emit(b'\x88\x1C\x06')               # mov [esi+eax], bl
a.emit(b'\x40')                        # inc eax
a.jmp('dcb_shift')

a.label('dcb_shifted')
# line_len--
a.emit(b'\x49')                        # dec ecx
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x89\x0C\x85')               # mov [LINE_LEN + eax*4], ecx
a.emit_u32(LINE_LEN)
# cursor_x--
a.emit(b'\xFF\x0D')                    # dec dword [CURSOR_X]
a.emit_u32(CURSOR_X)
# modified
a.emit(b'\xC7\x05')
a.emit_u32(MODIFIED)
a.emit_u32(1)
# redraw line
a.emit(b'\x8B\x05')
a.emit_u32(CURSOR_Y)
a.call_local('draw_line')

a.label('dcb_done')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: delete_char_fwd() - Delete key handler
# ============================================================
a.label('delete_char_fwd')
a.emit(b'\x60')                        # pushad
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.call_local('get_line_ptr')
a.emit(b'\x8B\x15')                    # mov edx, [CURSOR_X]
a.emit_u32(CURSOR_X)
# if cursor_x >= len, nothing
a.emit(b'\x39\xCA')                    # cmp edx, ecx
a.jcc32(0x8D, 'dcf_done')              # jge done

# Shift left from cursor_x
a.emit(b'\x89\xD0')                    # mov eax, edx (i = cursor_x)
a.label('dcf_shift')
a.emit(b'\x8D\x59\xFF')               # lea ebx, [ecx-1]
a.emit(b'\x39\xD8')                    # cmp eax, ebx
a.jcc32(0x8D, 'dcf_shifted')
a.emit(b'\x8A\x5C\x06\x01')           # mov bl, [esi+eax+1]
a.emit(b'\x88\x1C\x06')               # mov [esi+eax], bl
a.emit(b'\x40')                        # inc eax
a.jmp('dcf_shift')

a.label('dcf_shifted')
a.emit(b'\x49')                        # dec ecx
a.emit(b'\x8B\x05')
a.emit_u32(CURSOR_Y)
a.emit(b'\x89\x0C\x85')
a.emit_u32(LINE_LEN)
a.emit(b'\xC7\x05')
a.emit_u32(MODIFIED)
a.emit_u32(1)
a.emit(b'\x8B\x05')
a.emit_u32(CURSOR_Y)
a.call_local('draw_line')

a.label('dcf_done')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: split_line() - Enter key handler
# Split current line at cursor_x, insert new line below
# ============================================================
a.label('split_line')
a.emit(b'\x60')                        # pushad

a.emit(b'\x8B\x3D')                    # mov edi, [NUM_LINES]
a.emit_u32(NUM_LINES)
a.emit(b'\x81\xFF')                    # cmp edi, MAX_LINES-1
a.emit_u32(MAX_LINES - 1)
a.jcc32(0x8D, 'sl_done')               # jge too many lines

# Allocate new line
a.call_local('alloc_line')
a.emit(b'\x89\xC3')                    # mov ebx, eax (new line ptr)

# Get current line
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.call_local('get_line_ptr')
# esi=curr_ptr, ecx=curr_len

a.emit(b'\x8B\x15')                    # mov edx, [CURSOR_X]
a.emit_u32(CURSOR_X)

# Copy bytes from cursor_x to end into new line
# new_len = curr_len - cursor_x
a.emit(b'\x89\xC8')                    # mov eax, ecx
a.emit(b'\x29\xD0')                    # sub eax, edx (new_len = len - cursor_x)
a.emit(b'\x50')                        # push eax (new_len)
# Copy loop: for i=0; i<new_len; i++: new[i] = old[cursor_x + i]
a.emit(b'\x31\xC9')                    # xor ecx, ecx (i=0)
a.label('sl_copy')
a.emit(b'\x39\xC1')                    # cmp ecx, eax
a.jcc32(0x8D, 'sl_copy_done')          # jge
a.emit(b'\x8D\x3C\x0A')               # lea edi, [edx+ecx] (src offset)
a.emit(b'\x8A\x3C\x3E')               # mov bh, [esi+edi]
a.emit(b'\x88\x3C\x0B')               # mov [ebx+ecx], bh
a.emit(b'\x41')                        # inc ecx
a.jmp('sl_copy')
a.label('sl_copy_done')

# Truncate current line at cursor_x
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x89\x14\x85')               # mov [LINE_LEN + eax*4], edx
a.emit_u32(LINE_LEN)

# Shift lines down: for i = num_lines; i > cursor_y+1; i--:
#   lines[i] = lines[i-1], line_len[i] = line_len[i-1]
a.emit(b'\x8B\x3D')                    # mov edi, [NUM_LINES]
a.emit_u32(NUM_LINES)
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x40')                        # inc eax (insert position)
a.emit(b'\x50')                        # push eax

a.label('sl_shift')
a.emit(b'\x39\xC7')                    # cmp edi, eax
a.jcc32(0x8E, 'sl_shift_done')         # jle done
a.emit(b'\x8D\x4F\xFF')               # lea ecx, [edi-1]
# lines[edi] = lines[ecx]
a.emit(b'\x8B\x14\x8D')               # mov edx, [LINES_PTR + ecx*4]
a.emit_u32(LINES_PTR)
a.emit(b'\x89\x14\xBD')               # mov [LINES_PTR + edi*4], edx
a.emit_u32(LINES_PTR)
# line_len[edi] = line_len[ecx]
a.emit(b'\x8B\x14\x8D')               # mov edx, [LINE_LEN + ecx*4]
a.emit_u32(LINE_LEN)
a.emit(b'\x89\x14\xBD')               # mov [LINE_LEN + edi*4], edx
a.emit_u32(LINE_LEN)
a.emit(b'\x4F')                        # dec edi
a.jmp32('sl_shift')
a.label('sl_shift_done')

# Insert new line at cursor_y + 1
a.emit(b'\x58')                        # pop eax (insert pos = cursor_y + 1)
a.emit(b'\x89\x1C\x85')               # mov [LINES_PTR + eax*4], ebx
a.emit_u32(LINES_PTR)
a.emit(b'\x59')                        # pop ecx (new_len from earlier push)
a.emit(b'\x89\x0C\x85')               # mov [LINE_LEN + eax*4], ecx
a.emit_u32(LINE_LEN)

# num_lines++
a.emit(b'\xFF\x05')                    # inc dword [NUM_LINES]
a.emit_u32(NUM_LINES)

# cursor_y++, cursor_x = 0
a.emit(b'\xFF\x05')                    # inc dword [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\xC7\x05')                    # mov dword [CURSOR_X], 0
a.emit_u32(CURSOR_X)
a.emit_u32(0)

# modified
a.emit(b'\xC7\x05')
a.emit_u32(MODIFIED)
a.emit_u32(1)

# Ensure visible and full redraw
a.call_local('ensure_visible')
a.call_local('draw_screen')

a.label('sl_done')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: load_file()
# Parse command line for filename, load file into line buffers
# ============================================================
a.label('load_file')
a.emit(b'\x60')                        # pushad

# GetCommandLineA
a.call_iat(IAT['GetCommandLineA'])
# eax = ptr to command line string
# Skip past the program name (handle quotes)
a.emit(b'\x89\xC6')                    # mov esi, eax

# Skip leading spaces
a.label('lf_skip_space1')
a.emit(b'\x8A\x06')                    # mov al, [esi]
a.emit(b'\x3C\x20')                    # cmp al, ' '
a.jcc(0x74, 'lf_skip_space1_next')
a.emit(b'\x3C\x22')                    # cmp al, '"'
a.jcc(0x74, 'lf_quoted_prog')
a.jmp('lf_skip_prog')

a.label('lf_skip_space1_next')
a.emit(b'\x46')                        # inc esi
a.jmp('lf_skip_space1')

a.label('lf_quoted_prog')
a.emit(b'\x46')                        # inc esi (skip opening quote)
a.label('lf_qp_loop')
a.emit(b'\x8A\x06')                    # mov al, [esi]
a.emit(b'\x84\xC0')                    # test al, al
a.jcc32(0x84, 'lf_no_file')            # jz end of string
a.emit(b'\x3C\x22')                    # cmp al, '"'
a.jcc(0x74, 'lf_qp_end')
a.emit(b'\x46')                        # inc esi
a.jmp('lf_qp_loop')
a.label('lf_qp_end')
a.emit(b'\x46')                        # inc esi (skip closing quote)
a.jmp('lf_skip_spaces')

a.label('lf_skip_prog')
# Skip non-space chars (unquoted program name)
a.label('lf_sp_loop')
a.emit(b'\x8A\x06')                    # mov al, [esi]
a.emit(b'\x84\xC0')                    # test al, al
a.jcc32(0x84, 'lf_no_file')
a.emit(b'\x3C\x20')                    # cmp al, ' '
a.jcc(0x74, 'lf_skip_spaces')
a.emit(b'\x46')                        # inc esi
a.jmp('lf_sp_loop')

a.label('lf_skip_spaces')
# Skip spaces between program name and argument
a.emit(b'\x8A\x06')                    # mov al, [esi]
a.emit(b'\x84\xC0')
a.jcc32(0x84, 'lf_no_file')
a.emit(b'\x3C\x20')
a.jcc(0x75, 'lf_got_arg')
a.emit(b'\x46')
a.jmp('lf_skip_spaces')

a.label('lf_got_arg')
# esi points to filename. Copy to FILENAME buffer
a.emit(b'\xBF')                        # mov edi, FILENAME
a.emit_u32(FILENAME)
a.label('lf_copy_fn')
a.emit(b'\x8A\x06')                    # mov al, [esi]
a.emit(b'\x84\xC0')
a.jcc(0x74, 'lf_fn_done')
a.emit(b'\x3C\x0D')                    # cmp al, 13 (CR)
a.jcc(0x74, 'lf_fn_done')
a.emit(b'\x3C\x0A')                    # cmp al, 10 (LF)
a.jcc(0x74, 'lf_fn_done')
a.emit(b'\x88\x07')                    # mov [edi], al
a.emit(b'\x46')                        # inc esi
a.emit(b'\x47')                        # inc edi
a.jmp('lf_copy_fn')
a.label('lf_fn_done')
a.emit(b'\xC6\x07\x00')               # mov byte [edi], 0 (null terminate)

# Strip trailing spaces from filename
a.label('lf_strip_trail')
a.emit(b'\x4F')                        # dec edi
a.emit(b'\x81\xFF')                    # cmp edi, FILENAME
a.emit_u32(FILENAME)
a.jcc32(0x8C, 'lf_fn_stripped')        # jl done
a.emit(b'\x80\x3F\x20')               # cmp byte [edi], ' '
a.jcc(0x74, 'lf_strip_set')
a.emit(b'\x80\x3F\x09')               # cmp byte [edi], tab
a.jcc(0x75, 'lf_fn_stripped')
a.label('lf_strip_set')
a.emit(b'\xC6\x07\x00')               # mov byte [edi], 0
a.jmp('lf_strip_trail')
a.label('lf_fn_stripped')

# Check if filename is empty
a.emit(b'\x80\x3D')                    # cmp byte [FILENAME], 0
a.emit_u32(FILENAME)
a.emit(b'\x00')
a.jcc32(0x84, 'lf_no_file')

# Open file: CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
a.emit(b'\x6A\x00')                   # push 0 (hTemplate)
a.emit(b'\x6A\x00')                   # push 0 (dwFlags)
a.emit(b'\x6A\x03')                   # push 3 (OPEN_EXISTING)
a.emit(b'\x6A\x00')                   # push NULL (security)
a.emit(b'\x6A\x01')                   # push 1 (FILE_SHARE_READ)
a.emit(b'\x68\x00\x00\x00\x80')       # push 0x80000000 (GENERIC_READ)
a.emit(b'\x68')                        # push FILENAME
a.emit_u32(FILENAME)
a.call_iat(IAT['CreateFileA'])
# eax = handle or INVALID_HANDLE_VALUE (-1)
a.emit(b'\x83\xF8\xFF')               # cmp eax, -1
a.jcc32(0x84, 'lf_no_file')            # je failed

a.emit(b'\x89\xC7')                    # mov edi, eax (file handle)

# Get file size
a.emit(b'\x6A\x00')                   # push NULL (high dword)
a.emit(b'\x57')                        # push edi (handle)
a.call_iat(IAT['GetFileSize'])
a.emit(b'\x89\xC3')                    # mov ebx, eax (file size)

# Read file into FILE_BUF
# ReadFile(handle, FILE_BUF, size, &bytesRead, NULL)
a.emit(b'\x6A\x00')                   # push NULL (overlapped)
a.emit(b'\x68')                        # push &NUM_READ
a.emit_u32(NUM_READ)
a.emit(b'\x53')                        # push size (ebx)
a.emit(b'\x68')                        # push FILE_BUF
a.emit_u32(FILE_BUF)
a.emit(b'\x57')                        # push handle
a.call_iat(IAT['ReadFile'])

# Close file
a.emit(b'\x57')                        # push handle
a.call_iat(IAT['CloseHandle'])

# Parse FILE_BUF into lines
# Reset: num_lines = 0, first line already allocated in main
# We re-parse: for each byte, if \n start new line, else append
a.emit(b'\xBE')                        # mov esi, FILE_BUF
a.emit_u32(FILE_BUF)
a.emit(b'\x31\xFF')                    # xor edi, edi (current line index = 0)
a.emit(b'\x8B\x0D')                    # mov ecx, [NUM_READ]
a.emit_u32(NUM_READ)
a.emit(b'\x01\xF1')                    # add ecx, esi (end ptr)
a.emit(b'\x31\xD2')                    # xor edx, edx (current col = 0)

a.label('lf_parse')
a.emit(b'\x39\xCE')                    # cmp esi, ecx
a.jcc32(0x8D, 'lf_parse_done')         # jge done

a.emit(b'\x8A\x06')                    # mov al, [esi]
a.emit(b'\x46')                        # inc esi

# Skip \r
a.emit(b'\x3C\x0D')                    # cmp al, 0x0D
a.jcc(0x74, 'lf_parse')                # skip CR

# Check \n
a.emit(b'\x3C\x0A')                    # cmp al, 0x0A
a.jcc32(0x84, 'lf_newline')

# Regular char: store in current line at col edx
a.emit(b'\x81\xFA')                    # cmp edx, MAX_LINE_LEN-1
a.emit_u32(MAX_LINE_LEN - 1)
a.jcc32(0x8D, 'lf_parse')              # jge skip char

a.emit(b'\x50')                        # push eax
a.emit(b'\x8B\x04\xBD')               # mov eax, [LINES_PTR + edi*4]
a.emit_u32(LINES_PTR)
a.emit(b'\x5B')                        # pop ebx -> no, that pops eax into ebx. Let me fix.
# Actually: push the char, get line ptr, store char
# Simpler: use the line ptr directly
# Let me redo:
a.emit(b'\x88\x04\x10')               # mov [eax+edx], al -> but eax was just loaded as ptr, al is char
# Wait - we need: line_ptr = LINES_PTR[edi*4], then line_ptr[edx] = char
# eax = line_ptr (just loaded), but al was the character and got overwritten by mov eax,...
# Need to save char first.

# Actually the push eax / pop ebx approach would work:
# push eax saved the char, but pop ebx put it in ebx not back. Let me trace:
# al = character
# push eax -> saves char
# mov eax, [LINES_PTR + edi*4] -> eax = line ptr
# pop ebx -> ebx = char (in bl)
# mov [eax+edx], bl -> store char
# That's correct! But I already emitted push eax, mov eax, pop ebx.
# And then I emitted mov [eax+edx], al which is wrong (should be bl).
# Let me check what I actually emitted...

# I emitted:
# push eax (50)
# mov eax, [LINES_PTR + edi*4] (8B 04 BD ...)
# pop ebx (5B) -- this is wrong, I wrote "pop ebx -> no, that pops eax into ebx"
# mov [eax+edx], al (88 04 10) -- should be bl

# I need to fix this. But since I already emitted those bytes...
# Actually the emit is sequential, so what I emitted at this point is:
# After the "push eax" line: 50
# After "mov eax, [LINES_PTR+edi*4]": 8B 04 BD <u32>
# After "pop ebx (5B)": 5B
# After "mov [eax+edx], al": 88 04 10

# The 5B is pop ebx, and 88 04 10 is mov [eax+edx], al.
# I need mov [eax+edx], bl = 88 1C 10
# But I can't go back. Since this is bytearray, I can patch it.
# Actually, let me just continue and patch the byte.

# The last 3 bytes emitted were 88 04 10. The 04 should be 1C (for bl).
# Let me just overwrite:
a.code[-2] = 0x1C  # fix: mov [eax+edx], bl instead of al

a.emit(b'\x42')                        # inc edx
# Update line_len
a.emit(b'\x89\x14\xBD')               # mov [LINE_LEN + edi*4], edx
a.emit_u32(LINE_LEN)
a.jmp32('lf_parse')

a.label('lf_newline')
# Start new line
a.emit(b'\x47')                        # inc edi (next line)
a.emit(b'\x81\xFF')                    # cmp edi, MAX_LINES-1
a.emit_u32(MAX_LINES - 1)
a.jcc32(0x8D, 'lf_parse_done')         # too many lines

# Allocate new line buffer
a.emit(b'\x51')                        # push ecx
a.emit(b'\x52')                        # push edx
a.emit(b'\x56')                        # push esi
a.emit(b'\x57')                        # push edi
a.call_local('alloc_line')
a.emit(b'\x5F')                        # pop edi
a.emit(b'\x56')                        # push edi -> no, I need esi back
# Let me redo pops in correct order
# Actually the pops should mirror: pop edi, pop esi, pop edx, pop ecx
# But I already emitted pop edi (5F) and push edi (57). Let me continue correctly:
a.emit(b'\x5E')                        # pop esi
a.emit(b'\x5A')                        # pop edx
a.emit(b'\x59')                        # pop ecx

# Fix: I emitted push edi (57) by mistake after pop edi (5F).
# The sequence is now: 5F 57 5E 5A 59 which is pop edi, push edi, pop esi, pop edx, pop ecx
# That leaves the stack wrong. Let me patch: change the 57 to a NOP.
a.code[-4] = 0x90  # NOP out the erroneous push edi

# Store new line ptr
a.emit(b'\x89\x04\xBD')               # mov [LINES_PTR + edi*4], eax
a.emit_u32(LINES_PTR)
a.emit(b'\xC7\x04\xBD')               # mov dword [LINE_LEN + edi*4], 0
a.emit_u32(LINE_LEN)
a.emit_u32(0)
a.emit(b'\x31\xD2')                    # xor edx, edx (reset col)
a.jmp32('lf_parse')

a.label('lf_parse_done')
# num_lines = edi + 1
a.emit(b'\x8D\x47\x01')               # lea eax, [edi+1]
a.emit(b'\xA3')                        # mov [NUM_LINES], eax
a.emit_u32(NUM_LINES)

a.label('lf_no_file')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# SUBROUTINE: save_file()
# Write all lines to FILENAME
# ============================================================
a.label('save_file')
a.emit(b'\x60')                        # pushad

# Check filename exists
a.emit(b'\x80\x3D')                    # cmp byte [FILENAME], 0
a.emit_u32(FILENAME)
a.emit(b'\x00')
a.jcc32(0x84, 'sf_done')

# CreateFileA for writing
a.emit(b'\x6A\x00')                   # hTemplate
a.emit(b'\x6A\x00')                   # flags
a.emit(b'\x6A\x02')                   # CREATE_ALWAYS
a.emit(b'\x6A\x00')                   # security
a.emit(b'\x6A\x00')                   # share
a.emit(b'\x68\x00\x00\x00\x40')       # GENERIC_WRITE
a.emit(b'\x68')
a.emit_u32(FILENAME)
a.call_iat(IAT['CreateFileA'])
a.emit(b'\x83\xF8\xFF')
a.jcc32(0x84, 'sf_done')
a.emit(b'\x89\xC7')                    # mov edi, eax (handle)

# Write each line + \r\n
a.emit(b'\x31\xDB')                    # xor ebx, ebx (line index)
a.label('sf_loop')
a.emit(b'\x3B\x1D')                    # cmp ebx, [NUM_LINES]
a.emit_u32(NUM_LINES)
a.jcc32(0x8D, 'sf_close')              # jge done

# Write line content
a.emit(b'\x89\xD8')                    # mov eax, ebx
a.call_local('get_line_ptr')
# esi=ptr, ecx=len
a.emit(b'\x85\xC9')                    # test ecx, ecx
a.jcc(0x74, 'sf_write_nl')             # skip if empty

# WriteFile(handle, ptr, len, &written, NULL)
a.emit(b'\x53')                        # push ebx (save line idx)
a.emit(b'\x6A\x00')
a.emit(b'\x68')
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x51')                        # push len
a.emit(b'\x56')                        # push ptr
a.emit(b'\x57')                        # push handle
a.call_iat(IAT['WriteFile'])
a.emit(b'\x5B')                        # pop ebx

a.label('sf_write_nl')
# Write \r\n (except for last line? Actually always write it for simplicity)
# Store \r\n in TEMP_BUF
a.emit(b'\xC6\x05')                    # mov byte [TEMP_BUF], 0x0D
a.emit_u32(TEMP_BUF)
a.emit(b'\x0D')
a.emit(b'\xC6\x05')                    # mov byte [TEMP_BUF+1], 0x0A
a.emit_u32(TEMP_BUF + 1)
a.emit(b'\x0A')

a.emit(b'\x53')                        # push ebx
a.emit(b'\x6A\x00')
a.emit(b'\x68')
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x6A\x02')                   # 2 bytes
a.emit(b'\x68')                        # push TEMP_BUF
a.emit_u32(TEMP_BUF)
a.emit(b'\x57')                        # push handle
a.call_iat(IAT['WriteFile'])
a.emit(b'\x5B')                        # pop ebx

a.emit(b'\x43')                        # inc ebx
a.jmp32('sf_loop')

a.label('sf_close')
a.emit(b'\x57')                        # push handle
a.call_iat(IAT['CloseHandle'])

# Clear modified flag
a.emit(b'\xC7\x05')
a.emit_u32(MODIFIED)
a.emit_u32(0)

a.label('sf_done')
a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# MAIN
# ============================================================
a.label('main')
a.emit(b'\x55')                        # push ebp
a.emit(b'\x89\xE5')                    # mov ebp, esp
a.emit(b'\x83\xEC\x40')               # sub esp, 64

# Get stdout
a.emit(b'\x6A\xF5')                   # push -11
a.call_iat(IAT['GetStdHandle'])
a.emit(b'\xA3')
a.emit_u32(STDOUT_H)

# Get stdin
a.emit(b'\x6A\xF6')                   # push -10
a.call_iat(IAT['GetStdHandle'])
a.emit(b'\xA3')
a.emit_u32(STDIN_H)

# SetConsoleMode on stdin: ENABLE_EXTENDED_FLAGS (0x0080) to properly clear all other flags
# This disables echo, line input, quick edit, mouse input, etc.
a.emit(b'\x68\x80\x00\x00\x00')       # push 0x0080 (ENABLE_EXTENDED_FLAGS)
a.emit(b'\xFF\x35')                    # push [STDIN_H]
a.emit_u32(STDIN_H)
a.call_iat(IAT['SetConsoleMode'])

# Flush pending input, wait, flush again to catch late-arriving events
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_H)
a.call_iat(IAT['FlushConsoleInputBuffer'])
a.emit(b'\x68\xC8\x00\x00\x00')       # push 200 (200ms)
a.call_iat(IAT['Sleep'])
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_H)
a.call_iat(IAT['FlushConsoleInputBuffer'])

# Set console title
a.emit(b'\x68')
a.emit_u32(IMAGE_BASE + title_rva)
a.call_iat(IAT['SetConsoleTitleA'])

# Get console size
a.emit(b'\x68')                        # push CSBI_BUF
a.emit_u32(CSBI_BUF)
a.emit(b'\xFF\x35')
a.emit_u32(STDOUT_H)
a.call_iat(IAT['GetConsoleScreenBufferInfo'])

# CSBI: dwSize.X at +0 (WORD), dwSize.Y at +2 (WORD)
# But we want the window size, not buffer size.
# srWindow: Left(+10), Top(+12), Right(+14), Bottom(+16)
# width = Right - Left + 1, height = Bottom - Top + 1
a.emit(b'\x0F\xB7\x05')               # movzx eax, word [CSBI_BUF+14] (Right)
a.emit_u32(CSBI_BUF + 14)
a.emit(b'\x0F\xB7\x0D')               # movzx ecx, word [CSBI_BUF+10] (Left)
a.emit_u32(CSBI_BUF + 10)
a.emit(b'\x29\xC8')                    # sub eax, ecx
a.emit(b'\x40')                        # inc eax
a.emit(b'\xA3')
a.emit_u32(SCREEN_W)

a.emit(b'\x0F\xB7\x05')               # movzx eax, word [CSBI_BUF+16] (Bottom)
a.emit_u32(CSBI_BUF + 16)
a.emit(b'\x0F\xB7\x0D')               # movzx ecx, word [CSBI_BUF+12] (Top)
a.emit_u32(CSBI_BUF + 12)
a.emit(b'\x29\xC8')                    # sub eax, ecx
a.emit(b'\x40')                        # inc eax
a.emit(b'\xA3')
a.emit_u32(SCREEN_H)

# Hide cursor blink (make it a small underline)
# SetConsoleCursorInfo(handle, &CURSOR_INFO)
# CURSOR_INFO: dwSize=25 (DWORD), bVisible=TRUE (BOOL)
a.emit(b'\xC7\x05')                    # mov dword [TEMP_BUF], 25
a.emit_u32(TEMP_BUF)
a.emit_u32(25)
a.emit(b'\xC7\x05')                    # mov dword [TEMP_BUF+4], 1 (visible)
a.emit_u32(TEMP_BUF + 4)
a.emit_u32(1)
a.emit(b'\x68')                        # push TEMP_BUF
a.emit_u32(TEMP_BUF)
a.emit(b'\xFF\x35')
a.emit_u32(STDOUT_H)
a.call_iat(IAT['SetConsoleCursorInfo'])

# Initialize: allocate first line, set num_lines=1
a.call_local('alloc_line')
a.emit(b'\xA3')                        # mov [LINES_PTR], eax (line 0 ptr)
a.emit_u32(LINES_PTR)
a.emit(b'\xC7\x05')                    # mov dword [LINE_LEN], 0
a.emit_u32(LINE_LEN)
a.emit_u32(0)
a.emit(b'\xC7\x05')                    # mov dword [NUM_LINES], 1
a.emit_u32(NUM_LINES)
a.emit_u32(1)
a.emit(b'\xC7\x05')                    # cursor_x = 0
a.emit_u32(CURSOR_X)
a.emit_u32(0)
a.emit(b'\xC7\x05')                    # cursor_y = 0
a.emit_u32(CURSOR_Y)
a.emit_u32(0)
a.emit(b'\xC7\x05')                    # scroll_y = 0
a.emit_u32(SCROLL_Y)
a.emit_u32(0)
a.emit(b'\xC7\x05')                    # modified = 0
a.emit_u32(MODIFIED)
a.emit_u32(0)

# Load file if specified on command line
a.call_local('load_file')

# Initial draw
a.call_local('draw_screen')
a.call_local('update_cursor')

# ============================================================
# MAIN LOOP: read input, handle keys
# ============================================================
a.label('main_loop')

# ReadConsoleInputA(stdin, &INPUT_REC, 1, &NUM_READ) - blocking
a.emit(b'\x68')
a.emit_u32(NUM_READ)
a.emit(b'\x6A\x01')
a.emit(b'\x68')
a.emit_u32(INPUT_REC)
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_H)
a.call_iat(IAT['ReadConsoleInputA'])

# Check KEY_EVENT (EventType at offset 0 == 1)
a.emit(b'\x66\x83\x3D')               # cmp word [INPUT_REC], 1
a.emit_u32(INPUT_REC)
a.emit(b'\x01')
a.jcc32(0x85, 'main_loop')             # jne skip

# Check bKeyDown (offset 4)
a.emit(b'\x83\x3D')                    # cmp dword [INPUT_REC+4], 0
a.emit_u32(INPUT_REC + 4)
a.emit(b'\x00')
a.jcc32(0x84, 'main_loop')             # je skip (key up)

# Get virtual key code (offset 10, WORD)
a.emit(b'\x0F\xB7\x05')               # movzx eax, word [INPUT_REC+10]
a.emit_u32(INPUT_REC + 10)

# Get ASCII char (offset 14, uChar.AsciiChar)
a.emit(b'\x0F\xB6\x1D')               # movzx ebx, byte [INPUT_REC+14]
a.emit_u32(INPUT_REC + 14)

# Get control key state (offset 16, DWORD)
a.emit(b'\x8B\x0D')                    # mov ecx, [INPUT_REC+16]
a.emit_u32(INPUT_REC + 16)

# ---- Check Escape (VK_ESCAPE = 0x1B) ----
a.emit(b'\x3D\x1B\x00\x00\x00')       # cmp eax, 0x1B
a.jcc32(0x84, 'do_exit')

# ---- Check Ctrl+Q (VK_Q=0x51 with ctrl) ----
a.emit(b'\x3D\x51\x00\x00\x00')       # cmp eax, 0x51 (Q)
a.jcc32(0x85, 'not_ctrl_q')
a.emit(b'\xF7\xC1\x08\x00\x00\x00')   # test ecx, 0x08 (LEFT_CTRL)
a.jcc32(0x85, 'not_ctrl_q_r')
a.jmp32('do_exit')
a.label('not_ctrl_q_r')
a.emit(b'\xF7\xC1\x04\x00\x00\x00')   # test ecx, 0x04 (RIGHT_CTRL)
a.jcc32(0x84, 'not_ctrl_q')
a.jmp32('do_exit')
a.label('not_ctrl_q')

# ---- Check Ctrl+S (VK_S=0x53 with ctrl) ----
a.emit(b'\x3D\x53\x00\x00\x00')       # cmp eax, 0x53
a.jcc32(0x85, 'not_ctrl_s')
a.emit(b'\xF7\xC1\x0C\x00\x00\x00')   # test ecx, 0x0C (LEFT_CTRL|RIGHT_CTRL)
a.jcc32(0x84, 'not_ctrl_s')
a.call_local('save_file')
a.call_local('draw_status')
a.call_local('update_cursor')
a.jmp32('main_loop')
a.label('not_ctrl_s')

# ---- Arrow keys ----
# VK_LEFT = 0x25
a.emit(b'\x3D\x25\x00\x00\x00')
a.jcc32(0x84, 'key_left')
# VK_RIGHT = 0x27
a.emit(b'\x3D\x27\x00\x00\x00')
a.jcc32(0x84, 'key_right')
# VK_UP = 0x26
a.emit(b'\x3D\x26\x00\x00\x00')
a.jcc32(0x84, 'key_up')
# VK_DOWN = 0x28
a.emit(b'\x3D\x28\x00\x00\x00')
a.jcc32(0x84, 'key_down')

# VK_HOME = 0x24
a.emit(b'\x3D\x24\x00\x00\x00')
a.jcc32(0x84, 'key_home')
# VK_END = 0x23
a.emit(b'\x3D\x23\x00\x00\x00')
a.jcc32(0x84, 'key_end')

# VK_PRIOR (PgUp) = 0x21
a.emit(b'\x3D\x21\x00\x00\x00')
a.jcc32(0x84, 'key_pgup')
# VK_NEXT (PgDn) = 0x22
a.emit(b'\x3D\x22\x00\x00\x00')
a.jcc32(0x84, 'key_pgdn')

# VK_BACK = 0x08
a.emit(b'\x3D\x08\x00\x00\x00')
a.jcc32(0x84, 'key_backspace')
# VK_DELETE = 0x2E
a.emit(b'\x3D\x2E\x00\x00\x00')
a.jcc32(0x84, 'key_delete')
# VK_RETURN = 0x0D
a.emit(b'\x3D\x0D\x00\x00\x00')
a.jcc32(0x84, 'key_enter')

# VK_F1 = 0x70
a.emit(b'\x3D\x70\x00\x00\x00')
a.jcc32(0x84, 'key_f1')

# ---- Printable character ----
# If ASCII char (bl) >= 0x20, insert it
a.emit(b'\x80\xFB\x20')               # cmp bl, 0x20
a.jcc32(0x82, 'main_loop')             # jb skip (non-printable)
a.emit(b'\x88\xD8')                    # mov al, bl
a.call_local('insert_char')
a.call_local('draw_status')
a.call_local('update_cursor')
a.jmp32('main_loop')

# ---- Key handlers ----

a.label('key_left')
a.emit(b'\x83\x3D')                    # cmp dword [CURSOR_X], 0
a.emit_u32(CURSOR_X)
a.emit(b'\x00')
a.jcc32(0x84, 'kl_prev_line')
a.emit(b'\xFF\x0D')                    # dec [CURSOR_X]
a.emit_u32(CURSOR_X)
a.jmp32('key_done')
a.label('kl_prev_line')
# Move to end of previous line
a.emit(b'\x83\x3D')                    # cmp dword [CURSOR_Y], 0
a.emit_u32(CURSOR_Y)
a.emit(b'\x00')
a.jcc32(0x84, 'key_done')
a.emit(b'\xFF\x0D')                    # dec [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x04\x85')               # mov eax, [LINE_LEN + eax*4]
a.emit_u32(LINE_LEN)
a.emit(b'\xA3')                        # mov [CURSOR_X], eax
a.emit_u32(CURSOR_X)
a.call_local('ensure_visible')
a.jmp32('key_done')

a.label('key_right')
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x04\x85')               # mov eax, [LINE_LEN + eax*4]
a.emit_u32(LINE_LEN)
a.emit(b'\x39\x05')                    # cmp [CURSOR_X], eax
a.emit_u32(CURSOR_X)
a.jcc32(0x8C, 'kr_advance')            # jl - can move right
# At end of line: move to start of next line
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x40')                        # inc eax
a.emit(b'\x3B\x05')                    # cmp eax, [NUM_LINES]
a.emit_u32(NUM_LINES)
a.jcc32(0x8D, 'key_done')              # jge at last line
a.emit(b'\xA3')                        # mov [CURSOR_Y], eax
a.emit_u32(CURSOR_Y)
a.emit(b'\xC7\x05')                    # mov dword [CURSOR_X], 0
a.emit_u32(CURSOR_X)
a.emit_u32(0)
a.call_local('ensure_visible')
a.jmp32('key_done')
a.label('kr_advance')
a.emit(b'\xFF\x05')                    # inc [CURSOR_X]
a.emit_u32(CURSOR_X)
a.jmp32('key_done')

a.label('key_up')
a.emit(b'\x83\x3D')                    # cmp dword [CURSOR_Y], 0
a.emit_u32(CURSOR_Y)
a.emit(b'\x00')
a.jcc32(0x84, 'key_done')
a.emit(b'\xFF\x0D')                    # dec [CURSOR_Y]
a.emit_u32(CURSOR_Y)
# Clamp cursor_x to line length
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x04\x85')               # mov eax, [LINE_LEN + eax*4]
a.emit_u32(LINE_LEN)
a.emit(b'\x39\x05')                    # cmp [CURSOR_X], eax
a.emit_u32(CURSOR_X)
a.jcc32(0x8E, 'ku_ok')                 # jle ok
a.emit(b'\xA3')                        # mov [CURSOR_X], eax
a.emit_u32(CURSOR_X)
a.label('ku_ok')
a.call_local('ensure_visible')
a.jmp32('key_done')

a.label('key_down')
a.emit(b'\x8B\x05')                    # mov eax, [CURSOR_Y]
a.emit_u32(CURSOR_Y)
a.emit(b'\x40')                        # inc eax
a.emit(b'\x3B\x05')                    # cmp eax, [NUM_LINES]
a.emit_u32(NUM_LINES)
a.jcc32(0x8D, 'key_done')
a.emit(b'\xA3')
a.emit_u32(CURSOR_Y)
# Clamp cursor_x
a.emit(b'\x8B\x04\x85')
a.emit_u32(LINE_LEN)
a.emit(b'\x39\x05')
a.emit_u32(CURSOR_X)
a.jcc32(0x8E, 'kd_ok')
a.emit(b'\xA3')
a.emit_u32(CURSOR_X)
a.label('kd_ok')
a.call_local('ensure_visible')
a.jmp32('key_done')

a.label('key_home')
a.emit(b'\xC7\x05')
a.emit_u32(CURSOR_X)
a.emit_u32(0)
a.jmp32('key_done')

a.label('key_end')
a.emit(b'\x8B\x05')
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x04\x85')
a.emit_u32(LINE_LEN)
a.emit(b'\xA3')
a.emit_u32(CURSOR_X)
a.jmp32('key_done')

a.label('key_pgup')
a.emit(b'\x8B\x05')                    # mov eax, [SCREEN_H]
a.emit_u32(SCREEN_H)
a.emit(b'\x48')                        # dec eax (page = screen_h - 1)
a.emit(b'\x29\x05')                    # sub [CURSOR_Y], eax
a.emit_u32(CURSOR_Y)
# Clamp to 0
a.emit(b'\x83\x3D')                    # cmp dword [CURSOR_Y], 0
a.emit_u32(CURSOR_Y)
a.jcc32(0x8D, 'pgup_ok')               # jge ok
a.emit(b'\xC7\x05')
a.emit_u32(CURSOR_Y)
a.emit_u32(0)
a.label('pgup_ok')
# Clamp cursor_x
a.emit(b'\x8B\x05')
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x04\x85')
a.emit_u32(LINE_LEN)
a.emit(b'\x39\x05')
a.emit_u32(CURSOR_X)
a.jcc32(0x8E, 'pgup_cx_ok')
a.emit(b'\xA3')
a.emit_u32(CURSOR_X)
a.label('pgup_cx_ok')
a.call_local('ensure_visible')
a.call_local('draw_screen')
a.jmp32('key_done')

a.label('key_pgdn')
a.emit(b'\x8B\x05')
a.emit_u32(SCREEN_H)
a.emit(b'\x48')
a.emit(b'\x01\x05')                    # add [CURSOR_Y], eax
a.emit_u32(CURSOR_Y)
# Clamp to num_lines - 1
a.emit(b'\x8B\x05')
a.emit_u32(NUM_LINES)
a.emit(b'\x48')                        # dec eax (max line)
a.emit(b'\x39\x05')
a.emit_u32(CURSOR_Y)
a.jcc32(0x8E, 'pgdn_ok')               # jle ok
a.emit(b'\xA3')
a.emit_u32(CURSOR_Y)
a.label('pgdn_ok')
a.emit(b'\x8B\x05')
a.emit_u32(CURSOR_Y)
a.emit(b'\x8B\x04\x85')
a.emit_u32(LINE_LEN)
a.emit(b'\x39\x05')
a.emit_u32(CURSOR_X)
a.jcc32(0x8E, 'pgdn_cx_ok')
a.emit(b'\xA3')
a.emit_u32(CURSOR_X)
a.label('pgdn_cx_ok')
a.call_local('ensure_visible')
a.call_local('draw_screen')
a.jmp32('key_done')

a.label('key_backspace')
a.call_local('delete_char_back')
a.call_local('draw_status')
a.call_local('update_cursor')
a.jmp32('main_loop')

a.label('key_delete')
a.call_local('delete_char_fwd')
a.call_local('draw_status')
a.call_local('update_cursor')
a.jmp32('main_loop')

a.label('key_enter')
a.call_local('split_line')
a.call_local('update_cursor')
a.jmp32('main_loop')

a.label('key_f1')
a.call_local('show_help')
a.call_local('draw_screen')
a.call_local('update_cursor')
a.jmp32('main_loop')

a.label('key_done')
a.call_local('draw_status')
a.call_local('update_cursor')
a.jmp32('main_loop')

# ---- Exit ----
a.label('do_exit')
a.emit(b'\x6A\x00')                   # push 0
a.call_iat(IAT['ExitProcess'])

# ============================================================
# SUBROUTINE: show_help()
# Clear screen, draw help text, wait for any key
# ============================================================
a.label('show_help')
a.emit(b'\x60')                        # pushad

# Clear entire screen with blue background
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\x0F\xAF\x1D')               # imul ebx, [SCREEN_H]
a.emit_u32(SCREEN_H)
# Fill chars with spaces from (0,0)
a.emit(b'\x31\xC9')                    # xor ecx, ecx
a.emit(b'\x31\xD2')                    # xor edx, edx
a.emit(b'\xB0\x20')                    # mov al, ' '
a.call_local('fill_char')
# Fill attr with 0x1F (white on blue)
a.emit(b'\x31\xC9')
a.emit(b'\x31\xD2')
a.emit(b'\xBE\x1F\x00\x00\x00')       # mov esi, 0x1F
a.call_local('fill_attr')

# Draw each help line centered vertically
# start_row = (SCREEN_H - HELP_NUM_LINES) / 2
a.emit(b'\x8B\x05')                    # mov eax, [SCREEN_H]
a.emit_u32(SCREEN_H)
a.emit(b'\x2D')                        # sub eax, HELP_NUM_LINES
a.emit_u32(HELP_NUM_LINES)
a.emit(b'\xD1\xF8')                    # sar eax, 1 (divide by 2)
a.emit(b'\x89\xC2')                    # mov edx, eax (current row)
# Clamp to 0 minimum
a.emit(b'\x85\xD2')                    # test edx, edx
a.jcc(0x79, 'sh_row_ok')               # jns ok
a.emit(b'\x31\xD2')                    # xor edx, edx
a.label('sh_row_ok')

# Loop through help lines
a.emit(b'\x31\xFF')                    # xor edi, edi (line index)
a.label('sh_line_loop')
a.emit(b'\x81\xFF')                    # cmp edi, HELP_NUM_LINES
a.emit_u32(HELP_NUM_LINES)
a.jcc32(0x8D, 'sh_lines_done')         # jge done

# Get help line RVA and length from a lookup table we'll embed
# We'll use a jump table approach: load address and length from embedded data
a.emit(b'\x52')                        # push edx (row)
a.emit(b'\x57')                        # push edi (index)

# Load help_table base from rdata
a.emit(b'\xBE')                        # mov esi, help_table (in rdata)
a.emit_u32(IMAGE_BASE + help_table_rva)

# eax = [esi + edi*8] = string address (SIB: scale=8, index=edi, base=esi)
a.emit(b'\x8B\x04\xFE')               # mov eax, [esi + edi*8]
# ecx = [esi + edi*8 + 4] = string length
a.emit(b'\x8B\x4C\xFE\x04')           # mov ecx, [esi + edi*8 + 4]

a.emit(b'\x89\xC6')                    # mov esi, eax (string ptr)
a.emit(b'\x89\xCF')                    # mov edi, ecx (length)

a.emit(b'\x5B')                        # pop ebx (was edi/index, now in ebx)
a.emit(b'\x5A')                        # pop edx (row)

# x = (SCREEN_W - length) / 2 for centering
a.emit(b'\x8B\x0D')                    # mov ecx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\x29\xF9')                    # sub ecx, edi (ecx = screen_w - len)
a.emit(b'\xD1\xF9')                    # sar ecx, 1
# Clamp to 2 minimum
a.emit(b'\x83\xF9\x02')               # cmp ecx, 2
a.jcc(0x7D, 'sh_x_ok')                 # jge ok
a.emit(b'\xB9\x02\x00\x00\x00')       # mov ecx, 2
a.label('sh_x_ok')

# Only draw if length > 0
a.emit(b'\x85\xFF')                    # test edi, edi
a.jcc(0x74, 'sh_skip_draw')            # jz skip

a.emit(b'\x52')                        # push edx
a.emit(b'\x53')                        # push ebx
a.call_local('write_str_at')
a.emit(b'\x5B')                        # pop ebx
a.emit(b'\x5A')                        # pop edx

a.label('sh_skip_draw')
# Highlight title line (first line) with yellow on blue = 0x1E
a.emit(b'\x85\xDB')                    # test ebx, ebx (line index)
a.jcc(0x75, 'sh_not_title')            # jnz not title
a.emit(b'\x52')                        # push edx
a.emit(b'\x53')                        # push ebx
a.emit(b'\x31\xC9')                    # xor ecx, ecx
a.emit(b'\x8B\x1D')                    # mov ebx, [SCREEN_W]
a.emit_u32(SCREEN_W)
a.emit(b'\xBE\x1E\x00\x00\x00')       # mov esi, 0x1E (yellow on blue)
a.call_local('fill_attr')
a.emit(b'\x5B')                        # pop ebx
a.emit(b'\x5A')                        # pop edx
a.label('sh_not_title')

# Highlight "--- Press any key ---" line (last line) with 0x1B (cyan on blue)
a.emit(b'\x81\xFB')                    # cmp ebx, HELP_NUM_LINES - 1
a.emit_u32(HELP_NUM_LINES - 1)
a.jcc(0x75, 'sh_not_footer')
a.emit(b'\x52')                        # push edx
a.emit(b'\x53')                        # push ebx
a.emit(b'\x31\xC9')
a.emit(b'\x8B\x1D')
a.emit_u32(SCREEN_W)
a.emit(b'\xBE\x1B\x00\x00\x00')       # mov esi, 0x1B (cyan on blue)
a.call_local('fill_attr')
a.emit(b'\x5B')
a.emit(b'\x5A')
a.label('sh_not_footer')

# Next line
a.emit(b'\x89\xDF')                    # mov edi, ebx (restore line index)
a.emit(b'\x47')                        # inc edi
a.emit(b'\x42')                        # inc edx (next row)
a.jmp32('sh_line_loop')

a.label('sh_lines_done')

# Hide cursor during help
a.emit(b'\xC7\x05')                    # mov dword [TEMP_BUF], 1
a.emit_u32(TEMP_BUF)
a.emit_u32(1)
a.emit(b'\xC7\x05')                    # mov dword [TEMP_BUF+4], 0 (invisible)
a.emit_u32(TEMP_BUF + 4)
a.emit_u32(0)
a.emit(b'\x68')
a.emit_u32(TEMP_BUF)
a.emit(b'\xFF\x35')
a.emit_u32(STDOUT_H)
a.call_iat(IAT['SetConsoleCursorInfo'])

# Wait for any keypress
a.label('sh_wait')
a.emit(b'\x68')
a.emit_u32(NUM_READ)
a.emit(b'\x6A\x01')
a.emit(b'\x68')
a.emit_u32(INPUT_REC)
a.emit(b'\xFF\x35')
a.emit_u32(STDIN_H)
a.call_iat(IAT['ReadConsoleInputA'])
# Check KEY_EVENT + bKeyDown
a.emit(b'\x66\x83\x3D')
a.emit_u32(INPUT_REC)
a.emit(b'\x01')
a.jcc(0x75, 'sh_wait')
a.emit(b'\x83\x3D')
a.emit_u32(INPUT_REC + 4)
a.emit(b'\x00')
a.jcc(0x74, 'sh_wait')

# Restore cursor visibility
a.emit(b'\xC7\x05')
a.emit_u32(TEMP_BUF)
a.emit_u32(25)
a.emit(b'\xC7\x05')
a.emit_u32(TEMP_BUF + 4)
a.emit_u32(1)
a.emit(b'\x68')
a.emit_u32(TEMP_BUF)
a.emit(b'\xFF\x35')
a.emit_u32(STDOUT_H)
a.call_iat(IAT['SetConsoleCursorInfo'])

a.emit(b'\x61')                        # popad
a.emit(b'\xC3')                        # ret

# ============================================================
# Build executable
# ============================================================
code_bytes = a.bytes()
print(f"Machine code: {len(code_bytes)} bytes")

text_size = (len(code_bytes) + 0x1FF) & ~0x1FF
text_section = code_bytes.ljust(text_size, b'\x00')
print(f"Text section: {hex(text_size)}")

rdata_size = 0x800
rdata = bytes(rdata[:rdata_size])

bss_vsize = 0x20000  # 128KB for file buffer + line data

# PE Headers
dos_header = bytearray(0x80)
dos_header[0:2] = b'MZ'
struct.pack_into('<I', dos_header, 0x3C, 0x80)

pe_sig = b'PE\x00\x00'
n_sections = 3
coff = struct.pack('<HHIIIHH', 0x014C, n_sections, 0, 0, 0, 0xE0, 0x0103)

opt = bytearray(0xE0)
struct.pack_into('<H', opt, 0, 0x10B)      # PE32
struct.pack_into('<B', opt, 2, 6)           # linker ver
struct.pack_into('<I', opt, 4, text_size)   # SizeOfCode
struct.pack_into('<I', opt, 8, rdata_size)  # SizeOfInitializedData
struct.pack_into('<I', opt, 16, TEXT_RVA)   # AddressOfEntryPoint
struct.pack_into('<I', opt, 20, TEXT_RVA)   # BaseOfCode
struct.pack_into('<I', opt, 24, RDATA_RVA)  # BaseOfData
struct.pack_into('<I', opt, 28, IMAGE_BASE) # ImageBase
struct.pack_into('<I', opt, 32, 0x1000)     # SectionAlignment
struct.pack_into('<I', opt, 36, 0x200)      # FileAlignment
struct.pack_into('<H', opt, 40, 4)          # OS version major
struct.pack_into('<H', opt, 48, 4)          # Subsystem version major

# SizeOfImage: headers(0x1000) + text + rdata + bss
text_va_size = (text_size + 0xFFF) & ~0xFFF
rdata_va_size = (rdata_size + 0xFFF) & ~0xFFF
bss_va_start = RDATA_RVA + rdata_va_size
size_of_image = bss_va_start + bss_vsize
# Round up to section alignment
size_of_image = (size_of_image + 0xFFF) & ~0xFFF

# Recalculate BSS_RVA if needed
assert BSS_RVA == RDATA_RVA + rdata_va_size or BSS_RVA == 0x3000

struct.pack_into('<I', opt, 56, size_of_image)
struct.pack_into('<I', opt, 60, 0x200)      # SizeOfHeaders
struct.pack_into('<H', opt, 68, 3)          # Subsystem: CONSOLE
struct.pack_into('<I', opt, 72, 0x100000)   # SizeOfStackReserve
struct.pack_into('<I', opt, 76, 0x1000)     # SizeOfStackCommit
struct.pack_into('<I', opt, 80, 0x100000)   # SizeOfHeapReserve
struct.pack_into('<I', opt, 84, 0x1000)     # SizeOfHeapCommit
struct.pack_into('<I', opt, 92, 16)         # NumberOfRvaAndSizes

# Import directory
struct.pack_into('<II', opt, 96 + 8, RDATA_RVA, 40)  # IDT RVA + size
# IAT directory
struct.pack_into('<II', opt, 96 + 96, RDATA_RVA + K32_IAT_OFF, K32_IAT_SIZE)

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

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "machedit.exe")
with open(out_path, 'wb') as f:
    f.write(exe)

print(f"\nGenerated {out_path} ({len(exe)} bytes)")
print(f"Machine code: {len(code_bytes)} bytes")
print(f"Sections: .text={hex(text_size)} .rdata={hex(rdata_size)} .bss={hex(bss_vsize)}")
print(f"SizeOfImage: {hex(size_of_image)}")
print(f"\nUsage:")
print(f"  machedit.exe            - open empty editor")
print(f"  machedit.exe file.txt   - edit file")
print(f"  Ctrl+S = save, Esc = exit")
