#!/usr/bin/env python3
"""Minimal test: draw border with SetConsoleCursorPosition + WriteConsoleA,
   then exit. To verify these APIs work correctly."""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000

class Asm:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []
    def pos(self): return len(self.code)
    def emit(self, bs): self.code.extend(bs)
    def label(self, name): self.labels[name] = self.pos()
    def emit_u32(self, val): self.emit(struct.pack('<I', val))
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
    def call_local(self, label):
        self.emit(b'\xE8')
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')
    def call_iat(self, addr):
        self.emit(b'\xFF\x15')
        self.emit_u32(addr)
    def resolve(self):
        for off, size, lbl, relative in self.fixups:
            target = self.labels[lbl]
            disp = target - (off + size)
            if size == 1:
                self.code[off] = disp & 0xFF
            else:
                struct.pack_into('<i', self.code, off, disp)
    def bytes(self):
        self.resolve()
        return bytes(self.code)

def hint_name(hint, name):
    b = struct.pack('<H', hint) + name.encode() + b'\x00'
    if len(b) % 2: b += b'\x00'
    return b

kernel32_funcs = ["GetStdHandle", "SetConsoleCursorPosition",
                  "WriteConsoleA", "ExitProcess", "Sleep"]
k32_hns = [hint_name(0, f) for f in kernel32_funcs]
kernel32_name = b"kernel32.dll\x00"

rdata = bytearray(0x400)
K32_ILT_OFF = 0x30
K32_ILT_SIZE = (len(kernel32_funcs) + 1) * 4
K32_IAT_OFF = K32_ILT_OFF + K32_ILT_SIZE
K32_IAT_SIZE = K32_ILT_SIZE
k32_name_off = (K32_IAT_OFF + K32_IAT_SIZE + 3) & ~3
rdata[k32_name_off:k32_name_off+len(kernel32_name)] = kernel32_name

hn_off = (k32_name_off + len(kernel32_name) + 3) & ~3
k32_hn_rvas = []
for hn in k32_hns:
    k32_hn_rvas.append(RDATA_RVA + hn_off)
    rdata[hn_off:hn_off+len(hn)] = hn
    hn_off += len(hn)

for i, rva in enumerate(k32_hn_rvas):
    struct.pack_into('<I', rdata, K32_ILT_OFF + i*4, rva)
    struct.pack_into('<I', rdata, K32_IAT_OFF + i*4, rva)

struct.pack_into('<IIIII', rdata, 0,
    RDATA_RVA + K32_ILT_OFF, 0, 0, RDATA_RVA + k32_name_off, RDATA_RVA + K32_IAT_OFF)
rdata[20:40] = b'\x00' * 20

IAT = {}
for i, name in enumerate(kernel32_funcs):
    IAT[name] = IMAGE_BASE + RDATA_RVA + K32_IAT_OFF + i * 4

# BSS area
BSS_ABS = IMAGE_BASE + 0x3000
CHAR_BUF = BSS_ABS
NUM_WRITTEN = BSS_ABS + 0x10
STDOUT_H = BSS_ABS + 0x20

a = Asm()
a.jmp32('main')

# set_cursor: cl=x, ch=y
a.label('set_cursor')
a.emit(b'\x0F\xB6\xC1')     # movzx eax, cl
a.emit(b'\x0F\xB6\xD5')     # movzx edx, ch
a.emit(b'\xC1\xE2\x10')     # shl edx, 16
a.emit(b'\x09\xD0')          # or eax, edx
a.emit(b'\x50')               # push eax (COORD)
a.emit(b'\xFF\x35')           # push [STDOUT]
a.emit_u32(STDOUT_H)
a.call_iat(IAT['SetConsoleCursorPosition'])
a.emit(b'\xC3')

# write_char: al=char
a.label('write_char')
a.emit(b'\xA2')
a.emit_u32(CHAR_BUF)
a.emit(b'\x6A\x00')          # push 0
a.emit(b'\x68')
a.emit_u32(NUM_WRITTEN)
a.emit(b'\x6A\x01')
a.emit(b'\x68')
a.emit_u32(CHAR_BUF)
a.emit(b'\xFF\x35')
a.emit_u32(STDOUT_H)
a.call_iat(IAT['WriteConsoleA'])
a.emit(b'\xC3')

a.label('main')
a.emit(b'\x55')               # push ebp
a.emit(b'\x89\xE5')           # mov ebp, esp

# GetStdHandle(-11)
a.emit(b'\x6A\xF5')
a.call_iat(IAT['GetStdHandle'])
a.emit(b'\xA3')
a.emit_u32(STDOUT_H)

# Draw top border: 20 '#' at row 0
a.emit(b'\x31\xC9')           # xor ecx, ecx (x=0, y=0)
a.label('top')
a.call_local('set_cursor')
a.emit(b'\xB0\x23')           # mov al, '#'
a.call_local('write_char')
a.emit(b'\xFE\xC1')           # inc cl
a.emit(b'\x80\xF9\x14')      # cmp cl, 20
a.jcc(0x72, 'top')

# Draw left side: '#' at x=0, y=1..9
a.emit(b'\xB5\x01')           # mov ch, 1
a.label('left')
a.emit(b'\x30\xC9')           # xor cl, cl
a.call_local('set_cursor')
a.emit(b'\xB0\x23')
a.call_local('write_char')
a.emit(b'\xFE\xC5')           # inc ch
a.emit(b'\x80\xFD\x0A')      # cmp ch, 10
a.jcc(0x72, 'left')

# Draw "OK" at (5, 5)
a.emit(b'\xB1\x05')           # mov cl, 5
a.emit(b'\xB5\x05')           # mov ch, 5
a.call_local('set_cursor')
a.emit(b'\xB0\x4F')           # mov al, 'O'
a.call_local('write_char')
a.emit(b'\xB0\x4B')           # mov al, 'K'
a.call_local('write_char')

# Move cursor to (0, 12)
a.emit(b'\xB1\x00')
a.emit(b'\xB5\x0C')
a.call_local('set_cursor')

# Sleep 3 seconds then exit
a.emit(b'\x68\xB8\x0B\x00\x00')  # push 3000
a.call_iat(IAT['Sleep'])

a.emit(b'\x6A\x00')
a.call_iat(IAT['ExitProcess'])

code_bytes = a.bytes()
text_size = (len(code_bytes) + 0x1FF) & ~0x1FF
text_section = code_bytes.ljust(text_size, b'\x00')

dos_header = bytearray(0x80)
dos_header[0:2] = b'MZ'
struct.pack_into('<I', dos_header, 0x3C, 0x80)
pe_sig = b'PE\x00\x00'
coff = struct.pack('<HHIIIHH', 0x014C, 3, 0, 0, 0, 0xE0, 0x0103)
opt = bytearray(0xE0)
struct.pack_into('<H', opt, 0, 0x10B)
struct.pack_into('<B', opt, 2, 6)
struct.pack_into('<I', opt, 4, text_size)
struct.pack_into('<I', opt, 8, 0x400)
struct.pack_into('<I', opt, 16, TEXT_RVA)
struct.pack_into('<I', opt, 20, TEXT_RVA)
struct.pack_into('<I', opt, 24, RDATA_RVA)
struct.pack_into('<I', opt, 28, IMAGE_BASE)
struct.pack_into('<I', opt, 32, 0x1000)
struct.pack_into('<I', opt, 36, 0x200)
struct.pack_into('<H', opt, 40, 4)
struct.pack_into('<H', opt, 48, 4)
struct.pack_into('<I', opt, 56, 0x5000)
struct.pack_into('<I', opt, 60, 0x200)
struct.pack_into('<H', opt, 68, 3)
struct.pack_into('<I', opt, 72, 0x100000)
struct.pack_into('<I', opt, 76, 0x1000)
struct.pack_into('<I', opt, 80, 0x100000)
struct.pack_into('<I', opt, 84, 0x1000)
struct.pack_into('<I', opt, 92, 16)
struct.pack_into('<II', opt, 96+8, RDATA_RVA, 40)
struct.pack_into('<II', opt, 96+96, RDATA_RVA+K32_IAT_OFF, K32_IAT_SIZE)

def section_hdr(name, vsize, rva, rawsize, rawptr, chars):
    h = bytearray(40)
    h[0:len(name)] = name
    struct.pack_into('<I', h, 8, vsize)
    struct.pack_into('<I', h, 12, rva)
    struct.pack_into('<I', h, 16, rawsize)
    struct.pack_into('<I', h, 20, rawptr)
    struct.pack_into('<I', h, 36, chars)
    return bytes(h)

text_hdr = section_hdr(b'.text\x00\x00\x00', text_size, TEXT_RVA, text_size, 0x200, 0x60000020)
rdata_hdr = section_hdr(b'.rdata\x00\x00', 0x400, RDATA_RVA, 0x400, 0x200+text_size, 0x40000040)
bss_hdr = section_hdr(b'.bss\x00\x00\x00\x00', 0x1000, 0x3000, 0, 0, 0xC0000080)

headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + text_hdr + rdata_hdr + bss_hdr
headers = headers.ljust(0x200, b'\x00')
exe = headers + text_section + bytes(rdata[:0x400])

with open('test_draw.exe', 'wb') as f:
    f.write(exe)
print(f"Generated test_draw.exe ({len(exe)} bytes, code={len(code_bytes)})")
