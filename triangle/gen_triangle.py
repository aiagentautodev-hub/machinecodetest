#!/usr/bin/env python3
"""Generate a PE exe that prints a triangle of '*' using raw machine code.
   Features: loops, conditionals, stack buffer manipulation."""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000

N_ROWS = 10  # triangle height

# ============================================================
# Mini assembler with label support (handles forward jumps)
# ============================================================
class Asm:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}       # name -> offset
        self.fixups = []       # (offset, size, label, relative)

    def pos(self):
        return len(self.code)

    def emit(self, bs):
        self.code.extend(bs)

    def label(self, name):
        self.labels[name] = self.pos()

    def emit_u32(self, val):
        self.emit(struct.pack('<I', val))

    # jmp rel8
    def jmp(self, label):
        self.emit(b'\xEB')
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    # jcc rel8 (short conditional jump)
    def jcc(self, opcode, label):
        self.emit(bytes([opcode]))
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    # jcc rel32 (near conditional jump, 0F 8x)
    def jcc32(self, opcode2, label):
        self.emit(bytes([0x0F, opcode2]))
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')

    # call [imm32] (indirect call through IAT)
    def call_iat(self, addr):
        self.emit(b'\xFF\x15')
        self.emit_u32(addr)

    def resolve(self):
        for off, size, lbl, relative in self.fixups:
            target = self.labels[lbl]
            if relative:
                # relative to instruction after the operand
                disp = target - (off + size)
                if size == 1:
                    assert -128 <= disp <= 127, f"jump to {lbl} too far: {disp}"
                    self.code[off] = disp & 0xFF
                else:
                    struct.pack_into('<i', self.code, off, disp)
            else:
                struct.pack_into('<I', self.code, off, target)

    def bytes(self):
        self.resolve()
        return bytes(self.code)

# ============================================================
# .rdata: imports + data
# ============================================================
def hint_name(hint, name):
    b = struct.pack('<H', hint) + name.encode() + b'\x00'
    if len(b) % 2: b += b'\x00'
    return b

kernel32_str = b"kernel32.dll\x00"
hn_list = [
    hint_name(0, "GetStdHandle"),
    hint_name(0, "WriteFile"),
    hint_name(0, "ExitProcess"),
]

rdata = bytearray(0x200)

# Hint/Name entries at 0x80
hn_pos = 0x80
hn_rvas = []
for hn in hn_list:
    hn_rvas.append(RDATA_RVA + hn_pos)
    rdata[hn_pos:hn_pos+len(hn)] = hn
    hn_pos += len(hn)

# kernel32 name at 0x70
rdata[0x70:0x70+len(kernel32_str)] = kernel32_str

# ILT at 0x50, IAT at 0x60
ilt_off, iat_off = 0x50, 0x60
ilt = struct.pack('<IIII', *hn_rvas, 0)
rdata[ilt_off:ilt_off+len(ilt)] = ilt
rdata[iat_off:iat_off+len(ilt)] = ilt

# IDT at 0x00
idt = struct.pack('<IIIII', RDATA_RVA+ilt_off, 0, 0, RDATA_RVA+0x70, RDATA_RVA+iat_off)
idt += b'\x00' * 20
rdata[0:len(idt)] = idt

IAT = [IMAGE_BASE + RDATA_RVA + iat_off + i*4 for i in range(3)]
IAT_GetStdHandle, IAT_WriteFile, IAT_ExitProcess = IAT

# ============================================================
# .text: the triangle algorithm in raw x86
# ============================================================
# Algorithm:
#   get stdout handle -> edi
#   for i = 1 to N:
#     build line in stack buffer:  (N-i) spaces + (2*i-1) stars + \r\n
#     WriteFile(edi, buf, len, &written, 0)
#   ExitProcess(0)
#
# Register plan:
#   edi = stdout handle
#   esi = i (row counter, 1..N)
#   ebx = N (constant)
#
# Stack: [esp] = line buffer (64 bytes), [esp+64] = written dword

a = Asm()

# Prologue: reserve stack space (64 buf + 4 written + padding)
a.emit(b'\x83\xEC\x50')              # sub esp, 80

# Save callee-saved regs
a.emit(b'\x57')                       # push edi
a.emit(b'\x56')                       # push esi
a.emit(b'\x53')                       # push ebx

# GetStdHandle(-11)
a.emit(b'\x6A\xF5')                   # push -11
a.call_iat(IAT_GetStdHandle)
a.emit(b'\x89\xC7')                   # mov edi, eax  (handle)

# ebx = N, esi = 1
a.emit(b'\xBB')                        # mov ebx, N
a.emit_u32(N_ROWS)
a.emit(b'\xBE\x01\x00\x00\x00')       # mov esi, 1

# --- outer loop ---
a.label('row_loop')

# ecx = N - i (number of spaces)
a.emit(b'\x89\xD9')                   # mov ecx, ebx
a.emit(b'\x29\xF1')                   # sub ecx, esi

# edx -> buffer start = esp + 12 (after pushed regs)
a.emit(b'\x8D\x54\x24\x0C')          # lea edx, [esp+12]

# ebp = edx (save buffer start)
a.emit(b'\x89\xD5')                   # mov ebp, edx

# --- fill spaces ---
# store ecx spaces at [edx], advance edx
a.emit(b'\x85\xC9')                   # test ecx, ecx
a.jcc(0x74, 'spaces_done')            # jz spaces_done

a.label('space_loop')
a.emit(b'\xC6\x02\x20')              # mov byte [edx], ' '
a.emit(b'\x42')                        # inc edx
a.emit(b'\x49')                        # dec ecx
a.jcc(0x75, 'space_loop')             # jnz space_loop

a.label('spaces_done')

# ecx = 2*i - 1 (number of stars)
a.emit(b'\x8D\x0C\x36')              # lea ecx, [esi+esi]  ; ecx = 2*i
a.emit(b'\x49')                        # dec ecx             ; ecx = 2*i-1

a.label('star_loop')
a.emit(b'\xC6\x02\x2A')              # mov byte [edx], '*'
a.emit(b'\x42')                        # inc edx
a.emit(b'\x49')                        # dec ecx
a.jcc(0x75, 'star_loop')              # jnz star_loop

# append \r\n
a.emit(b'\xC6\x02\x0D')              # mov byte [edx], 0x0D
a.emit(b'\x42')                        # inc edx
a.emit(b'\xC6\x02\x0A')              # mov byte [edx], 0x0A
a.emit(b'\x42')                        # inc edx

# line length = edx - ebp
a.emit(b'\x29\xEA')                   # sub edx, ebp  ; edx = length

# WriteFile(edi, ebp, edx, &written, 0)
a.emit(b'\x6A\x00')                   # push 0 (lpOverlapped)
a.emit(b'\x8D\x4C\x24\x50')          # lea ecx, [esp+0x50] ; &written (adjusted for push)
a.emit(b'\x51')                        # push ecx
a.emit(b'\x52')                        # push edx  (nBytes)
a.emit(b'\x55')                        # push ebp  (lpBuffer)
a.emit(b'\x57')                        # push edi  (hFile)
a.call_iat(IAT_WriteFile)

# esi++, compare with ebx
a.emit(b'\x46')                        # inc esi
a.emit(b'\x39\xDE')                   # cmp esi, ebx
a.jcc(0x7E, 'row_loop')               # jle row_loop

# ExitProcess(0)
a.emit(b'\x6A\x00')                   # push 0
a.call_iat(IAT_ExitProcess)

code_bytes = a.bytes()
text_section = code_bytes.ljust(0x200, b'\x00')

# ============================================================
# PE Headers (same structure as hello.exe)
# ============================================================
dos_header = bytearray(0x80)
dos_header[0:2] = b'MZ'
struct.pack_into('<I', dos_header, 0x3C, 0x80)

pe_sig = b'PE\x00\x00'
coff = struct.pack('<HHIIIHH', 0x014C, 2, 0, 0, 0, 0xE0, 0x0103)

opt = bytearray(0xE0)
struct.pack_into('<H', opt, 0, 0x10B)
struct.pack_into('<B', opt, 2, 6)
struct.pack_into('<I', opt, 4, 0x200)
struct.pack_into('<I', opt, 8, 0x200)
struct.pack_into('<I', opt, 16, TEXT_RVA)
struct.pack_into('<I', opt, 20, TEXT_RVA)
struct.pack_into('<I', opt, 24, RDATA_RVA)
struct.pack_into('<I', opt, 28, IMAGE_BASE)
struct.pack_into('<I', opt, 32, 0x1000)
struct.pack_into('<I', opt, 36, 0x200)
struct.pack_into('<H', opt, 40, 4)
struct.pack_into('<H', opt, 48, 4)
struct.pack_into('<I', opt, 56, 0x3000)
struct.pack_into('<I', opt, 60, 0x200)
struct.pack_into('<H', opt, 68, 3)
struct.pack_into('<I', opt, 72, 0x100000)
struct.pack_into('<I', opt, 76, 0x1000)
struct.pack_into('<I', opt, 80, 0x100000)
struct.pack_into('<I', opt, 84, 0x1000)
struct.pack_into('<I', opt, 92, 16)
struct.pack_into('<II', opt, 96 + 8, RDATA_RVA, 40)
struct.pack_into('<II', opt, 96 + 96, RDATA_RVA + iat_off, 16)

def section_hdr(name, vsize, rva, rawsize, rawptr, chars):
    h = bytearray(40)
    h[0:len(name)] = name
    struct.pack_into('<I', h, 8, vsize)
    struct.pack_into('<I', h, 12, rva)
    struct.pack_into('<I', h, 16, rawsize)
    struct.pack_into('<I', h, 20, rawptr)
    struct.pack_into('<I', h, 36, chars)
    return bytes(h)

text_hdr  = section_hdr(b'.text\x00\x00\x00', 0x200, TEXT_RVA, 0x200, 0x200, 0x60000020)
rdata_hdr = section_hdr(b'.rdata\x00\x00', 0x200, RDATA_RVA, 0x200, 0x400, 0x40000040)

headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + text_hdr + rdata_hdr
headers = headers.ljust(0x200, b'\x00')

exe = headers + text_section + bytes(rdata)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "triangle.exe")
with open(out_path, 'wb') as f:
    f.write(exe)

print(f"Generated {out_path} ({len(exe)} bytes)")
print(f"Machine code ({len(code_bytes)} bytes):")
for i in range(0, len(code_bytes), 16):
    chunk = code_bytes[i:i+16]
    hexstr = ' '.join(f'{b:02X}' for b in chunk)
    print(f"  {i:04X}: {hexstr}")
print(f"\nTriangle rows: {N_ROWS}")
