#!/usr/bin/env python3
"""Generate a PE exe that prints a Fibonacci triangle using raw machine code.
   Features: nested loops, integer division (itoa), subroutine call/ret.

   Output:
   1
   1 1
   1 1 2
   1 1 2 3
   1 1 2 3 5
   ...
"""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000
N_ROWS = 10

# ============================================================
# Mini assembler with label support
# ============================================================
class Asm:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []  # (offset, size, label, relative)

    def pos(self):
        return len(self.code)

    def emit(self, bs):
        self.code.extend(bs)

    def label(self, name):
        self.labels[name] = self.pos()

    def emit_u32(self, val):
        self.emit(struct.pack('<I', val))

    def emit_i32(self, val):
        self.emit(struct.pack('<i', val))

    # jmp rel8
    def jmp(self, label):
        self.emit(b'\xEB')
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    # jmp rel32
    def jmp32(self, label):
        self.emit(b'\xE9')
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')

    # jcc rel8
    def jcc(self, opcode, label):
        self.emit(bytes([opcode]))
        self.fixups.append((self.pos(), 1, label, True))
        self.emit(b'\x00')

    # call rel32 (local subroutine)
    def call_local(self, label):
        self.emit(b'\xE8')
        self.fixups.append((self.pos(), 4, label, True))
        self.emit(b'\x00\x00\x00\x00')

    # call [imm32] (indirect through IAT)
    def call_iat(self, addr):
        self.emit(b'\xFF\x15')
        self.emit_u32(addr)

    def resolve(self):
        for off, size, lbl, relative in self.fixups:
            target = self.labels[lbl]
            if relative:
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
# .rdata
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
hn_pos = 0x80
hn_rvas = []
for hn in hn_list:
    hn_rvas.append(RDATA_RVA + hn_pos)
    rdata[hn_pos:hn_pos+len(hn)] = hn
    hn_pos += len(hn)

rdata[0x70:0x70+len(kernel32_str)] = kernel32_str

ilt_off, iat_off = 0x50, 0x60
ilt = struct.pack('<IIII', *hn_rvas, 0)
rdata[ilt_off:ilt_off+len(ilt)] = ilt
rdata[iat_off:iat_off+len(ilt)] = ilt

idt = struct.pack('<IIIII', RDATA_RVA+ilt_off, 0, 0, RDATA_RVA+0x70, RDATA_RVA+iat_off)
idt += b'\x00' * 20
rdata[0:len(idt)] = idt

IAT_GetStdHandle = IMAGE_BASE + RDATA_RVA + iat_off
IAT_WriteFile    = IMAGE_BASE + RDATA_RVA + iat_off + 4
IAT_ExitProcess  = IMAGE_BASE + RDATA_RVA + iat_off + 8

# ============================================================
# .text: Fibonacci triangle in x86 machine code
# ============================================================
# Stack frame layout (after prologue):
#   [ebp - 4]    stdout handle
#   [ebp - 8]    fib_a
#   [ebp - 12]   fib_b
#   [ebp - 16]   col counter
#   [ebp - 20]   row counter (esi)
#   [ebp - 128]  line buffer (108 bytes)
#   [ebp - 132]  written (for WriteFile)
#
# We use edi as buffer write pointer within inner loop.

a = Asm()

# Jump over subroutine
a.jmp32('main')

# ============================================================
# itoa subroutine: convert integer to decimal ASCII
#   Input:  eax = number, edi = buffer pointer
#   Output: edi = advanced past written digits
#   Clobbers: eax, ecx, edx
# ============================================================
a.label('itoa')
a.emit(b'\x53')                        # push ebx
a.emit(b'\x31\xC9')                    # xor ecx, ecx  (digit count = 0)
a.emit(b'\xBB\x0A\x00\x00\x00')       # mov ebx, 10

a.label('itoa_div')
a.emit(b'\x31\xD2')                    # xor edx, edx
a.emit(b'\xF7\xF3')                    # div ebx  (eax/10, remainder in edx)
a.emit(b'\x52')                        # push edx (save digit)
a.emit(b'\x41')                        # inc ecx
a.emit(b'\x85\xC0')                    # test eax, eax
a.jcc(0x75, 'itoa_div')                # jnz itoa_div

a.label('itoa_write')
a.emit(b'\x58')                        # pop eax
a.emit(b'\x04\x30')                    # add al, '0'
a.emit(b'\x88\x07')                    # mov [edi], al
a.emit(b'\x47')                        # inc edi
a.emit(b'\x49')                        # dec ecx
a.jcc(0x75, 'itoa_write')              # jnz itoa_write

a.emit(b'\x5B')                        # pop ebx
a.emit(b'\xC3')                        # ret

# ============================================================
# main
# ============================================================
a.label('main')

# Prologue
a.emit(b'\x55')                        # push ebp
a.emit(b'\x89\xE5')                    # mov ebp, esp
a.emit(b'\x81\xEC\x84\x00\x00\x00')   # sub esp, 132

# GetStdHandle(-11)
a.emit(b'\x6A\xF5')                    # push -11
a.call_iat(IAT_GetStdHandle)
a.emit(b'\x89\x45\xFC')               # mov [ebp-4], eax  (stdout)

# esi = row counter = 1
a.emit(b'\xBE\x01\x00\x00\x00')       # mov esi, 1

# --- outer loop (rows) ---
a.label('row_loop')

# Initialize fib: a=1, b=1
a.emit(b'\xC7\x45\xF8\x01\x00\x00\x00')  # mov [ebp-8], 1   (fib_a)
a.emit(b'\xC7\x45\xF4\x01\x00\x00\x00')  # mov [ebp-12], 1  (fib_b)

# col counter [ebp-16] = esi (number of cols this row)
a.emit(b'\x89\x75\xF0')               # mov [ebp-16], esi

# edi = buffer start
a.emit(b'\x8D\xBD\x80\xFF\xFF\xFF')   # lea edi, [ebp-128]

# --- inner loop (columns) ---
a.label('col_loop')

# eax = fib_a, call itoa
a.emit(b'\x8B\x45\xF8')               # mov eax, [ebp-8]
a.call_local('itoa')

# write space after number
a.emit(b'\xC6\x07\x20')               # mov byte [edi], ' '
a.emit(b'\x47')                        # inc edi

# advance fibonacci: new_a = fib_b, new_b = fib_a + fib_b
a.emit(b'\x8B\x45\xF8')               # mov eax, [ebp-8]   (old a)
a.emit(b'\x8B\x4D\xF4')               # mov ecx, [ebp-12]  (old b)
a.emit(b'\x89\x4D\xF8')               # mov [ebp-8], ecx   (a = old b)
a.emit(b'\x01\xC1')                    # add ecx, eax       (ecx = a+b)
a.emit(b'\x89\x4D\xF4')               # mov [ebp-12], ecx  (b = a+b)

# dec col counter
a.emit(b'\xFF\x4D\xF0')               # dec dword [ebp-16]
a.jcc(0x75, 'col_loop')                # jnz col_loop

# --- end of row: replace last space with \r\n ---
a.emit(b'\x4F')                        # dec edi (back over trailing space)
a.emit(b'\xC6\x07\x0D')               # mov byte [edi], 0x0D
a.emit(b'\x47')                        # inc edi
a.emit(b'\xC6\x07\x0A')               # mov byte [edi], 0x0A
a.emit(b'\x47')                        # inc edi

# line length = edi - (ebp-128)
a.emit(b'\x8D\x8D\x80\xFF\xFF\xFF')   # lea ecx, [ebp-128]  (buf start)
a.emit(b'\x89\xFA')                    # mov edx, edi
a.emit(b'\x29\xCA')                    # sub edx, ecx        (edx = length)

# WriteFile(handle, buf, len, &written, 0)
a.emit(b'\x6A\x00')                    # push 0 (lpOverlapped)
a.emit(b'\x8D\x45\x7C')               # lea eax, [ebp-132]...
# actually ebp-132 = ebp - 0x84, let me use the written var
# Recalculate: [ebp - 132] is at offset -0x84
a.emit(b'\x8D\x85\x7C\xFF\xFF\xFF')   # lea eax, [ebp-132]
a.emit(b'\x50')                        # push eax  (&written)
a.emit(b'\x52')                        # push edx  (nBytes)
a.emit(b'\x51')                        # push ecx  (lpBuffer)
a.emit(b'\xFF\x75\xFC')               # push [ebp-4]  (handle)
a.call_iat(IAT_WriteFile)

# next row
a.emit(b'\x46')                        # inc esi
a.emit(b'\x81\xFE')                    # cmp esi, N_ROWS
a.emit_u32(N_ROWS + 1)
a.jcc(0x75, 'row_loop')                # jne row_loop

# ExitProcess(0)
a.emit(b'\x6A\x00')                    # push 0
a.call_iat(IAT_ExitProcess)

code_bytes = a.bytes()
text_section = code_bytes.ljust(0x200, b'\x00')

# ============================================================
# PE Headers
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

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fib_triangle.exe")
with open(out_path, 'wb') as f:
    f.write(exe)

print(f"Generated {out_path} ({len(exe)} bytes)")
print(f"Machine code ({len(code_bytes)} bytes):")
for i in range(0, len(code_bytes), 16):
    chunk = code_bytes[i:i+16]
    hexstr = ' '.join(f'{b:02X}' for b in chunk)
    print(f"  {i:04X}: {hexstr}")
print(f"\nRows: {N_ROWS}")
