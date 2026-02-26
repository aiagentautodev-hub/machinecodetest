#!/usr/bin/env python3
"""Generate a PE exe that renders the Mandelbrot set in ASCII using raw machine code.
   Uses fixed-point arithmetic (16.16 format) for fractional math.

   Output: 80x40 ASCII Mandelbrot set with density-mapped characters.
"""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000

# Display size
WIDTH  = 80
HEIGHT = 40
MAX_ITER = 64

# Fixed-point 16.16 constants
# View: x in [-2.5, 1.0], y in [-1.2, 1.2]
# FP16.16: multiply by 65536
def fp(f):
    return int(f * 65536) & 0xFFFFFFFF

X_MIN = fp(-2.5)    # 0xFFFD8000
X_MAX = fp(1.0)     # 0x00010000
Y_MIN = fp(-1.2)    # 0xFFFECCCD
Y_MAX = fp(1.2)     # 0x00013333

# dx = (X_MAX - X_MIN) / WIDTH, dy = (Y_MAX - Y_MIN) / HEIGHT
# We'll compute these in code to avoid precision issues

# Characters mapped by iteration count (dark to light)
# " .:-=+*#%@" (10 chars, index = iter * 10 / MAX_ITER)
palette = b' .:-=+*#%@'

# ============================================================
class Asm:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []
    def pos(self): return len(self.code)
    def emit(self, bs): self.code.extend(bs)
    def label(self, name): self.labels[name] = self.pos()
    def emit_u32(self, val): self.emit(struct.pack('<I', val))
    def emit_i32(self, val): self.emit(struct.pack('<i', val))
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
    def resolve(self):
        for off, size, lbl, relative in self.fixups:
            assert lbl in self.labels, f"undefined label: {lbl}"
            target = self.labels[lbl]
            disp = target - (off + size)
            if size == 1:
                assert -128 <= disp <= 127, f"jump to {lbl} too far: {disp}"
                self.code[off] = disp & 0xFF
            else:
                struct.pack_into('<i', self.code, off, disp)
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

kernel32_funcs = ["GetStdHandle", "WriteFile", "ExitProcess"]
k32_hns = [hint_name(0, f) for f in kernel32_funcs]
kernel32_name = b"kernel32.dll\x00"

rdata = bytearray(0x200)

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

# Palette string
pal_off = (hn_off + 3) & ~3
palette_rva = RDATA_RVA + pal_off
rdata[pal_off:pal_off+len(palette)] = palette
pal_off += len(palette)

IAT = {}
for i, name in enumerate(kernel32_funcs):
    IAT[name] = IMAGE_BASE + RDATA_RVA + K32_IAT_OFF + i * 4

# BSS
BSS_RVA = 0x3000
BSS_ABS = IMAGE_BASE + BSS_RVA
# Line buffer: WIDTH + 2 bytes (\r\n) at offset 0
LINE_BUF = BSS_ABS
WRITTEN  = BSS_ABS + 0x100
STDOUT_H = BSS_ABS + 0x104

# ============================================================
# Machine code
# ============================================================
a = Asm()

a.jmp32('main')

# ============================================================
# fp_mul: signed fixed-point 16.16 multiply
#   Input:  eax, ecx (both signed fp16.16)
#   Output: eax = (eax * ecx) >> 16
#   Clobbers: edx
# ============================================================
a.label('fp_mul')
a.emit(b'\xF7\xE9')                   # imul ecx  (edx:eax = eax * ecx, signed)
# Result is in edx:eax as 64-bit. We need bits [47:16] = middle 32 bits.
# That's: (edx << 16) | (eax >> 16)
a.emit(b'\x0F\xAC\xD0\x10')          # shrd eax, edx, 16
a.emit(b'\xC3')                        # ret

# ============================================================
# mandelbrot_iter: compute iterations for point (cx, cy)
#   Input:  [ebp-4] = cx (fp16.16), [ebp-8] = cy (fp16.16)
#   Output: eax = iteration count (0..MAX_ITER)
#   Algorithm: z = 0; for i in 0..MAX_ITER: z = z^2 + c; if |z|^2 > 4: break
# ============================================================
a.label('mandel_iter')
a.emit(b'\x55')                        # push ebp
a.emit(b'\x89\xE5')                    # mov ebp, esp
a.emit(b'\x83\xEC\x10')               # sub esp, 16

# Local vars: [ebp-4]=cx, [ebp-8]=cy already on stack from caller
# We use: esi=zx, edi=zy, ebx=iteration counter

a.emit(b'\x53')                        # push ebx
a.emit(b'\x56')                        # push esi
a.emit(b'\x57')                        # push edi

a.emit(b'\x31\xF6')                    # xor esi, esi  (zx = 0)
a.emit(b'\x31\xFF')                    # xor edi, edi  (zy = 0)
a.emit(b'\x31\xDB')                    # xor ebx, ebx  (iter = 0)

a.label('mi_loop')
# zx2 = zx * zx
a.emit(b'\x89\xF0')                    # mov eax, esi
a.emit(b'\x89\xF1')                    # mov ecx, esi
a.call_local('fp_mul')
a.emit(b'\x89\x45\xF0')              # mov [ebp-16], eax  (zx2)

# zy2 = zy * zy
a.emit(b'\x50')                        # push eax (save zx2)
a.emit(b'\x89\xF8')                    # mov eax, edi
a.emit(b'\x89\xF9')                    # mov ecx, edi
a.call_local('fp_mul')
# eax = zy2
a.emit(b'\x89\xC2')                    # mov edx, eax (zy2)
a.emit(b'\x58')                        # pop eax... no wait, I saved zx2 on stack
# Actually let me reorganize. Let me keep zx2 in a local.

# Wait, let me redo this more carefully.
# eax = zy2 now, [ebp-16] = zx2

# Check |z|^2 = zx2 + zy2 > 4.0 (fp 4.0 = 0x40000)
a.emit(b'\x8B\x4D\xF0')              # mov ecx, [ebp-16]  (zx2)
a.emit(b'\x01\xC1')                    # add ecx, eax       (zx2 + zy2)
a.emit(b'\x81\xF9\x00\x00\x04\x00')  # cmp ecx, 0x00040000 (4.0 in fp16.16)
a.jcc32(0x8D, 'mi_done')              # jge mi_done (escaped)

# new_zy = 2 * zx * zy + cy
a.emit(b'\x89\xF0')                    # mov eax, esi (zx)
a.emit(b'\x89\xF9')                    # mov ecx, edi (zy)
a.call_local('fp_mul')
# eax = zx * zy
a.emit(b'\x01\xC0')                    # add eax, eax  (2 * zx * zy)
a.emit(b'\x03\x45\xF8')              # add eax, [ebp-8]  (+ cy)
a.emit(b'\x89\xC7')                    # mov edi, eax  (new zy)

# new_zx = zx2 - zy2 + cx
a.emit(b'\x8B\x45\xF0')              # mov eax, [ebp-16]  (zx2)
a.emit(b'\x2B\xC2')                    # sub eax, edx       (zx2 - zy2) -- edx still has zy2!
# Wait, edx got clobbered by fp_mul call. I need to save zy2.

# Let me redesign to save zy2 properly.
# Actually I already used edx=zy2 before the fp_mul call for 2*zx*zy.
# fp_mul clobbers edx. So I need to save zy2 in a local.

# --- Let me restart the loop body more carefully ---

# I'll rewrite the whole mandel_iter

# Clear everything from mi_loop onwards and redo
a2_start = None  # We'll just keep going and fix it

# Hmm, the issue is I already emitted partial code. Let me just restart the whole Asm.

# ============================================================
# Let me restart cleanly
# ============================================================

a = Asm()
a.jmp32('main')

# fp_mul: eax * ecx -> eax (fp16.16 signed)
a.label('fp_mul')
a.emit(b'\xF7\xE9')                   # imul ecx
a.emit(b'\x0F\xAC\xD0\x10')          # shrd eax, edx, 16
a.emit(b'\xC3')

# ============================================================
# mandel_iter(cx, cy) -> eax = iterations
# Args passed on stack: [esp+4]=cx, [esp+8]=cy (after call)
# ============================================================
a.label('mandel_iter')
a.emit(b'\x55')                        # push ebp
a.emit(b'\x89\xE5')                    # mov ebp, esp
a.emit(b'\x83\xEC\x10')               # sub esp, 16 (locals: [ebp-4]=zx2, [ebp-8]=zy2)
a.emit(b'\x53')                        # push ebx
a.emit(b'\x56')                        # push esi
a.emit(b'\x57')                        # push edi

# esi=zx, edi=zy, ebx=iter
a.emit(b'\x31\xF6')                    # xor esi, esi
a.emit(b'\x31\xFF')                    # xor edi, edi
a.emit(b'\x31\xDB')                    # xor ebx, ebx

a.label('mi_loop')
# Compute zx2 = zx * zx
a.emit(b'\x89\xF0')                    # mov eax, esi
a.emit(b'\x89\xF1')                    # mov ecx, esi
a.call_local('fp_mul')
a.emit(b'\x89\x45\xFC')              # mov [ebp-4], eax  (zx2)

# Compute zy2 = zy * zy
a.emit(b'\x89\xF8')                    # mov eax, edi
a.emit(b'\x89\xF9')                    # mov ecx, edi
a.call_local('fp_mul')
a.emit(b'\x89\x45\xF8')              # mov [ebp-8], eax  (zy2)

# Check zx2 + zy2 >= 4.0 (0x40000)
a.emit(b'\x8B\x4D\xFC')              # mov ecx, [ebp-4]
a.emit(b'\x01\xC1')                    # add ecx, eax
a.emit(b'\x81\xF9\x00\x00\x04\x00')  # cmp ecx, 0x00040000
a.jcc32(0x8D, 'mi_done')              # jge -> escaped

# new_zy = 2 * zx * zy + cy
a.emit(b'\x89\xF0')                    # mov eax, esi
a.emit(b'\x89\xF9')                    # mov ecx, edi
a.call_local('fp_mul')                 # eax = zx * zy
a.emit(b'\x01\xC0')                    # add eax, eax (2 * zx * zy)
a.emit(b'\x03\x45\x0C')              # add eax, [ebp+12] (+ cy)
# Save new_zy temporarily
a.emit(b'\x89\xC7')                    # mov edi, eax (new zy - temporary, ok since we compute zx next)

# new_zx = zx2 - zy2 + cx
a.emit(b'\x8B\x45\xFC')              # mov eax, [ebp-4]  (zx2)
a.emit(b'\x2B\x45\xF8')              # sub eax, [ebp-8]  (- zy2)
a.emit(b'\x03\x45\x08')              # add eax, [ebp+8]  (+ cx)
a.emit(b'\x89\xC6')                    # mov esi, eax (new zx)

# iter++
a.emit(b'\x43')                        # inc ebx
a.emit(b'\x81\xFB')                   # cmp ebx, MAX_ITER
a.emit_u32(MAX_ITER)
a.jcc32(0x8C, 'mi_loop')              # jl mi_loop

a.label('mi_done')
a.emit(b'\x89\xD8')                    # mov eax, ebx (return iter count)
a.emit(b'\x5F')                        # pop edi
a.emit(b'\x5E')                        # pop esi
a.emit(b'\x5B')                        # pop ebx
a.emit(b'\x89\xEC')                    # mov esp, ebp
a.emit(b'\x5D')                        # pop ebp
a.emit(b'\xC3')                        # ret

# ============================================================
# main
# ============================================================
a.label('main')
a.emit(b'\x55')                        # push ebp
a.emit(b'\x89\xE5')                    # mov ebp, esp
a.emit(b'\x83\xEC\x20')               # sub esp, 32

# GetStdHandle(-11)
a.emit(b'\x6A\xF5')
a.call_iat(IAT['GetStdHandle'])
a.emit(b'\xA3')
a.emit_u32(STDOUT_H)

# Outer loop: y from 0 to HEIGHT-1
# We compute cy for each row and cx for each column.
#
# cy = Y_MIN + row * dy, where dy = (Y_MAX - Y_MIN) / HEIGHT
# cx = X_MIN + col * dx, where dx = (X_MAX - X_MIN) / WIDTH
#
# To avoid division, precompute dx and dy as constants.
# dx = (1.0 - (-2.5)) / 80 = 3.5 / 80 = 0.04375 = fp 2867
# dy = (1.2 - (-1.2)) / 40 = 2.4 / 40 = 0.06 = fp 3932

DX = int(3.5 / WIDTH * 65536)    # 2867
DY = int(2.4 / HEIGHT * 65536)   # 3932

# Use stack vars: [ebp-4]=row, [ebp-8]=col, [ebp-12]=cy, [ebp-16]=cx

a.emit(b'\xC7\x45\xFC\x00\x00\x00\x00')  # mov [ebp-4], 0 (row=0)

a.label('row_loop')

# cy = Y_MIN + row * DY (all as signed 32-bit)
a.emit(b'\x8B\x45\xFC')               # mov eax, [ebp-4] (row)
a.emit(b'\x69\xC0')                   # imul eax, eax, DY
a.emit_i32(DY)
a.emit(b'\x05')                        # add eax, Y_MIN
a.emit_i32(int.from_bytes(struct.pack('<I', Y_MIN), 'little', signed=True))
a.emit(b'\x89\x45\xF4')              # mov [ebp-12], eax (cy)

# Reset col, buffer pointer
a.emit(b'\xC7\x45\xF8\x00\x00\x00\x00')  # mov [ebp-8], 0 (col=0)
a.emit(b'\xBF')                        # mov edi, LINE_BUF
a.emit_u32(LINE_BUF)

a.label('col_loop')

# cx = X_MIN + col * DX
a.emit(b'\x8B\x45\xF8')              # mov eax, [ebp-8] (col)
a.emit(b'\x69\xC0')                   # imul eax, eax, DX
a.emit_i32(DX)
a.emit(b'\x05')                        # add eax, X_MIN
a.emit_i32(int.from_bytes(struct.pack('<I', X_MIN), 'little', signed=True))

# Call mandel_iter(cx, cy)
a.emit(b'\xFF\x75\xF4')              # push [ebp-12] (cy)
a.emit(b'\x50')                        # push eax (cx)
a.call_local('mandel_iter')
a.emit(b'\x83\xC4\x08')              # add esp, 8 (clean up args)

# Map iteration to palette character
# index = iter * 10 / MAX_ITER (approximate: iter * 10 >> 6 for MAX_ITER=64)
# Or simpler: iter >> (log2(MAX_ITER/10)) ≈ iter * 10 / 64
# Let's do: eax = eax * 10 / 64 = (eax * 10) >> 6
# But if iter == MAX_ITER (in set), use space (index 0)

a.emit(b'\x3D')                        # cmp eax, MAX_ITER
a.emit_u32(MAX_ITER)
a.jcc(0x72, 'not_in_set')             # jb -> not in set

# In set: use space
a.emit(b'\xC6\x07\x20')              # mov byte [edi], ' '
a.jmp('char_done')

a.label('not_in_set')
# index = eax * 10 / MAX_ITER
# eax * 10:
a.emit(b'\x8D\x04\x80')              # lea eax, [eax + eax*4]  (eax * 5)
a.emit(b'\x01\xC0')                    # add eax, eax            (eax * 10)
# / 64 = >> 6
a.emit(b'\xC1\xE8\x06')              # shr eax, 6
# Clamp to 9
a.emit(b'\x83\xF8\x09')              # cmp eax, 9
a.jcc(0x76, 'idx_ok')                 # jbe idx_ok
a.emit(b'\xB0\x09')                   # mov al, 9
a.label('idx_ok')
# Load char from palette
a.emit(b'\x0F\xB6\xC0')              # movzx eax, al
a.emit(b'\x8A\x80')                   # mov al, [palette + eax]
a.emit_u32(IMAGE_BASE + palette_rva)
a.emit(b'\x88\x07')                   # mov [edi], al

a.label('char_done')
a.emit(b'\x47')                        # inc edi

# Next col
a.emit(b'\xFF\x45\xF8')              # inc dword [ebp-8]
a.emit(b'\x81\x7D\xF8')              # cmp dword [ebp-8], WIDTH
a.emit_u32(WIDTH)
a.jcc32(0x8C, 'col_loop')             # jl col_loop

# Append \r\n
a.emit(b'\xC6\x07\x0D')              # mov byte [edi], 0x0D
a.emit(b'\x47')
a.emit(b'\xC6\x07\x0A')              # mov byte [edi], 0x0A
a.emit(b'\x47')

# Write line: WriteFile(handle, LINE_BUF, WIDTH+2, &written, 0)
line_len = WIDTH + 2
a.emit(b'\x6A\x00')                   # push 0
a.emit(b'\x68')
a.emit_u32(WRITTEN)
a.emit(b'\x68')
a.emit_u32(line_len)
a.emit(b'\x68')
a.emit_u32(LINE_BUF)
a.emit(b'\xFF\x35')
a.emit_u32(STDOUT_H)
a.call_iat(IAT['WriteFile'])

# Next row
a.emit(b'\xFF\x45\xFC')              # inc dword [ebp-4]
a.emit(b'\x81\x7D\xFC')              # cmp dword [ebp-4], HEIGHT
a.emit_u32(HEIGHT)
a.jcc32(0x8C, 'row_loop')             # jl row_loop

# Exit
a.emit(b'\x6A\x00')
a.call_iat(IAT['ExitProcess'])

code_bytes = a.bytes()
print(f"Machine code: {len(code_bytes)} bytes")

text_size = (len(code_bytes) + 0x1FF) & ~0x1FF
text_section = code_bytes.ljust(text_size, b'\x00')

# PE Headers
dos_header = bytearray(0x80)
dos_header[0:2] = b'MZ'
struct.pack_into('<I', dos_header, 0x3C, 0x80)
pe_sig = b'PE\x00\x00'
coff = struct.pack('<HHIIIHH', 0x014C, 3, 0, 0, 0, 0xE0, 0x0103)

opt = bytearray(0xE0)
struct.pack_into('<H', opt, 0, 0x10B)
struct.pack_into('<B', opt, 2, 6)
struct.pack_into('<I', opt, 4, text_size)
struct.pack_into('<I', opt, 8, 0x200)
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
struct.pack_into('<H', opt, 68, 3)  # CONSOLE
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

rdata_size = 0x200
text_hdr  = section_hdr(b'.text\x00\x00\x00', text_size, TEXT_RVA, text_size, 0x200, 0x60000020)
rdata_hdr = section_hdr(b'.rdata\x00\x00', rdata_size, RDATA_RVA, rdata_size, 0x200+text_size, 0x40000040)
bss_hdr   = section_hdr(b'.bss\x00\x00\x00\x00', 0x1000, 0x3000, 0, 0, 0xC0000080)

headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + text_hdr + rdata_hdr + bss_hdr
headers = headers.ljust(0x200, b'\x00')

exe = headers + text_section + bytes(rdata[:rdata_size])

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mandelbrot.exe")
with open(out_path, 'wb') as f:
    f.write(exe)

print(f"Generated {out_path} ({len(exe)} bytes)")
print(f"Fixed-point constants: DX={DX}, DY={DY}")
print(f"View: x=[{-2.5}, {1.0}], y=[{-1.2}, {1.2}]")
print(f"Resolution: {WIDTH}x{HEIGHT}, Max iterations: {MAX_ITER}")
