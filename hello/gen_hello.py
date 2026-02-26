#!/usr/bin/env python3
"""Generate a minimal Windows PE executable from raw machine code.
   Prints "Hello" to stdout using WriteFile, no assembler needed."""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000

# --- Strings ---
hello_str = b"Hello\r\n"
kernel32_str = b"kernel32.dll\x00"

# --- Hint/Name entries ---
def hint_name(hint, name):
    b = struct.pack('<H', hint) + name.encode() + b'\x00'
    if len(b) % 2: b += b'\x00'
    return b

hn_GetStdHandle = hint_name(0, "GetStdHandle")
hn_WriteFile    = hint_name(0, "WriteFile")
hn_ExitProcess  = hint_name(0, "ExitProcess")

# --- .rdata layout (RVA 0x2000) ---
# 0x00: IDT (40 bytes: 1 entry + null)
# 0x50: ILT (16 bytes: 3 entries + null)
# 0x60: IAT (16 bytes: 3 entries + null)
# 0x70: kernel32 name
# 0x80: hint/name entries
# 0xC0: hello string

rdata = bytearray(0x200)

# Hint/Name entries
hn_pos = 0x80
hn_rvas = []
for hn in [hn_GetStdHandle, hn_WriteFile, hn_ExitProcess]:
    hn_rvas.append(RDATA_RVA + hn_pos)
    rdata[hn_pos:hn_pos+len(hn)] = hn
    hn_pos += len(hn)

# Hello string
hello_rva = RDATA_RVA + 0xC0
rdata[0xC0:0xC0+len(hello_str)] = hello_str

# kernel32.dll name
rdata[0x70:0x70+len(kernel32_str)] = kernel32_str

# ILT
ilt_off = 0x50
ilt = struct.pack('<IIII', hn_rvas[0], hn_rvas[1], hn_rvas[2], 0)
rdata[ilt_off:ilt_off+len(ilt)] = ilt

# IAT (same as ILT, loader overwrites at load time)
iat_off = 0x60
rdata[iat_off:iat_off+len(ilt)] = ilt

# IDT
idt = struct.pack('<IIIII',
    RDATA_RVA + ilt_off, 0, 0, RDATA_RVA + 0x70, RDATA_RVA + iat_off)
idt += b'\x00' * 20
rdata[0:len(idt)] = idt

# IAT addresses for code
IAT_GetStdHandle = IMAGE_BASE + RDATA_RVA + iat_off
IAT_WriteFile    = IMAGE_BASE + RDATA_RVA + iat_off + 4
IAT_ExitProcess  = IMAGE_BASE + RDATA_RVA + iat_off + 8

# --- .text: machine code (RVA 0x1000) ---
code = bytearray()

def emit(b):
    code.extend(b)

# sub esp, 16          ; local space
emit(b'\x83\xEC\x10')

# push -11             ; STD_OUTPUT_HANDLE
emit(b'\x6A\xF5')

# call [GetStdHandle]
emit(b'\xFF\x15')
emit(struct.pack('<I', IAT_GetStdHandle))

# eax = handle. Now call WriteFile(handle, buf, len, &written, NULL)
# push 0               ; lpOverlapped = NULL
emit(b'\x6A\x00')

# lea ecx, [esp+4]     ; &written (on stack)
emit(b'\x8D\x4C\x24\x04')

# push ecx             ; lpNumberOfBytesWritten
emit(b'\x51')

# push 7               ; nNumberOfBytesToWrite
emit(b'\x6A\x07')

# push hello_addr      ; lpBuffer
emit(b'\x68')
emit(struct.pack('<I', IMAGE_BASE + hello_rva))

# push eax             ; hFile
emit(b'\x50')

# call [WriteFile]
emit(b'\xFF\x15')
emit(struct.pack('<I', IAT_WriteFile))

# push 0               ; uExitCode
emit(b'\x6A\x00')

# call [ExitProcess]
emit(b'\xFF\x15')
emit(struct.pack('<I', IAT_ExitProcess))

text_section = bytes(code).ljust(0x200, b'\x00')

# --- PE Headers ---
dos_header = bytearray(0x80)
dos_header[0:2] = b'MZ'
struct.pack_into('<I', dos_header, 0x3C, 0x80)

pe_sig = b'PE\x00\x00'

coff = struct.pack('<HHIIIHH',
    0x014C, 2, 0, 0, 0, 0xE0, 0x0103)

opt = bytearray(0xE0)
struct.pack_into('<H', opt, 0, 0x10B)        # Magic: PE32
struct.pack_into('<B', opt, 2, 6)             # MajorLinkerVersion
struct.pack_into('<I', opt, 4, 0x200)         # SizeOfCode
struct.pack_into('<I', opt, 8, 0x200)         # SizeOfInitializedData
struct.pack_into('<I', opt, 16, TEXT_RVA)     # AddressOfEntryPoint
struct.pack_into('<I', opt, 20, TEXT_RVA)     # BaseOfCode
struct.pack_into('<I', opt, 24, RDATA_RVA)    # BaseOfData
struct.pack_into('<I', opt, 28, IMAGE_BASE)   # ImageBase
struct.pack_into('<I', opt, 32, 0x1000)       # SectionAlignment
struct.pack_into('<I', opt, 36, 0x200)        # FileAlignment
struct.pack_into('<H', opt, 40, 4)            # MajorOSVersion
struct.pack_into('<H', opt, 48, 4)            # MajorSubsystemVersion
struct.pack_into('<I', opt, 56, 0x3000)       # SizeOfImage
struct.pack_into('<I', opt, 60, 0x200)        # SizeOfHeaders
struct.pack_into('<H', opt, 68, 3)            # Subsystem: CONSOLE
struct.pack_into('<I', opt, 72, 0x100000)     # SizeOfStackReserve
struct.pack_into('<I', opt, 76, 0x1000)       # SizeOfStackCommit
struct.pack_into('<I', opt, 80, 0x100000)     # SizeOfHeapReserve
struct.pack_into('<I', opt, 84, 0x1000)       # SizeOfHeapCommit
struct.pack_into('<I', opt, 92, 16)           # NumberOfRvaAndSizes
# Data directories
struct.pack_into('<II', opt, 96 + 8, RDATA_RVA, 40)         # Import
struct.pack_into('<II', opt, 96 + 96, RDATA_RVA + iat_off, 16)  # IAT

# Section headers
def section_hdr(name, vsize, rva, rawsize, rawptr, chars):
    h = bytearray(40)
    h[0:len(name)] = name
    struct.pack_into('<I', h, 8, vsize)
    struct.pack_into('<I', h, 12, rva)
    struct.pack_into('<I', h, 16, rawsize)
    struct.pack_into('<I', h, 20, rawptr)
    struct.pack_into('<I', h, 36, chars)
    return bytes(h)

text_hdr  = section_hdr(b'.text\x00\x00\x00',  0x200, TEXT_RVA,  0x200, 0x200, 0x60000020)
rdata_hdr = section_hdr(b'.rdata\x00\x00', 0x200, RDATA_RVA, 0x200, 0x400, 0x40000040)

headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + text_hdr + rdata_hdr
headers = headers.ljust(0x200, b'\x00')

exe = headers + text_section + bytes(rdata)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hello.exe")
with open(out_path, 'wb') as f:
    f.write(exe)

print(f"Generated {out_path} ({len(exe)} bytes)")
print(f"Machine code ({len(code)} bytes):")
print(' '.join(f'{b:02X}' for b in code))
