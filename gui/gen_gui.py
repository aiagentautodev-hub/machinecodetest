#!/usr/bin/env python3
"""Generate a Win32 GUI window application from raw machine code.
   Imports from kernel32.dll + user32.dll.
   Features: WndProc callback, message loop, RegisterClass, CreateWindowEx."""

import struct, os

IMAGE_BASE = 0x00400000
TEXT_RVA   = 0x1000
RDATA_RVA  = 0x2000

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

    # jmp [iat_addr] - indirect jump for tail calls
    def jmp_iat(self, addr):
        self.emit(b'\xFF\x25')
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
# .rdata: imports from kernel32 + user32, plus string data
# ============================================================
def hint_name(hint, name):
    b = struct.pack('<H', hint) + name.encode() + b'\x00'
    if len(b) % 2: b += b'\x00'
    return b

# Import functions
kernel32_funcs = ["GetModuleHandleA", "ExitProcess"]
user32_funcs = [
    "RegisterClassA", "CreateWindowExA", "ShowWindow",
    "GetMessageA", "TranslateMessage", "DispatchMessageA",
    "DefWindowProcA", "PostQuitMessage", "LoadCursorA",
]

k32_hns = [hint_name(0, f) for f in kernel32_funcs]
u32_hns = [hint_name(0, f) for f in user32_funcs]

kernel32_name = b"kernel32.dll\x00"
user32_name   = b"user32.dll\x00"
class_name    = b"McWnd\x00"
window_title  = b"Machine Code Window\x00"

# Layout .rdata (0x400 bytes to be safe)
rdata = bytearray(0x400)

# IDT: 3 entries (kernel32, user32, null) = 60 bytes at 0x00
IDT_OFF = 0x00

# ILTs: after IDT
K32_ILT_OFF = 0x3C
K32_ILT_SIZE = (len(kernel32_funcs) + 1) * 4  # 12 bytes
U32_ILT_OFF = K32_ILT_OFF + K32_ILT_SIZE
U32_ILT_SIZE = (len(user32_funcs) + 1) * 4    # 40 bytes

# IATs: after ILTs
K32_IAT_OFF = U32_ILT_OFF + U32_ILT_SIZE
K32_IAT_SIZE = K32_ILT_SIZE
U32_IAT_OFF = K32_IAT_OFF + K32_IAT_SIZE
U32_IAT_SIZE = U32_ILT_SIZE

# DLL names: after IATs
NAMES_OFF = U32_IAT_OFF + U32_IAT_SIZE
# Round up to 4-byte boundary
NAMES_OFF = (NAMES_OFF + 3) & ~3

# Place kernel32 name
k32_name_off = NAMES_OFF
rdata[k32_name_off:k32_name_off+len(kernel32_name)] = kernel32_name

# Place user32 name
u32_name_off = k32_name_off + len(kernel32_name)
if u32_name_off % 2: u32_name_off += 1
rdata[u32_name_off:u32_name_off+len(user32_name)] = user32_name

# Hint/Name entries
hn_off = (u32_name_off + len(user32_name) + 3) & ~3

k32_hn_rvas = []
for hn in k32_hns:
    k32_hn_rvas.append(RDATA_RVA + hn_off)
    rdata[hn_off:hn_off+len(hn)] = hn
    hn_off += len(hn)

u32_hn_rvas = []
for hn in u32_hns:
    u32_hn_rvas.append(RDATA_RVA + hn_off)
    rdata[hn_off:hn_off+len(hn)] = hn
    hn_off += len(hn)

# String data
str_off = (hn_off + 3) & ~3
classname_rva = RDATA_RVA + str_off
rdata[str_off:str_off+len(class_name)] = class_name
str_off += len(class_name)

title_rva = RDATA_RVA + str_off
rdata[str_off:str_off+len(window_title)] = window_title
str_off += len(window_title)

print(f"rdata used: {hex(str_off)} / 0x400")

# Build ILTs
for i, rva in enumerate(k32_hn_rvas):
    struct.pack_into('<I', rdata, K32_ILT_OFF + i*4, rva)
struct.pack_into('<I', rdata, K32_ILT_OFF + len(k32_hn_rvas)*4, 0)

for i, rva in enumerate(u32_hn_rvas):
    struct.pack_into('<I', rdata, U32_ILT_OFF + i*4, rva)
struct.pack_into('<I', rdata, U32_ILT_OFF + len(u32_hn_rvas)*4, 0)

# Build IATs (same as ILTs)
for i, rva in enumerate(k32_hn_rvas):
    struct.pack_into('<I', rdata, K32_IAT_OFF + i*4, rva)
struct.pack_into('<I', rdata, K32_IAT_OFF + len(k32_hn_rvas)*4, 0)

for i, rva in enumerate(u32_hn_rvas):
    struct.pack_into('<I', rdata, U32_IAT_OFF + i*4, rva)
struct.pack_into('<I', rdata, U32_IAT_OFF + len(u32_hn_rvas)*4, 0)

# Build IDT
# kernel32 entry
struct.pack_into('<IIIII', rdata, IDT_OFF,
    RDATA_RVA + K32_ILT_OFF, 0, 0, RDATA_RVA + k32_name_off, RDATA_RVA + K32_IAT_OFF)
# user32 entry
struct.pack_into('<IIIII', rdata, IDT_OFF + 20,
    RDATA_RVA + U32_ILT_OFF, 0, 0, RDATA_RVA + u32_name_off, RDATA_RVA + U32_IAT_OFF)
# null terminator
rdata[IDT_OFF+40:IDT_OFF+60] = b'\x00' * 20

# Compute IAT absolute addresses for use in code
def iat_addr(dll_iat_off, idx):
    return IMAGE_BASE + RDATA_RVA + dll_iat_off + idx * 4

IAT = {}
for i, name in enumerate(kernel32_funcs):
    IAT[name] = iat_addr(K32_IAT_OFF, i)
for i, name in enumerate(user32_funcs):
    IAT[name] = iat_addr(U32_IAT_OFF, i)

print("IAT addresses:")
for name, addr in IAT.items():
    print(f"  {name}: {hex(addr)}")

# ============================================================
# .text: Win32 GUI in raw x86
# ============================================================
WNDPROC_ABS = IMAGE_BASE + TEXT_RVA  # WndProc is at start of .text

a = Asm()

# ---- Jump to main (skip over WndProc) ----
a.jmp32('main')

# ============================================================
# WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
# stdcall callback - we must ret 16
# ============================================================
a.label('wndproc')
# [esp+4]=hwnd [esp+8]=msg [esp+12]=wParam [esp+16]=lParam
a.emit(b'\x83\x7C\x24\x08\x02')      # cmp dword [esp+8], 2  (WM_DESTROY)
a.jcc(0x74, 'on_destroy')             # je on_destroy

# WM_PAINT: check for msg == 0x000F
a.emit(b'\x83\x7C\x24\x08\x0F')      # cmp dword [esp+8], 0x0F (WM_PAINT)
a.jcc(0x74, 'on_paint')               # je on_paint

# Default: tail-call DefWindowProcA (same stack layout)
a.jmp_iat(IAT['DefWindowProcA'])

a.label('on_destroy')
a.emit(b'\x6A\x00')                   # push 0
a.call_iat(IAT['PostQuitMessage'])
a.emit(b'\x31\xC0')                   # xor eax, eax
a.emit(b'\xC2\x10\x00')              # ret 16

# WM_PAINT handler - just pass to DefWindowProc for now
a.label('on_paint')
a.jmp_iat(IAT['DefWindowProcA'])

# ============================================================
# main: register class, create window, message loop
# ============================================================
a.label('main')

a.emit(b'\x55')                        # push ebp
a.emit(b'\x89\xE5')                    # mov ebp, esp
a.emit(b'\x83\xEC\x40')               # sub esp, 64 (locals + MSG)

# Save callee-saved
a.emit(b'\x53')                        # push ebx
a.emit(b'\x56')                        # push esi
a.emit(b'\x57')                        # push edi

# GetModuleHandleA(NULL)
a.emit(b'\x6A\x00')                   # push 0
a.call_iat(IAT['GetModuleHandleA'])
a.emit(b'\x89\xC3')                   # mov ebx, eax  (hInstance)

# LoadCursorA(NULL, IDC_ARROW = 32512)
a.emit(b'\x68\x00\x7F\x00\x00')      # push 32512
a.emit(b'\x6A\x00')                   # push 0
a.call_iat(IAT['LoadCursorA'])
a.emit(b'\x89\xC6')                   # mov esi, eax  (hCursor)

# Build WNDCLASS on stack (40 bytes) - push in reverse field order
a.emit(b'\x68')                        # push classname_addr
a.emit_u32(IMAGE_BASE + classname_rva)
a.emit(b'\x6A\x00')                   # push 0          (lpszMenuName)
a.emit(b'\x6A\x06')                   # push 6          (hbrBackground = COLOR_WINDOW+1)
a.emit(b'\x56')                        # push esi        (hCursor)
a.emit(b'\x6A\x00')                   # push 0          (hIcon)
a.emit(b'\x53')                        # push ebx        (hInstance)
a.emit(b'\x6A\x00')                   # push 0          (cbWndExtra)
a.emit(b'\x6A\x00')                   # push 0          (cbClsExtra)
a.emit(b'\x68')                        # push WndProc_addr
a.emit_u32(WNDPROC_ABS + 5)           # +5 to skip the initial jmp32 instruction
a.emit(b'\x6A\x03')                   # push 3          (style = CS_HREDRAW|CS_VREDRAW)

# RegisterClassA(&wndclass)  - esp points to WNDCLASS
a.emit(b'\x54')                        # push esp
a.call_iat(IAT['RegisterClassA'])
a.emit(b'\x83\xC4\x28')              # add esp, 40     (clean up WNDCLASS)

# CreateWindowExA(0, class, title, WS_OVERLAPPEDWINDOW,
#   CW_USEDEFAULT, CW_USEDEFAULT, 640, 480, 0, 0, hInst, 0)
CW_USEDEFAULT = 0x80000000
WS_OVERLAPPEDWINDOW = 0x00CF0000

a.emit(b'\x6A\x00')                   # push 0          (lpParam)
a.emit(b'\x53')                        # push ebx        (hInstance)
a.emit(b'\x6A\x00')                   # push 0          (hMenu)
a.emit(b'\x6A\x00')                   # push 0          (hWndParent)
a.emit(b'\x68\xE0\x01\x00\x00')      # push 480        (nHeight)
a.emit(b'\x68\x80\x02\x00\x00')      # push 640        (nWidth)
a.emit(b'\x68')                        # push CW_USEDEFAULT (y)
a.emit_u32(CW_USEDEFAULT)
a.emit(b'\x68')                        # push CW_USEDEFAULT (x)
a.emit_u32(CW_USEDEFAULT)
a.emit(b'\x68')                        # push WS_OVERLAPPEDWINDOW
a.emit_u32(WS_OVERLAPPEDWINDOW)
a.emit(b'\x68')                        # push title_addr
a.emit_u32(IMAGE_BASE + title_rva)
a.emit(b'\x68')                        # push classname_addr
a.emit_u32(IMAGE_BASE + classname_rva)
a.emit(b'\x6A\x00')                   # push 0          (dwExStyle)
a.call_iat(IAT['CreateWindowExA'])
# eax = hwnd
a.emit(b'\x89\xC7')                   # mov edi, eax    (save hwnd)

# ShowWindow(hwnd, SW_SHOW = 5)
a.emit(b'\x6A\x05')                   # push 5
a.emit(b'\x57')                        # push edi
a.call_iat(IAT['ShowWindow'])

# ---- Message loop ----
# MSG struct on stack: use [ebp-28-some] area
# We'll use ebp-40 as MSG base (28 bytes)

a.label('msg_loop')
# GetMessageA(&msg, 0, 0, 0)
a.emit(b'\x6A\x00')                   # push 0 (wMsgFilterMax)
a.emit(b'\x6A\x00')                   # push 0 (wMsgFilterMin)
a.emit(b'\x6A\x00')                   # push 0 (hWnd)
a.emit(b'\x8D\x45\xD8')              # lea eax, [ebp-40]  (MSG struct)
a.emit(b'\x50')                        # push eax
a.call_iat(IAT['GetMessageA'])

# if eax == 0, quit
a.emit(b'\x85\xC0')                   # test eax, eax
a.jcc(0x74, 'quit')                   # jz quit

# TranslateMessage(&msg)
a.emit(b'\x8D\x45\xD8')              # lea eax, [ebp-40]
a.emit(b'\x50')                        # push eax
a.call_iat(IAT['TranslateMessage'])

# DispatchMessageA(&msg)
a.emit(b'\x8D\x45\xD8')              # lea eax, [ebp-40]
a.emit(b'\x50')                        # push eax
a.call_iat(IAT['DispatchMessageA'])

a.jmp('msg_loop')

# ---- quit ----
a.label('quit')
a.emit(b'\x6A\x00')                   # push 0
a.call_iat(IAT['ExitProcess'])

code_bytes = a.bytes()
print(f"\nMachine code: {len(code_bytes)} bytes")

# Pad .text to 0x400
text_section = code_bytes.ljust(0x400, b'\x00')

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
struct.pack_into('<I', opt, 4, 0x400)          # SizeOfCode
struct.pack_into('<I', opt, 8, 0x400)          # SizeOfInitializedData
struct.pack_into('<I', opt, 16, TEXT_RVA)      # EntryPoint
struct.pack_into('<I', opt, 20, TEXT_RVA)      # BaseOfCode
struct.pack_into('<I', opt, 24, RDATA_RVA)     # BaseOfData
struct.pack_into('<I', opt, 28, IMAGE_BASE)
struct.pack_into('<I', opt, 32, 0x1000)        # SectionAlignment
struct.pack_into('<I', opt, 36, 0x200)         # FileAlignment
struct.pack_into('<H', opt, 40, 4)             # MajorOSVersion
struct.pack_into('<H', opt, 48, 4)             # MajorSubsystemVersion
struct.pack_into('<I', opt, 56, 0x4000)        # SizeOfImage (needs room)
struct.pack_into('<I', opt, 60, 0x200)         # SizeOfHeaders
struct.pack_into('<H', opt, 68, 2)             # Subsystem: GUI (2)
struct.pack_into('<I', opt, 72, 0x100000)
struct.pack_into('<I', opt, 76, 0x1000)
struct.pack_into('<I', opt, 80, 0x100000)
struct.pack_into('<I', opt, 84, 0x1000)
struct.pack_into('<I', opt, 92, 16)

# Total IAT spans both kernel32 and user32 IATs
total_iat_off = K32_IAT_OFF
total_iat_size = (U32_IAT_OFF + U32_IAT_SIZE) - K32_IAT_OFF

struct.pack_into('<II', opt, 96 + 8, RDATA_RVA, 60)                        # Import Dir
struct.pack_into('<II', opt, 96 + 96, RDATA_RVA + total_iat_off, total_iat_size)  # IAT

def section_hdr(name, vsize, rva, rawsize, rawptr, chars):
    h = bytearray(40)
    h[0:len(name)] = name
    struct.pack_into('<I', h, 8, vsize)
    struct.pack_into('<I', h, 12, rva)
    struct.pack_into('<I', h, 16, rawsize)
    struct.pack_into('<I', h, 20, rawptr)
    struct.pack_into('<I', h, 36, chars)
    return bytes(h)

text_hdr  = section_hdr(b'.text\x00\x00\x00', 0x400, TEXT_RVA, 0x400, 0x200, 0x60000020)
rdata_hdr = section_hdr(b'.rdata\x00\x00', 0x400, RDATA_RVA, 0x400, 0x600, 0x40000040)

headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + text_hdr + rdata_hdr
headers = headers.ljust(0x200, b'\x00')

exe = headers + text_section + bytes(rdata)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui.exe")
with open(out_path, 'wb') as f:
    f.write(exe)

print(f"Generated {out_path} ({len(exe)} bytes)")
print(f"\nDisassembly-like view:")
for i in range(0, len(code_bytes), 16):
    chunk = code_bytes[i:i+16]
    hexstr = ' '.join(f'{b:02X}' for b in chunk)
    print(f"  {i:04X}: {hexstr}")
