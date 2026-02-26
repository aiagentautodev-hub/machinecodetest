"""Test machedit.exe - full test with F1 help and typing."""
import ctypes, ctypes.wintypes, subprocess, time, os

kernel32 = ctypes.windll.kernel32
exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'machedit', 'machedit.exe')

proc = subprocess.Popen([exe], creationflags=0x00000010)  # CREATE_NEW_CONSOLE
time.sleep(4)  # Wait for editor to init (includes 200ms sleep in editor)

kernel32.FreeConsole()
kernel32.AttachConsole(proc.pid)

GENERIC_RW = 0xC0000000
hout = kernel32.CreateFileW("CONOUT$", GENERIC_RW, 3, None, 3, 0, None)
hin = kernel32.CreateFileW("CONIN$", GENERIC_RW, 3, None, 3, 0, None)

class CSBI(ctypes.Structure):
    _fields_ = [
        ("dwSize_X", ctypes.wintypes.SHORT), ("dwSize_Y", ctypes.wintypes.SHORT),
        ("dwCursorPosition_X", ctypes.wintypes.SHORT), ("dwCursorPosition_Y", ctypes.wintypes.SHORT),
        ("wAttributes", ctypes.wintypes.WORD),
        ("srWindow_Left", ctypes.wintypes.SHORT), ("srWindow_Top", ctypes.wintypes.SHORT),
        ("srWindow_Right", ctypes.wintypes.SHORT), ("srWindow_Bottom", ctypes.wintypes.SHORT),
        ("dwMaxWinSize_X", ctypes.wintypes.SHORT), ("dwMaxWinSize_Y", ctypes.wintypes.SHORT),
    ]

csbi = CSBI()
kernel32.GetConsoleScreenBufferInfo(hout, ctypes.byref(csbi))
cols = csbi.dwSize_X if csbi.dwSize_X > 0 else 120
rows = csbi.srWindow_Bottom - csbi.srWindow_Top + 1
if rows <= 0: rows = 30

def read_screen(label):
    buf = (ctypes.c_char * (cols + 10))()
    nread = ctypes.c_ulong()
    lines = []
    for row in range(rows):
        kernel32.ReadConsoleOutputCharacterA(hout, buf, cols, row << 16, ctypes.byref(nread))
        line = bytes(buf[:nread.value]).decode('ascii', errors='replace').rstrip()
        lines.append(f"Row {row:2d}: |{line}|")
    return f"\n=== {label} ===\n" + "\n".join(lines) + "\n"

def send_key(vk, char=0, ctrl=0):
    class KE(ctypes.Structure):
        _fields_ = [("bKD", ctypes.wintypes.BOOL), ("wRC", ctypes.wintypes.WORD),
                     ("wVK", ctypes.wintypes.WORD), ("wVSC", ctypes.wintypes.WORD),
                     ("UC", ctypes.wintypes.WCHAR), ("dwCKS", ctypes.wintypes.DWORD)]
    class IR(ctypes.Structure):
        _fields_ = [("ET", ctypes.wintypes.WORD), ("_p", ctypes.wintypes.WORD), ("KE", KE)]
    ir = IR(); ir.ET = 1; ir.KE.bKD = 1; ir.KE.wRC = 1; ir.KE.wVK = vk
    ir.KE.UC = chr(char) if char else '\0'; ir.KE.dwCKS = ctrl
    w = ctypes.wintypes.DWORD()
    kernel32.WriteConsoleInputW(hin, ctypes.byref(ir), 1, ctypes.byref(w))
    time.sleep(0.05)
    ir.KE.bKD = 0
    kernel32.WriteConsoleInputW(hin, ctypes.byref(ir), 1, ctypes.byref(w))
    time.sleep(0.1)

out = f"Buffer: {cols}x{rows}\nCursor: {csbi.dwCursorPosition_X},{csbi.dwCursorPosition_Y}\n"
out += read_screen("INITIAL")

# Type some text
for ch in "Hello":
    send_key(ord(ch), ord(ch))
time.sleep(0.3)
out += read_screen("AFTER TYPING 'Hello'")

# Press F1
send_key(0x70)  # VK_F1
time.sleep(0.5)
out += read_screen("HELP SCREEN (F1)")

# Press Escape to dismiss help
send_key(0x1B, 0x1B)
time.sleep(0.3)
out += read_screen("AFTER DISMISSING HELP")

# Exit
send_key(0x1B, 0x1B)
time.sleep(0.3)

kernel32.CloseHandle(hout)
kernel32.CloseHandle(hin)
kernel32.FreeConsole()

with open('console_debug.txt', 'w', encoding='utf-8') as f:
    f.write(out)

try:
    proc.wait(timeout=2)
except:
    proc.kill()
