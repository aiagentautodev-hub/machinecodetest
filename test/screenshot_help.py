"""Take a screenshot of machedit help screen using PIL."""
import ctypes, ctypes.wintypes, subprocess, time, os

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
exe = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'machedit', 'machedit.exe'))
out_png = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'screenshots', 'machedit_help.png'))

# Launch machedit
proc = subprocess.Popen([exe], creationflags=0x00000010)
print(f"PID={proc.pid}")
time.sleep(3)

# Attach and send Ctrl+H
kernel32.FreeConsole()
kernel32.AttachConsole(proc.pid)
hin = kernel32.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)

class KE(ctypes.Structure):
    _fields_ = [("bKD", ctypes.wintypes.BOOL), ("wRC", ctypes.wintypes.WORD),
                 ("wVK", ctypes.wintypes.WORD), ("wVSC", ctypes.wintypes.WORD),
                 ("UC", ctypes.wintypes.WCHAR), ("dwCKS", ctypes.wintypes.DWORD)]
class IR(ctypes.Structure):
    _fields_ = [("ET", ctypes.wintypes.WORD), ("_p", ctypes.wintypes.WORD), ("KE", KE)]

def send_key(vk, char=0, ctrl=0):
    ir = IR()
    ir.ET = 1; ir.KE.bKD = 1; ir.KE.wRC = 1; ir.KE.wVK = vk
    ir.KE.UC = chr(char) if char else '\0'; ir.KE.dwCKS = ctrl
    w = ctypes.wintypes.DWORD()
    kernel32.WriteConsoleInputW(hin, ctypes.byref(ir), 1, ctypes.byref(w))
    time.sleep(0.05)
    ir.KE.bKD = 0
    kernel32.WriteConsoleInputW(hin, ctypes.byref(ir), 1, ctypes.byref(w))
    time.sleep(0.1)

send_key(0x48, 0x08, 0x0008)  # Ctrl+H
time.sleep(2)
kernel32.CloseHandle(hin)
kernel32.FreeConsole()

# Find the Windows Terminal window with "MachEdit" in title
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
found_hwnd = None

def enum_cb(hwnd, lparam):
    global found_hwnd
    if not user32.IsWindowVisible(hwnd):
        return True
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    title = buf.value
    if "MachEdit" in title:
        found_hwnd = hwnd
        return False
    return True

user32.EnumWindows(EnumWindowsProc(enum_cb), 0)
print(f"HWND={found_hwnd}")

if found_hwnd:
    # Bring window to front
    user32.ShowWindow(found_hwnd, 9)  # SW_RESTORE
    time.sleep(0.3)
    user32.SetForegroundWindow(found_hwnd)
    time.sleep(0.5)

    # Switch to the MachEdit tab using Ctrl+Tab or keyboard
    # On Windows Terminal, Ctrl+Shift+Tab switches tabs
    # But we need to switch to the FIRST tab (MachEdit)
    # Use Ctrl+Alt+1 to switch to first tab in Windows Terminal
    # Simulate keypress: VK_CONTROL + VK_ALT + '1'
    INPUT_KEYBOARD = 1
    KEYEVENTF_KEYUP = 0x0002

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", ctypes.wintypes.WORD), ("wScan", ctypes.wintypes.WORD),
                     ("dwFlags", ctypes.wintypes.DWORD), ("time", ctypes.wintypes.DWORD),
                     ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

    class INPUT(ctypes.Structure):
        class _INPUT(ctypes.Union):
            _fields_ = [("ki", KEYBDINPUT)]
        _fields_ = [("type", ctypes.wintypes.DWORD), ("_input", _INPUT)]

    def press_key(vk, flags=0):
        inp = INPUT()
        inp.type = INPUT_KEYBOARD
        inp._input.ki.wVk = vk
        inp._input.ki.dwFlags = flags
        user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(inp))

    # Ctrl+Alt+1 to switch to tab 1
    press_key(0x11)  # VK_CONTROL down
    press_key(0x12)  # VK_MENU (Alt) down
    press_key(0x31)  # '1' down
    time.sleep(0.05)
    press_key(0x31, KEYEVENTF_KEYUP)
    press_key(0x12, KEYEVENTF_KEYUP)
    press_key(0x11, KEYEVENTF_KEYUP)
    time.sleep(1)

    # Get window rect
    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                     ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
    rect = RECT()
    user32.GetWindowRect(found_hwnd, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top
    print(f"Size: {w}x{h} at ({rect.left},{rect.top})")

    # Use PIL to capture
    from PIL import ImageGrab
    img = ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom))
    img.save(out_png)
    print(f"Saved: {out_png}")

proc.kill()
print("Done")
