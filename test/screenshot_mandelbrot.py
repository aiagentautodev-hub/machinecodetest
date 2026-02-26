"""Take a screenshot of mandelbrot.exe output."""
import ctypes, ctypes.wintypes, subprocess, time, os
from PIL import ImageGrab

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
exe = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mandelbrot', 'mandelbrot.exe'))
out_png = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'screenshots', 'mandelbrot.png'))

# Set a unique title via cmd /c title
title_marker = "MANDELBROT_SCREENSHOT_9823"
proc = subprocess.Popen(
    ['cmd.exe', '/c', f'title {title_marker} && {exe} && pause'],
    creationflags=0x00000010
)
print(f"PID={proc.pid}")
time.sleep(5)

# Find window by unique title
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
found_hwnd = None

def enum_cb(hwnd, lparam):
    global found_hwnd
    if not user32.IsWindowVisible(hwnd):
        return True
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    if title_marker in buf.value:
        found_hwnd = hwnd
        return False
    return True

user32.EnumWindows(EnumWindowsProc(enum_cb), 0)
print(f"HWND={found_hwnd}")

if found_hwnd:
    user32.ShowWindow(found_hwnd, 9)
    time.sleep(0.3)
    user32.SetForegroundWindow(found_hwnd)
    time.sleep(0.5)

    # Switch to first tab (Ctrl+Alt+1)
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

    press_key(0x11); press_key(0x12); press_key(0x31)
    time.sleep(0.05)
    press_key(0x31, KEYEVENTF_KEYUP); press_key(0x12, KEYEVENTF_KEYUP); press_key(0x11, KEYEVENTF_KEYUP)
    time.sleep(1)

    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                     ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
    rect = RECT()
    user32.GetWindowRect(found_hwnd, ctypes.byref(rect))
    print(f"Size: {rect.right-rect.left}x{rect.bottom-rect.top}")

    img = ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom))
    img.save(out_png)
    print(f"Saved: {out_png}")
else:
    # Debug: list all window titles
    titles = []
    def list_cb(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buf, 512)
        if buf.value:
            titles.append(buf.value)
        return True
    user32.EnumWindows(EnumWindowsProc(list_cb), 0)
    print("All titles:")
    for t in titles[:20]:
        print(f"  {t}")

proc.kill()
print("Done")
