# MachineCodeTest

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20x86-brightgreen.svg)]()

A progressive series of **Windows PE executables generated entirely from raw x86 machine code bytes** using Python. No compiler, no assembler, no linker — just Python scripts that emit bytes directly into valid PE32 executables.

## Programs

Each subdirectory contains a `gen_*.py` script that generates a working `.exe`:

| # | Program | Description | Size |
|---|---------|-------------|------|
| 1 | **[hello](hello/)** | Hello World — console output via `WriteConsoleA` | ~2 KB |
| 2 | **[triangle](triangle/)** | Pascal's Triangle — loops, arithmetic, formatted output | ~2 KB |
| 3 | **[fib_triangle](fib_triangle/)** | Fibonacci Triangle — nested loops, number formatting | ~2 KB |
| 4 | **[gui](gui/)** | GUI Window — Win32 `CreateWindowEx`, message loop, `WndProc` | ~4 KB |
| 5 | **[snake](snake/)** | Snake Game — real-time console game with input handling | ~4 KB |
| 6 | **[mandelbrot](mandelbrot/)** | Mandelbrot Set — fixed-point math, ANSI color rendering | ~3 KB |
| 7 | **[machedit](machedit/)** | Text Editor — PE2-style console editor with file I/O | ~6 KB |

## How It Works

Each Python generator script:

1. Builds a **PE32 header** (DOS stub, COFF header, Optional header, Section table)
2. Constructs an **Import Directory Table** with kernel32.dll (and user32.dll for GUI) function imports
3. Emits raw **x86 machine code** bytes using an `Asm` helper class that supports labels, forward references, and fixups
4. Writes out a valid Windows executable — no external tools required

```
gen_*.py  →  Asm class (labels, emit, fixups)  →  PE sections (.text, .rdata, .bss)  →  .exe
```

## Quick Start

```bash
# Generate and run any program
cd hello
python gen_hello.py
./hello.exe

# Generate the text editor
cd machedit
python gen_machedit.py
./machedit.exe              # empty editor
./machedit.exe file.txt     # edit a file
```

**Requirements**: Python 3.6+ and Windows (executables are Win32 PE32)

## MachEdit — The Text Editor

The crown jewel: a fully functional PE2-style console text editor generated from ~3400 bytes of hand-crafted x86 machine code.

**Features:**
- Arrow key navigation, Home/End, PgUp/PgDn
- Character insertion, Backspace, Delete
- Enter (line splitting), line joining
- Vertical scrolling
- File loading from command line
- Save (Ctrl+S)
- Help screen (Ctrl+H)
- Status bar with line/column, modified indicator
- Blue PE2 color scheme
- IME-aware (works on CJK Windows)

## Reference

The `reference/` directory contains `pe2.asm` — an x86 NASM assembly version of the text editor, which served as architectural reference for the machine code implementation.

## Screenshots

![Snake Game](screenshots/snake_screenshot.png)

## License

[MIT](LICENSE)
