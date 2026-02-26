# MachineCodeTest

Low-level machine code and x86 assembly experiments on Windows.

## Tools
- **NASM**: `C:/Users/User/AppData/Local/bin/NASM/nasm.exe`
- **GoLink**: `C:/Users/User/AppData/Local/bin/GoLink/GoLink.exe`
- Target: Win32 PE executables

## Memory Rules

- Update memory after significant code changes, bug fixes, or architectural decisions
- Record patterns, conventions, and debugging insights discovered during work
- Do not track session-specific info (current task details, temporary state)
- Memory files are stored in the auto-memory directory and persist across sessions
