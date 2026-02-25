; ============================================================================
; PE2 Editor - PE2-style text editor in x86 Assembly (Win32 Console)
; Assembler: NASM  |  Linker: GoLink  |  Target: Win32 Console PE
; ============================================================================

bits 32

; --- Win32 API imports ---
extern _GetStdHandle@4
extern _SetConsoleTitleA@4
extern _SetConsoleMode@8
extern _GetConsoleScreenBufferInfo@8
extern _SetConsoleCursorPosition@8
extern _ReadConsoleInputA@16
extern _WriteConsoleOutputCharacterA@20
extern _WriteConsoleOutputAttribute@20
extern _FillConsoleOutputCharacterA@20
extern _FillConsoleOutputAttribute@20
extern _CreateFileA@28
extern _ReadFile@20
extern _WriteFile@20
extern _CloseHandle@4
extern _GetFileSizeEx@8
extern _GetCommandLineA@0
extern _ExitProcess@4
extern _VirtualAlloc@16
extern _VirtualFree@12
extern _SetConsoleCursorInfo@8
extern _GetConsoleMode@8

; --- Constants ---
%define STD_INPUT_HANDLE  -10
%define STD_OUTPUT_HANDLE -11
%define GENERIC_READ      0x80000000
%define GENERIC_WRITE     0x40000000
%define OPEN_EXISTING     3
%define CREATE_ALWAYS     2
%define FILE_ATTRIBUTE_NORMAL 0x80
%define MEM_COMMIT        0x1000
%define MEM_RESERVE       0x2000
%define MEM_RELEASE       0x8000
%define PAGE_READWRITE    0x04
%define ENABLE_WINDOW_INPUT    0x0008
%define ENABLE_MOUSE_INPUT     0x0010
%define ENABLE_PROCESSED_INPUT 0x0001
%define ENABLE_EXTENDED_FLAGS  0x0080
%define ENABLE_QUICK_EDIT_MODE 0x0040
%define KEY_EVENT         0x0001
%define VK_LEFT   0x25
%define VK_UP     0x26
%define VK_RIGHT  0x27
%define VK_DOWN   0x28
%define VK_HOME   0x24
%define VK_END    0x23
%define VK_PRIOR  0x21
%define VK_NEXT   0x22
%define VK_DELETE 0x2E
%define VK_INSERT 0x2D
%define VK_RETURN 0x0D
%define VK_BACK   0x08
%define VK_ESCAPE 0x1B
%define VK_TAB    0x09
%define VK_F1     0x70
%define VK_F2     0x71
%define VK_F3     0x72
%define VK_F4     0x73
%define VK_F5     0x74
%define VK_F6     0x75
%define VK_F7     0x76
%define VK_F8     0x77
%define VK_F10    0x79

%define MAX_LINES  65536
%define MAX_LINE_LEN 256
%define LINE_BUF_SIZE 258       ; 2 bytes length + 256 data

; PE2 Color scheme
%define COLOR_TEXT      0x1F    ; White on Blue
%define COLOR_STATUS    0x30    ; Black on Cyan
%define COLOR_BLOCK     0x70    ; Black on White
%define COLOR_LINENUM   0x1E   ; Yellow on Blue

; ============================================================================
section .data
; ============================================================================

title_str      db "PE2 Editor", 0
untitled_str   db "[New File]", 0
save_ok_str    db " File saved. ", 0
save_fail_str  db " Save FAILED! ", 0
save_cancel_str db " Save cancelled. ", 0
saveas_prompt  db " Save as (Esc=cancel): ", 0
modified_str   db " Modified ", 0
no_mod_str     db "          ", 0
insert_str     db "INS", 0
overwr_str     db "OVR", 0
line_col_fmt   db "Ln:%-5d Col:%-3d", 0
confirm_exit   db " File modified. Save before exit? (Y/N/Esc) ", 0
search_prompt  db " Find: ", 0
replace_prompt db " Replace with: ", 0
goto_prompt    db " Go to line: ", 0
not_found_str  db " Not found. ", 0
replace_ask    db " Replace? (Y/N/A/Esc) ", 0
block_copy_str db " Block copied. ", 0
block_move_str db " Block moved. ", 0
block_del_str  db " Block deleted. ", 0
help_title     db " PE2 Editor - Help ", 0
newline_bytes  db 13, 10

; Help text lines
help_line0  db "  FILE : F2/Ctrl+S Save      EXIT : Alt+X (Esc cancel)   ", 0
help_line1  db "  NAV  : Arrows  Home  End  PgUp  PgDn                   ", 0
help_line2  db "  EDIT : Enter Split  Backspace/Delete  Ins=OVR toggle   ", 0
help_line3  db "  FIND : Ctrl+F Find  Ctrl+R Replace  Ctrl+G Goto line   ", 0
help_line4  db "  BLOCK: F3 Start  F4 End  F5 Copy  F6 Move  F8 Delete   ", 0
help_line5  db "  Press any key to close help                            ", 0
status_hint db "F1 Help  F2 Save  Ctrl+S  Ctrl+F/R/G  Alt+X Exit", 0

; ============================================================================
section .bss
; ============================================================================

h_stdin     resd 1
h_stdout    resd 1
cursor_x    resd 1              ; column (0-based)
cursor_y    resd 1              ; row in file (0-based)
top_line    resd 1              ; first visible line
num_lines   resd 1              ; total lines
modified    resd 1              ; dirty flag
insert_mode resd 1              ; 1=insert, 0=overwrite
screen_rows resd 1              ; console height
screen_cols resd 1              ; console width
filename    resb 260
line_ptrs   resd MAX_LINES      ; pointers to line buffers

; Block marking
block_start resd 1              ; start line (-1 = no block)
block_end   resd 1              ; end line (-1 = no block)

; Search buffer
search_buf  resb 128
replace_buf resb 128

; Temporary buffers
temp_buf    resb 512
attr_buf    resw 512            ; attribute buffer for one screen row
status_buf  resb 256
input_rec   resb 20             ; INPUT_RECORD
num_read    resd 1
num_written resd 1
status_input_col resd 1         ; input echo column on status row
stdin_mode  resd 1             ; original console input mode
csbi_buf    resb 22             ; CONSOLE_SCREEN_BUFFER_INFO
file_buf    resb 1              ; single byte read buffer
file_size   resq 1              ; 64-bit file size
cursor_info resb 8              ; CONSOLE_CURSOR_INFO

; line edit scratch
scratch_line resb LINE_BUF_SIZE

; message display timer
msg_timer   resd 1

; saved key state from ReadKey
last_vk     resd 1
last_char   resd 1
last_ctrl   resd 1

; ============================================================================
section .text
; ============================================================================

global Start

; ============================================================================
; Entry Point
; ============================================================================
Start:
    ; Get console handles
    push STD_INPUT_HANDLE
    call _GetStdHandle@4
    mov [h_stdin], eax

    push STD_OUTPUT_HANDLE
    call _GetStdHandle@4
    mov [h_stdout], eax

    ; Set console title
    push title_str
    call _SetConsoleTitleA@4

    ; Read current console input mode so we can preserve compatible flags
    push dword stdin_mode
    push dword [h_stdin]
    call _GetConsoleMode@8

    ; Keep existing mode bits, enable key/window events, and disable Quick Edit
    ; (console selection can freeze the editor loop and look like input is broken).
    mov eax, [stdin_mode]
    or eax, ENABLE_WINDOW_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_EXTENDED_FLAGS
    and eax, ~ENABLE_QUICK_EDIT_MODE
    push eax
    push dword [h_stdin]
    call _SetConsoleMode@8

    ; Get screen size
    call GetScreenSize

    ; Init editor state
    mov dword [cursor_x], 0
    mov dword [cursor_y], 0
    mov dword [top_line], 0
    mov dword [num_lines], 1
    mov dword [modified], 0
    mov dword [insert_mode], 1
    mov dword [block_start], -1
    mov dword [block_end], -1
    mov dword [msg_timer], 0

    ; Allocate first empty line
    call AllocLine
    mov [line_ptrs], eax
    mov word [eax], 0           ; length = 0

    ; Parse command line for filename
    call _GetCommandLineA@0
    ; eax points to command line string, skip past exe name
    mov esi, eax
    call SkipArg                ; skip program name
    call SkipSpaces
    cmp byte [esi], 0
    je .no_file

    ; Copy filename
    mov edi, filename
.copy_fn:
    lodsb
    cmp al, ' '
    je .fn_done
    cmp al, 0
    je .fn_done
    cmp al, '"'
    je .copy_fn                 ; skip quotes
    stosb
    jmp .copy_fn
.fn_done:
    mov byte [edi], 0

    ; Try to load file
    call LoadFile

.no_file:
    ; Set cursor visible
    mov dword [cursor_info], 25  ; dwSize = 25%
    mov dword [cursor_info+4], 1 ; bVisible = TRUE
    push cursor_info
    push dword [h_stdout]
    call _SetConsoleCursorInfo@8

    ; Main loop
    call DrawScreen
    call UpdateCursorPos

.main_loop:
    ; Decrement message timer
    cmp dword [msg_timer], 0
    je .read_input
    dec dword [msg_timer]
    cmp dword [msg_timer], 0
    jne .read_input
    ; Clear message - redraw status
    call DrawStatusBar

.read_input:
    call ReadKey
    ; Returns: eax=virtual key, ecx=char code, edx=control key state
    ; Save to memory (Win32 calls clobber eax/ecx/edx)
    mov [last_vk], eax
    mov [last_char], ecx
    mov [last_ctrl], edx
    test eax, eax
    jz .main_loop               ; no key event

    ; Check for Alt+X (exit)
    test edx, 0x0003            ; LEFT_ALT or RIGHT_ALT
    jnz .check_alt
    jmp .check_ctrl

.check_alt:
    mov eax, [last_vk]
    cmp eax, 'X'
    je .do_exit
    cmp eax, 'x'
    je .do_exit
    jmp .main_loop

.check_ctrl:
    mov edx, [last_ctrl]
    test edx, 0x000C            ; LEFT_CTRL or RIGHT_CTRL
    jnz .ctrl_key
    jmp .check_func

.ctrl_key:
    mov eax, [last_vk]
    cmp eax, 'S'
    je .do_save
    cmp eax, 'F'
    je .do_search
    cmp eax, 'R'
    je .do_replace
    cmp eax, 'G'
    je .do_goto
    jmp .main_loop

.check_func:
    mov eax, [last_vk]
    cmp eax, VK_F1
    je .do_help
    cmp eax, VK_F2
    je .do_save
    cmp eax, VK_F3
    je .do_block_start
    cmp eax, VK_F4
    je .do_block_end
    cmp eax, VK_F5
    je .do_block_copy
    cmp eax, VK_F6
    je .do_block_move
    cmp eax, VK_F8
    je .do_block_delete

    ; Navigation keys
    cmp eax, VK_LEFT
    je .do_left
    cmp eax, VK_RIGHT
    je .do_right
    cmp eax, VK_UP
    je .do_up
    cmp eax, VK_DOWN
    je .do_down
    cmp eax, VK_HOME
    je .do_home
    cmp eax, VK_END
    je .do_end
    cmp eax, VK_PRIOR
    je .do_pgup
    cmp eax, VK_NEXT
    je .do_pgdn

    ; Editing keys
    cmp eax, VK_RETURN
    je .do_enter
    cmp eax, VK_BACK
    je .do_backspace
    cmp eax, VK_DELETE
    je .do_delete
    cmp eax, VK_INSERT
    je .do_insert_toggle
    cmp eax, VK_TAB
    je .do_tab
    cmp eax, VK_ESCAPE
    je .do_exit

    ; Regular character
    mov ecx, [last_char]
    cmp ecx, 32
    jb .main_loop               ; ignore control chars
    cmp ecx, 126
    ja .main_loop

    ; Insert or overwrite char
    push ecx
    call InsertChar
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

; --- Action handlers ---
.do_left:
    call CursorLeft
    call UpdateCursorPos
    jmp .main_loop

.do_right:
    call CursorRight
    call UpdateCursorPos
    jmp .main_loop

.do_up:
    call CursorUp
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_down:
    call CursorDown
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_home:
    mov dword [cursor_x], 0
    call UpdateCursorPos
    jmp .main_loop

.do_end:
    call CursorEnd
    call UpdateCursorPos
    jmp .main_loop

.do_pgup:
    call PageUp
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_pgdn:
    call PageDown
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_enter:
    call SplitLine
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_backspace:
    call DoBackspace
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_delete:
    call DoDelete
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_insert_toggle:
    xor dword [insert_mode], 1
    call DrawStatusBar
    jmp .main_loop

.do_tab:
    ; Insert 4 spaces
    mov ecx, 4
.tab_loop:
    push ecx
    push dword ' '
    call InsertChar
    pop ecx
    dec ecx
    jnz .tab_loop
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_save:
    call SaveFile
    call DrawStatusBar
    jmp .main_loop

.do_search:
    call DoSearch
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_replace:
    call DoReplace
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_goto:
    call DoGotoLine
    call AdjustView
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_help:
    call ShowHelp
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_block_start:
    mov eax, [cursor_y]
    mov [block_start], eax
    call DrawScreen
    call DrawStatusBar
    jmp .main_loop

.do_block_end:
    mov eax, [cursor_y]
    mov [block_end], eax
    call DrawScreen
    call DrawStatusBar
    jmp .main_loop

.do_block_copy:
    call BlockCopy
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_block_move:
    call BlockMove
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_block_delete:
    call BlockDelete
    call DrawScreen
    call UpdateCursorPos
    jmp .main_loop

.do_exit:
    cmp dword [modified], 0
    je .exit_now

    ; Show confirm prompt
    call ShowMessage
    ; simplified: just show message and read Y/N
    push confirm_exit
    call ShowStatusMessage

.exit_confirm_loop:
    call ReadKey
    test eax, eax
    jz .exit_confirm_loop
    cmp ecx, 'Y'
    je .save_and_exit
    cmp ecx, 'y'
    je .save_and_exit
    cmp ecx, 'N'
    je .exit_now
    cmp ecx, 'n'
    je .exit_now
    cmp eax, VK_ESCAPE
    je .cancel_exit
    jmp .exit_confirm_loop

.save_and_exit:
    call SaveFile
    cmp dword [modified], 0
    jne .cancel_exit
.exit_now:
    ; Restore console input mode before returning to the shell
    push dword [stdin_mode]
    push dword [h_stdin]
    call _SetConsoleMode@8
    push 0
    call _ExitProcess@4

.cancel_exit:
    call DrawStatusBar
    jmp .main_loop

; ============================================================================
; GetScreenSize - query console dimensions
; ============================================================================
GetScreenSize:
    push csbi_buf
    push dword [h_stdout]
    call _GetConsoleScreenBufferInfo@8
    ; CONSOLE_SCREEN_BUFFER_INFO offsets:
    ;   0: dwSize(4)  4: dwCursorPos(4)  8: wAttributes(2)
    ;  10: srWindow.Left(2)  12: srWindow.Top(2)
    ;  14: srWindow.Right(2) 16: srWindow.Bottom(2)
    ;  18: dwMaximumWindowSize(4)
    movzx eax, word [csbi_buf+16] ; srWindow.Bottom
    movzx ecx, word [csbi_buf+14] ; srWindow.Right
    movzx edx, word [csbi_buf+12] ; srWindow.Top
    sub eax, edx
    inc eax
    mov [screen_rows], eax
    movzx edx, word [csbi_buf+10] ; srWindow.Left
    sub ecx, edx
    inc ecx
    mov [screen_cols], ecx
    ret

; ============================================================================
; AllocLine - allocate a line buffer, returns ptr in eax
; ============================================================================
AllocLine:
    ; VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
    push PAGE_READWRITE
    push MEM_COMMIT | MEM_RESERVE
    push LINE_BUF_SIZE
    push 0
    call _VirtualAlloc@16
    ret

; ============================================================================
; LoadFile - load file from [filename] into line buffers
; ============================================================================
LoadFile:
    pushad

    ; Open file
    push 0                      ; hTemplateFile
    push FILE_ATTRIBUTE_NORMAL  ; dwFlagsAndAttributes
    push OPEN_EXISTING          ; dwCreationDisposition
    push 0                      ; lpSecurityAttributes
    push 0                      ; dwShareMode
    push GENERIC_READ           ; dwDesiredAccess
    push filename               ; lpFileName
    call _CreateFileA@28
    cmp eax, -1
    je .load_fail
    mov ebx, eax                ; save handle

    ; Free existing first line if any
    ; (skip for simplicity, just overwrite)

    ; Read file byte by byte into lines
    mov dword [num_lines], 0
    xor edi, edi                ; current line index

    ; Allocate first line
    call AllocLine
    mov [line_ptrs + edi*4], eax
    mov ebp, eax                ; ebp = current line ptr
    mov word [ebp], 0           ; length = 0

.read_loop:
    ; ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
    push 0                      ; lpOverlapped
    push num_read               ; lpNumberOfBytesRead
    push 1                      ; nNumberOfBytesToRead
    push file_buf               ; lpBuffer
    push ebx                    ; hFile
    call _ReadFile@20
    test eax, eax
    jz .read_done
    cmp dword [num_read], 0
    je .read_done

    mov al, [file_buf]
    cmp al, 13                  ; CR
    je .read_loop               ; skip CR
    cmp al, 10                  ; LF
    je .new_line

    ; Add byte to current line
    movzx ecx, word [ebp]      ; current length
    cmp ecx, MAX_LINE_LEN - 1
    jge .read_loop              ; line too long, skip
    mov [ebp + 2 + ecx], al
    inc ecx
    mov [ebp], cx
    jmp .read_loop

.new_line:
    inc edi
    cmp edi, MAX_LINES - 1
    jge .read_done              ; too many lines
    call AllocLine
    mov [line_ptrs + edi*4], eax
    mov ebp, eax
    mov word [ebp], 0
    jmp .read_loop

.read_done:
    ; Close file
    push ebx
    call _CloseHandle@4

    lea eax, [edi + 1]
    mov [num_lines], eax

.load_fail:
    popad
    ret

; ============================================================================
; SaveFile - save lines to [filename]
; ============================================================================
SaveFile:
    pushad

    cmp byte [filename], 0
    jne .save_have_name

    ; Prompt for file name when saving a new buffer
    push saveas_prompt
    call ShowStatusMessage
    mov edi, filename
    mov ecx, 259
    call ReadLineInput
    test eax, eax
    jz .save_cancelled

.save_have_name:

    ; Create/truncate file
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push CREATE_ALWAYS
    push 0
    push 0
    push GENERIC_WRITE
    push filename
    call _CreateFileA@28
    cmp eax, -1
    je .save_failed
    mov ebx, eax

    ; Write each line
    xor esi, esi                ; line index
.save_loop:
    cmp esi, [num_lines]
    jge .save_close

    mov eax, [line_ptrs + esi*4]
    test eax, eax
    jz .save_next

    movzx ecx, word [eax]      ; line length
    lea edx, [eax + 2]         ; line data

    ; Write line data
    test ecx, ecx
    jz .save_newline

    push 0
    push num_written
    push ecx
    push edx
    push ebx
    call _WriteFile@20

.save_newline:
    ; Write CRLF
    push 0
    push num_written
    push 2
    push newline_bytes
    push ebx
    call _WriteFile@20

.save_next:
    inc esi
    jmp .save_loop

.save_close:
    push ebx
    call _CloseHandle@4

    mov dword [modified], 0
    push save_ok_str
    call ShowStatusMessage
    popad
    ret

.save_failed:
    push save_fail_str
    call ShowStatusMessage
    popad
    ret

.save_no_name:
    push save_cancel_str
    call ShowStatusMessage
    popad
    ret

.save_cancelled:
    push save_cancel_str
    call ShowStatusMessage
    popad
    ret

; ============================================================================
; DrawScreen - redraw entire screen
; ============================================================================
DrawScreen:
    pushad

    mov eax, [screen_rows]
    sub eax, 2                  ; reserve 2 bottom rows (status + hotkeys)
    cmp eax, 0
    jg .ds_rows_ok
    mov eax, 1
.ds_rows_ok:
    mov ecx, [top_line]         ; starting line index

    xor edx, edx               ; screen row

.draw_loop:
    cmp edx, eax
    jge .draw_status

    push eax
    push ecx
    push edx

    ; Check if this line is in block
    mov ebx, 0                  ; not in block
    cmp dword [block_start], -1
    je .no_block_check
    cmp dword [block_end], -1
    je .no_block_check
    ; Check: block_start <= ecx <= block_end
    mov edi, [block_start]
    mov esi, [block_end]
    ; Ensure edi <= esi
    cmp edi, esi
    jle .block_ordered
    xchg edi, esi
.block_ordered:
    cmp ecx, edi
    jl .no_block_check
    cmp ecx, esi
    jg .no_block_check
    mov ebx, 1                  ; in block
.no_block_check:

    cmp ecx, [num_lines]
    jge .draw_empty

    ; Draw line
    push ebx                    ; block flag
    push edx                    ; screen row
    push ecx                    ; line index
    call DrawLine
    add esp, 12
    jmp .draw_next

.draw_empty:
    ; Draw empty line (tilde or blank)
    push ebx
    push edx
    call DrawEmptyLine
    add esp, 8

.draw_next:
    pop edx
    pop ecx
    pop eax
    inc edx
    inc ecx
    jmp .draw_loop

.draw_status:
    call DrawStatusBar

    popad
    ret

; ============================================================================
; DrawLine - draw one line of text
; Args on stack: [esp+4]=line_index, [esp+8]=screen_row, [esp+12]=block_flag
; ============================================================================
DrawLine:
    push ebp
    mov ebp, esp
    pushad

    mov esi, [ebp+8]           ; line_index
    mov edi, [ebp+12]          ; screen_row
    mov ebx, [ebp+16]          ; block_flag

    ; Get line pointer
    mov eax, [line_ptrs + esi*4]
    test eax, eax
    jz .dl_empty

    movzx ecx, word [eax]      ; length
    lea edx, [eax + 2]         ; data pointer

    ; Write characters to console
    ; First fill the row with spaces
    push num_written

    ; COORD = (col << 16) | row -> pack as DWORD
    movzx eax, di              ; screen_row (low 16)
    shl eax, 16                ; row in high word? No...
    ; COORD: X in low word, Y in high word when passed as DWORD
    ; Actually COORD is {SHORT X, SHORT Y} = X in low 16, Y in high 16
    mov eax, edi
    shl eax, 16
    ; eax = row<<16 | 0 (col=0)
    push eax
    push dword [screen_cols]
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    ; Now write the actual line content
    mov eax, [line_ptrs + esi*4]
    movzx ecx, word [eax]
    lea edx, [eax + 2]
    test ecx, ecx
    jz .dl_set_attr

    ; Cap at screen_cols
    cmp ecx, [screen_cols]
    jle .dl_write
    mov ecx, [screen_cols]
.dl_write:
    mov eax, edi
    shl eax, 16                ; Y in high word, X=0 in low word

    push num_written
    push eax                   ; coord
    push ecx                   ; length
    push edx                   ; buffer
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20

.dl_set_attr:
    ; Set attributes for the row
    mov al, COLOR_TEXT
    test ebx, ebx
    jz .dl_not_block
    mov al, COLOR_BLOCK
.dl_not_block:

    movzx eax, al
    mov ecx, edi
    shl ecx, 16                ; coord: row in high, col 0 in low

    push num_written
    push ecx                   ; coord
    push dword [screen_cols]
    push eax                   ; attribute
    push dword [h_stdout]
    call _FillConsoleOutputAttribute@20

    jmp .dl_done

.dl_empty:
    ; Just clear the row
    mov eax, edi
    shl eax, 16

    push num_written
    push eax
    push dword [screen_cols]
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    mov ecx, edi
    shl ecx, 16
    push num_written
    push ecx
    push dword [screen_cols]
    push COLOR_TEXT
    push dword [h_stdout]
    call _FillConsoleOutputAttribute@20

.dl_done:
    popad
    pop ebp
    ret

; ============================================================================
; DrawEmptyLine - draw empty line (after file end)
; Args: [esp+4]=screen_row, [esp+8]=block_flag
; ============================================================================
DrawEmptyLine:
    push ebp
    mov ebp, esp
    pushad

    mov edi, [ebp+8]           ; screen_row

    ; Fill with spaces
    mov eax, edi
    shl eax, 16

    push num_written
    push eax
    push dword [screen_cols]
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    ; Put '~' at column 0
    mov eax, edi
    shl eax, 16

    push num_written
    push eax
    push 1
    push '~'
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    ; Set color
    mov ecx, edi
    shl ecx, 16
    push num_written
    push ecx
    push dword [screen_cols]
    push COLOR_TEXT
    push dword [h_stdout]
    call _FillConsoleOutputAttribute@20

    popad
    pop ebp
    ret

; ============================================================================
; DrawStatusBar
; ============================================================================
DrawStatusBar:
    pushad

    ; Status/info bar on second-to-last row (last row is hotkey bar)
    mov edi, [screen_rows]
    sub edi, 2
    cmp edi, 0
    jge .dsb_row_ok
    xor edi, edi
.dsb_row_ok:

    ; Fill with spaces and status color
    mov eax, edi
    shl eax, 16

    push num_written
    push eax
    push dword [screen_cols]
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    mov ecx, edi
    shl ecx, 16
    push num_written
    push ecx
    push dword [screen_cols]
    push COLOR_STATUS
    push dword [h_stdout]
    call _FillConsoleOutputAttribute@20

    ; Write filename (or [New File])
    mov esi, filename
    cmp byte [esi], 0
    jne .has_name
    mov esi, untitled_str
.has_name:
    ; Get string length
    mov ecx, esi
    xor edx, edx
.slen:
    cmp byte [ecx + edx], 0
    je .slen_done
    inc edx
    jmp .slen
.slen_done:

    mov eax, edi
    shl eax, 16
    or eax, 1                  ; col=1

    push num_written
    push eax
    push edx
    push esi
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20

    ; Write modified indicator
    cmp dword [modified], 0
    je .no_mod_ind
    ; Write " *" after filename
    mov eax, edi
    shl eax, 16
    or eax, 14                 ; approximate position

    push num_written
    push eax
    push 10
    push modified_str
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20
.no_mod_ind:

    ; Write line/col info on right side
    ; Build "Ln:XXXXX Col:XXX" string
    mov eax, [cursor_y]
    inc eax                    ; 1-based
    call IntToStr              ; result in temp_buf, length in ecx
    ; Write "Ln:" + number
    mov esi, temp_buf
    ; Prefix with "Ln:"
    mov byte [scratch_line], 'L'
    mov byte [scratch_line+1], 'n'
    mov byte [scratch_line+2], ':'
    mov edi, scratch_line+3
    ; Copy number
    push ecx
    rep movsb
    pop ecx
    add ecx, 3                ; "Ln:" prefix
    ; Add " Col:"
    mov byte [scratch_line + ecx], ' '
    inc ecx
    mov byte [scratch_line + ecx], 'C'
    inc ecx
    mov byte [scratch_line + ecx], 'o'
    inc ecx
    mov byte [scratch_line + ecx], 'l'
    inc ecx
    mov byte [scratch_line + ecx], ':'
    inc ecx

    push ecx
    mov eax, [cursor_x]
    inc eax                    ; 1-based
    call IntToStr
    mov esi, temp_buf
    pop edx
    ; Copy col number
    lea edi, [scratch_line + edx]
    add edx, ecx
    rep movsb

    ; Add INS/OVR
    mov byte [scratch_line + edx], ' '
    inc edx
    cmp dword [insert_mode], 1
    jne .ovr_mode
    mov byte [scratch_line + edx], 'I'
    inc edx
    mov byte [scratch_line + edx], 'N'
    inc edx
    mov byte [scratch_line + edx], 'S'
    inc edx
    jmp .mode_done
.ovr_mode:
    mov byte [scratch_line + edx], 'O'
    inc edx
    mov byte [scratch_line + edx], 'V'
    inc edx
    mov byte [scratch_line + edx], 'R'
    inc edx
.mode_done:

    ; Position on right side of status bar
    mov ecx, [screen_cols]
    sub ecx, edx
    sub ecx, 2                ; small margin

    mov eax, [screen_rows]
    sub eax, 2
    shl eax, 16
    or eax, ecx               ; col position

    push num_written
    push eax                  ; coord
    push edx                  ; length
    push scratch_line          ; buffer
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20

    ; Default input echo column when no interactive prompt is active
    mov dword [status_input_col], 0

    ; Draw hotkey row background (last row)
    mov eax, [screen_rows]
    dec eax
    shl eax, 16
    push num_written
    push eax
    push dword [screen_cols]
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    mov ecx, [screen_rows]
    dec ecx
    shl ecx, 16
    push num_written
    push ecx
    push dword [screen_cols]
    push COLOR_STATUS
    push dword [h_stdout]
    call _FillConsoleOutputAttribute@20

    ; Write a compact hotkey hint in the middle of the hotkey row
    mov esi, status_hint
    xor ecx, ecx
.dsb_hlen:
    cmp byte [esi + ecx], 0
    je .dsb_hlen_done
    inc ecx
    jmp .dsb_hlen
.dsb_hlen_done:
    mov eax, [screen_cols]
    sub eax, 2                 ; keep small margins
    cmp eax, 1
    jl .dsb_hint_done
    cmp ecx, eax
    jle .dsb_hlen_ok
    mov ecx, eax
.dsb_hlen_ok:
    mov eax, [screen_cols]
    sub eax, ecx
    shr eax, 1                 ; centered column
    mov edx, [screen_rows]
    dec edx
    shl edx, 16
    or edx, eax

    push num_written
    push edx
    push ecx
    push esi
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20
.dsb_hint_done:

    popad
    ret

; ============================================================================
; IntToStr - convert EAX to decimal string in temp_buf, length in ECX
; ============================================================================
IntToStr:
    pushad
    mov edi, temp_buf + 20     ; work backwards
    mov byte [edi], 0
    mov ecx, 10
    test eax, eax
    jnz .its_loop
    ; Zero
    dec edi
    mov byte [edi], '0'
    jmp .its_done
.its_loop:
    test eax, eax
    jz .its_done
    xor edx, edx
    div ecx
    add dl, '0'
    dec edi
    mov [edi], dl
    jmp .its_loop
.its_done:
    ; Copy to start of temp_buf
    mov esi, edi
    mov edi, temp_buf
    xor ecx, ecx
.its_copy:
    lodsb
    test al, al
    jz .its_end
    stosb
    inc ecx
    jmp .its_copy
.its_end:
    mov [esp + 24], ecx        ; store ecx in pushad frame (ecx is at offset 24)
    popad
    ret

; ============================================================================
; UpdateCursorPos - set console cursor to current editor position
; ============================================================================
UpdateCursorPos:
    call ClampCursorX
    ; Cursor on screen = (cursor_x, cursor_y - top_line)
    mov eax, [cursor_y]
    sub eax, [top_line]
    cmp eax, 0
    jge .ucp_row_nonneg
    xor eax, eax
.ucp_row_nonneg:
    mov ecx, [screen_rows]
    sub ecx, 3                  ; last text row (2 bottom rows excluded)
    cmp ecx, 0
    jge .ucp_text_rows_ok
    xor ecx, ecx
.ucp_text_rows_ok:
    cmp eax, ecx
    jle .ucp_row_ok
    mov eax, ecx
.ucp_row_ok:
    shl eax, 16
    mov ecx, [cursor_x]
    or eax, ecx
    ; COORD packed as {X, Y} = low word X, high word Y
    push eax
    push dword [h_stdout]
    call _SetConsoleCursorPosition@8
    ret

; ============================================================================
; ReadKey - read one key event
; Returns: eax=vk_code, ecx=char, edx=control_key_state
; ============================================================================
ReadKey:
.rk_loop:
    push num_read
    push 1
    push input_rec
    push dword [h_stdin]
    call _ReadConsoleInputA@16

    ; Check if KEY_EVENT
    cmp word [input_rec], KEY_EVENT
    jne .rk_loop

    ; Check bKeyDown
    cmp dword [input_rec + 4], 0
    je .rk_loop                ; ignore key up

    movzx eax, word [input_rec + 10]  ; wVirtualKeyCode
    movzx ecx, byte [input_rec + 14]  ; AsciiChar (in union at offset 14)
    mov edx, [input_rec + 16]          ; dwControlKeyState
    ret

; ============================================================================
; InsertChar - insert character (on stack) at cursor position
; ============================================================================
InsertChar:
    push ebp
    mov ebp, esp
    pushad

    mov eax, [cursor_y]
    mov esi, [line_ptrs + eax*4]
    test esi, esi
    jz .ic_done

    movzx ecx, word [esi]      ; current length
    mov edx, [cursor_x]

    ; If cursor_x > length, pad with spaces
    cmp edx, ecx
    jle .ic_no_pad
.ic_pad:
    cmp ecx, MAX_LINE_LEN - 1
    jge .ic_done
    mov byte [esi + 2 + ecx], ' '
    inc ecx
    cmp ecx, edx
    jl .ic_pad
.ic_no_pad:

    cmp dword [insert_mode], 1
    je .ic_insert
    ; Overwrite mode
    cmp edx, MAX_LINE_LEN - 1
    jge .ic_done
    mov al, [ebp+8]            ; character
    mov [esi + 2 + edx], al
    ; Update length if needed
    cmp edx, ecx
    jl .ic_ovr_nolen
    lea ecx, [edx + 1]
.ic_ovr_nolen:
    mov [esi], cx
    inc dword [cursor_x]
    mov dword [modified], 1
    jmp .ic_done

.ic_insert:
    cmp ecx, MAX_LINE_LEN - 1
    jge .ic_done

    ; Shift chars right from cursor_x
    mov edi, ecx               ; edi = old length
.ic_shift:
    cmp edi, edx
    jle .ic_place
    mov al, [esi + 2 + edi - 1]
    mov [esi + 2 + edi], al
    dec edi
    jmp .ic_shift
.ic_place:
    mov al, [ebp+8]
    mov [esi + 2 + edx], al
    inc ecx
    mov [esi], cx
    inc dword [cursor_x]
    mov dword [modified], 1

.ic_done:
    popad
    pop ebp
    ret 4

; ============================================================================
; DoBackspace
; ============================================================================
DoBackspace:
    pushad

    mov eax, [cursor_x]
    test eax, eax
    jnz .bs_inline

    ; At column 0: join with previous line
    cmp dword [cursor_y], 0
    je .bs_done
    ; If merge would overflow the line buffer, treat as no-op
    mov eax, [cursor_y]
    mov esi, [line_ptrs + eax*4]   ; current line
    test esi, esi
    jz .bs_done
    dec eax
    mov edi, [line_ptrs + eax*4]   ; previous line
    test edi, edi
    jz .bs_done
    movzx ecx, word [esi]
    movzx edx, word [edi]
    lea eax, [ecx + edx]
    cmp eax, MAX_LINE_LEN
    jge .bs_done

    dec dword [cursor_y]
    call CursorEnd              ; move to end of previous line
    call JoinLines              ; join current line with next
    jmp .bs_done

.bs_inline:
    ; Delete char before cursor
    mov edx, [cursor_y]
    mov esi, [line_ptrs + edx*4]
    test esi, esi
    jz .bs_done

    movzx ecx, word [esi]
    mov edx, [cursor_x]
    cmp edx, ecx
    jg .bs_just_move            ; cursor past end, just move left

    ; Shift chars left at position (cursor_x - 1)
    dec edx                     ; position to delete
    mov edi, edx
.bs_shift:
    lea eax, [edi + 1]
    cmp eax, ecx
    jge .bs_shift_done
    mov al, [esi + 2 + edi + 1]
    mov [esi + 2 + edi], al
    inc edi
    jmp .bs_shift
.bs_shift_done:
    dec ecx
    mov [esi], cx
    dec dword [cursor_x]
    mov dword [modified], 1
    jmp .bs_done

.bs_just_move:
    dec dword [cursor_x]

.bs_done:
    popad
    ret

; ============================================================================
; DoDelete - delete char at cursor
; ============================================================================
DoDelete:
    pushad

    mov edx, [cursor_y]
    mov esi, [line_ptrs + edx*4]
    test esi, esi
    jz .del_done

    movzx ecx, word [esi]
    mov eax, [cursor_x]

    cmp eax, ecx
    jge .del_join               ; at or past end: join with next line

    ; Shift chars left
    mov edi, eax
.del_shift:
    lea ebx, [edi + 1]
    cmp ebx, ecx
    jge .del_shift_done
    mov al, [esi + 2 + edi + 1]
    mov [esi + 2 + edi], al
    inc edi
    jmp .del_shift
.del_shift_done:
    dec ecx
    mov [esi], cx
    mov dword [modified], 1
    jmp .del_done

.del_join:
    ; Join current line with next
    mov eax, [cursor_y]
    lea ebx, [eax + 1]
    cmp ebx, [num_lines]
    jge .del_done

    mov esi, [line_ptrs + eax*4]
    mov edi, [line_ptrs + ebx*4]
    test esi, esi
    jz .del_done
    test edi, edi
    jz .del_done
    movzx ecx, word [esi]
    movzx edx, word [edi]
    lea eax, [ecx + edx]
    cmp eax, MAX_LINE_LEN
    jge .del_done

    call JoinLines

.del_done:
    popad
    ret

; ============================================================================
; JoinLines - join line at cursor_y with line at cursor_y+1
; ============================================================================
JoinLines:
    pushad

    mov eax, [cursor_y]
    lea ebx, [eax + 1]
    cmp ebx, [num_lines]
    jge .jl_done

    mov esi, [line_ptrs + eax*4]   ; current line
    mov edi, [line_ptrs + ebx*4]   ; next line
    test esi, esi
    jz .jl_done
    test edi, edi
    jz .jl_done

    movzx ecx, word [esi]          ; current length
    movzx edx, word [edi]          ; next length

    ; Append next line data to current line
    lea eax, [ecx + edx]
    cmp eax, MAX_LINE_LEN
    jge .jl_done                    ; too long

    ; Copy data
    push ecx
    xor ebx, ebx
.jl_copy:
    cmp ebx, edx
    jge .jl_copy_done
    mov al, [edi + 2 + ebx]
    push edx
    lea edx, [ecx + ebx]
    mov [esi + 2 + edx], al
    pop edx
    inc ebx
    jmp .jl_copy
.jl_copy_done:
    add ecx, edx
    mov [esi], cx
    pop ecx                         ; restore original length (for cursor pos)

    ; Remove next line: shift line_ptrs
    mov eax, [cursor_y]
    lea ebx, [eax + 1]
.jl_shift:
    lea ecx, [ebx + 1]
    cmp ecx, [num_lines]
    jge .jl_shift_done
    mov edx, [line_ptrs + ecx*4]
    mov [line_ptrs + ebx*4], edx
    inc ebx
    jmp .jl_shift
.jl_shift_done:
    dec dword [num_lines]
    mov dword [modified], 1

    ; Free the removed line buffer (skip for simplicity)

.jl_done:
    popad
    ret

; ============================================================================
; SplitLine - split current line at cursor position (Enter key)
; ============================================================================
SplitLine:
    pushad

    ; Check line limit
    mov eax, [num_lines]
    cmp eax, MAX_LINES - 1
    jge .sl_done

    ; Get current line
    mov eax, [cursor_y]
    mov esi, [line_ptrs + eax*4]
    test esi, esi
    jz .sl_done

    mov ebx, esi               ; keep current line ptr in ebx
    movzx ecx, word [ebx]      ; current length
    mov edx, [cursor_x]        ; split column

    ; Clamp split column to current line length
    cmp edx, ecx
    jle .sl_col_ok
    mov edx, ecx
.sl_col_ok:

    ; Allocate new line for the part after cursor
    push ecx                    ; preserve current length
    push edx                    ; preserve split column
    call AllocLine
    pop edx
    pop ecx
    test eax, eax
    jz .sl_done
    mov ebp, eax                ; keep new line ptr in ebp

    ; new_len = current_len - split_col
    mov eax, ecx
    sub eax, edx
    mov [ebp], ax

    ; Copy tail bytes to new line (if any)
    test eax, eax
    jz .sl_trunc
    push ecx                    ; save current_len for later
    mov ecx, eax                ; copy count = new_len
    lea esi, [ebx + 2 + edx]    ; src = old line tail
    lea edi, [ebp + 2]          ; dst = new line data
    cld
    rep movsb
    pop ecx                     ; restore current_len
    mov esi, ebx                ; restore current line ptr

.sl_trunc:
    ; Truncate current line at split column
    mov [ebx], dx

    ; Shift lines down to make room
    mov eax, [num_lines]
    dec eax                     ; last index
.sl_shift:
    mov ecx, [cursor_y]
    cmp eax, ecx
    jle .sl_shift_done
    mov ebx, [line_ptrs + eax*4]
    mov [line_ptrs + eax*4 + 4], ebx
    dec eax
    jmp .sl_shift
.sl_shift_done:

    ; Insert new line after current
    mov eax, [cursor_y]
    mov [line_ptrs + eax*4 + 4], ebp

    inc dword [num_lines]
    inc dword [cursor_y]
    mov dword [cursor_x], 0
    mov dword [modified], 1

.sl_done:
    popad
    ret

; ============================================================================
; Navigation
; ============================================================================
CursorLeft:
    cmp dword [cursor_x], 0
    je .cl_prev_line
    dec dword [cursor_x]
    ret
.cl_prev_line:
    cmp dword [cursor_y], 0
    je .cl_done
    dec dword [cursor_y]
    call CursorEnd
    call AdjustView
.cl_done:
    ret

CursorRight:
    mov eax, [cursor_y]
    mov esi, [line_ptrs + eax*4]
    test esi, esi
    jz .cr_done
    movzx ecx, word [esi]
    cmp [cursor_x], ecx
    jl .cr_move
    ; At end of line, go to next line
    mov eax, [cursor_y]
    inc eax
    cmp eax, [num_lines]
    jge .cr_done
    mov [cursor_y], eax
    mov dword [cursor_x], 0
    call AdjustView
    ret
.cr_move:
    inc dword [cursor_x]
.cr_done:
    ret

CursorUp:
    cmp dword [cursor_y], 0
    je .cu_done
    dec dword [cursor_y]
    call ClampCursorX
.cu_done:
    ret

CursorDown:
    mov eax, [cursor_y]
    inc eax
    cmp eax, [num_lines]
    jge .cd_done
    mov [cursor_y], eax
    call ClampCursorX
.cd_done:
    ret

CursorEnd:
    mov eax, [cursor_y]
    mov esi, [line_ptrs + eax*4]
    test esi, esi
    jz .ce_done
    movzx ecx, word [esi]
    mov [cursor_x], ecx
.ce_done:
    ret

PageUp:
    mov eax, [screen_rows]
    sub eax, 2                 ; text area height (2 bottom UI rows)
    cmp eax, 1
    jge .pu_height_ok
    mov eax, 1
.pu_height_ok:
    sub [cursor_y], eax
    cmp dword [cursor_y], 0
    jge .pu_done
    mov dword [cursor_y], 0
.pu_done:
    call ClampCursorX
    ret

PageDown:
    mov eax, [screen_rows]
    sub eax, 2
    cmp eax, 1
    jge .pd_height_ok
    mov eax, 1
.pd_height_ok:
    add [cursor_y], eax
    mov ecx, [num_lines]
    dec ecx
    cmp [cursor_y], ecx
    jle .pd_done
    mov [cursor_y], ecx
.pd_done:
    call ClampCursorX
    ret

; ClampCursorX - keep cursor within current line and visible screen width
ClampCursorX:
    push eax
    push ecx
    push esi

    mov eax, [num_lines]
    test eax, eax
    jnz .ccx_have_lines
    mov dword [cursor_y], 0
    mov dword [cursor_x], 0
    jmp .ccx_done

.ccx_have_lines:
    dec eax
    cmp dword [cursor_y], 0
    jge .ccx_y_nonneg
    mov dword [cursor_y], 0
.ccx_y_nonneg:
    mov ecx, [cursor_y]
    cmp ecx, eax
    jle .ccx_y_ok
    mov [cursor_y], eax
.ccx_y_ok:

    mov eax, [cursor_y]
    mov esi, [line_ptrs + eax*4]
    test esi, esi
    jz .ccx_zero_x
    movzx ecx, word [esi]
    cmp dword [cursor_x], 0
    jge .ccx_x_nonneg
    mov dword [cursor_x], 0
.ccx_x_nonneg:
    cmp [cursor_x], ecx
    jle .ccx_screen
    mov [cursor_x], ecx

.ccx_screen:
    mov eax, [screen_cols]
    test eax, eax
    jle .ccx_done
    dec eax
    cmp eax, 0
    jge .ccx_screen_ok
    xor eax, eax
.ccx_screen_ok:
    cmp [cursor_x], eax
    jle .ccx_done
    mov [cursor_x], eax
    jmp .ccx_done

.ccx_zero_x:
    mov dword [cursor_x], 0

.ccx_done:
    pop esi
    pop ecx
    pop eax
    ret

; ============================================================================
; AdjustView - scroll view so cursor is visible
; ============================================================================
AdjustView:
    ; If cursor_y < top_line, scroll up
    mov eax, [cursor_y]
    cmp eax, [top_line]
    jge .av_check_bottom
    mov [top_line], eax
    ret
.av_check_bottom:
    ; If cursor_y >= top_line + text_rows, scroll down (2 bottom UI rows)
    mov ecx, [top_line]
    add ecx, [screen_rows]
    sub ecx, 2
    cmp eax, ecx
    jl .av_done
    ; Set top_line so cursor is on last text row
    mov ecx, [screen_rows]
    sub ecx, 3                 ; -2 UI rows, -1 for 0-based
    cmp ecx, 0
    jge .av_rows_ok
    xor ecx, ecx
.av_rows_ok:
    sub eax, ecx
    cmp eax, 0
    jge .av_set
    xor eax, eax
.av_set:
    mov [top_line], eax
.av_done:
    ret

; ============================================================================
; Search
; ============================================================================
DoSearch:
    pushad

    ; Prompt for search string
    push search_prompt
    call ShowStatusMessage

    ; Read input string into search_buf
    mov edi, search_buf
    mov ecx, 126
    call ReadLineInput
    test eax, eax
    jz .search_cancel

    ; Search from current position
    call FindNext
    test eax, eax
    jnz .search_found

    push not_found_str
    call ShowStatusMessage
    jmp .search_cancel

.search_found:
    ; eax = line, edx = column
    mov [cursor_y], eax
    mov [cursor_x], edx
    call AdjustView

.search_cancel:
    popad
    ret

; ============================================================================
; FindNext - search for [search_buf] from cursor position
; Returns: eax=line (or 0 if not found), edx=column, ZF set if not found
; ============================================================================
FindNext:
    pushad

    mov ecx, [cursor_y]        ; start line
    mov ebx, [cursor_x]
    inc ebx                     ; start after cursor

.fn_line_loop:
    cmp ecx, [num_lines]
    jge .fn_wrap

    mov esi, [line_ptrs + ecx*4]
    test esi, esi
    jz .fn_next_line

    movzx edx, word [esi]      ; line length
    lea esi, [esi + 2]         ; line data

    ; Search within this line starting at ebx
.fn_col_loop:
    cmp ebx, edx
    jge .fn_next_line

    ; Compare search_buf with line at position ebx
    push ecx
    push edx
    push ebx
    lea edi, [esi + ebx]
    mov eax, search_buf
    xor ecx, ecx
.fn_cmp:
    mov cl, [eax]
    test cl, cl
    jz .fn_match                ; end of search string = match
    cmp byte [edi], 0
    je .fn_no_match
    pop ebx
    push ebx
    ; Check remaining length
    push eax
    mov eax, edx
    sub eax, ebx
    pop eax
    ; Simple: just compare byte
    mov cl, [eax]
    cmp cl, [edi]
    jne .fn_no_match
    inc eax
    inc edi
    jmp .fn_cmp

.fn_match:
    pop ebx
    pop edx
    pop ecx
    ; Found! ecx=line, ebx=col
    mov [esp+28], ecx          ; eax in pushad frame
    mov [esp+20], ebx          ; edx in pushad frame
    ; Set non-zero flag
    popad
    mov eax, eax               ; keep values
    test eax, -1               ; clear ZF (non-zero means found)
    ret

.fn_no_match:
    pop ebx
    pop edx
    pop ecx
    inc ebx
    jmp .fn_col_loop

.fn_next_line:
    inc ecx
    xor ebx, ebx               ; start at col 0
    jmp .fn_line_loop

.fn_wrap:
    ; Not found
    popad
    xor eax, eax
    ret

; ============================================================================
; DoReplace
; ============================================================================
DoReplace:
    pushad

    push search_prompt
    call ShowStatusMessage
    mov edi, search_buf
    mov ecx, 126
    call ReadLineInput
    test eax, eax
    jz .repl_cancel

    push replace_prompt
    call ShowStatusMessage
    mov edi, replace_buf
    mov ecx, 126
    call ReadLineInput
    test eax, eax
    jz .repl_cancel

    ; Find and replace loop
.repl_loop:
    call FindNext
    test eax, eax
    jz .repl_done

    mov [cursor_y], eax
    mov [cursor_x], edx
    call AdjustView
    call DrawScreen
    call UpdateCursorPos

    ; Ask Y/N/A/Esc
    push replace_ask
    call ShowStatusMessage

.repl_ask_loop:
    call ReadKey
    test eax, eax
    jz .repl_ask_loop
    cmp ecx, 'Y'
    je .repl_yes
    cmp ecx, 'y'
    je .repl_yes
    cmp ecx, 'N'
    je .repl_no
    cmp ecx, 'n'
    je .repl_no
    cmp ecx, 'A'
    je .repl_all
    cmp ecx, 'a'
    je .repl_all
    cmp eax, VK_ESCAPE
    je .repl_done
    jmp .repl_ask_loop

.repl_yes:
    call DoReplaceOne
    jmp .repl_loop

.repl_no:
    ; Skip, search for next
    jmp .repl_loop

.repl_all:
    call DoReplaceOne
.repl_all_loop:
    call FindNext
    test eax, eax
    jz .repl_done
    mov [cursor_y], eax
    mov [cursor_x], edx
    call DoReplaceOne
    jmp .repl_all_loop

.repl_done:
.repl_cancel:
    popad
    ret

; ============================================================================
; DoReplaceOne - replace search_buf with replace_buf at cursor position
; ============================================================================
DoReplaceOne:
    pushad

    mov eax, [cursor_y]
    mov esi, [line_ptrs + eax*4]
    test esi, esi
    jz .ro_done

    movzx ecx, word [esi]      ; line length
    mov edx, [cursor_x]        ; replace position

    ; Get search length into edi
    xor edi, edi
.ro_slen:
    cmp byte [search_buf + edi], 0
    je .ro_slen_done
    inc edi
    jmp .ro_slen
.ro_slen_done:

    ; Get replace length into ebx
    xor ebx, ebx
.ro_rlen:
    cmp byte [replace_buf + ebx], 0
    je .ro_rlen_done
    inc ebx
    jmp .ro_rlen
.ro_rlen_done:

    ; Build new line in scratch_line:
    ; [0..edx) + replace_buf + [edx+edi..ecx)
    ; Part 1: copy [0..edx) from original
    xor eax, eax
.ro_p1:
    cmp eax, edx
    jge .ro_p2
    mov cl, [esi + 2 + eax]
    mov [scratch_line + 2 + eax], cl
    inc eax
    jmp .ro_p1

.ro_p2:
    ; Part 2: copy replace_buf (ebx bytes)
    xor ecx, ecx
.ro_p2_loop:
    cmp ecx, ebx
    jge .ro_p3
    push eax
    mov al, [replace_buf + ecx]
    pop eax
    push edx
    mov dl, [replace_buf + ecx]
    mov [scratch_line + 2 + eax], dl
    pop edx
    inc eax
    inc ecx
    jmp .ro_p2_loop

.ro_p3:
    ; Part 3: copy [edx+edi..orig_length) from original
    movzx ecx, word [esi]      ; original length
    push eax                    ; save dest pos
    mov eax, edx
    add eax, edi                ; src = cursor_x + search_len
.ro_p3_loop:
    cmp eax, ecx
    jge .ro_p3_done
    mov dl, [esi + 2 + eax]
    pop ebx                     ; dest pos
    push ebx
    mov [scratch_line + 2 + ebx], dl
    inc eax
    ; increment dest pos on stack
    pop ebx
    inc ebx
    push ebx
    jmp .ro_p3_loop
.ro_p3_done:
    pop eax                     ; final dest pos = new length

    ; Check length
    cmp eax, MAX_LINE_LEN
    jge .ro_done

    ; Store new length
    mov [scratch_line], ax

    ; Copy scratch_line back to original line
    movzx ecx, ax
    mov word [esi], ax
    xor edx, edx
.ro_copyback:
    cmp edx, ecx
    jge .ro_copyback_done
    mov al, [scratch_line + 2 + edx]
    mov [esi + 2 + edx], al
    inc edx
    jmp .ro_copyback
.ro_copyback_done:

    ; Advance cursor past replacement
    mov eax, [cursor_x]
    ; Get replace length again
    xor ebx, ebx
.ro_rlen2:
    cmp byte [replace_buf + ebx], 0
    je .ro_rlen2_done
    inc ebx
    jmp .ro_rlen2
.ro_rlen2_done:
    add eax, ebx
    mov [cursor_x], eax
    mov dword [modified], 1

.ro_done:
    popad
    ret

; ============================================================================
; DoGotoLine
; ============================================================================
DoGotoLine:
    pushad

    push goto_prompt
    call ShowStatusMessage

    mov edi, temp_buf
    mov ecx, 10
    call ReadLineInput
    test eax, eax
    jz .gl_cancel

    ; Parse number from temp_buf
    mov esi, temp_buf
    xor eax, eax
    xor ecx, ecx
.gl_parse:
    movzx edx, byte [esi + ecx]
    cmp edx, '0'
    jb .gl_parse_done
    cmp edx, '9'
    ja .gl_parse_done
    imul eax, 10
    sub edx, '0'
    add eax, edx
    inc ecx
    jmp .gl_parse
.gl_parse_done:
    ; eax = line number (1-based)
    test eax, eax
    jz .gl_cancel
    dec eax                     ; to 0-based
    cmp eax, [num_lines]
    jl .gl_ok
    mov eax, [num_lines]
    dec eax
.gl_ok:
    mov [cursor_y], eax
    mov dword [cursor_x], 0
    call AdjustView

.gl_cancel:
    popad
    ret

; ============================================================================
; ReadLineInput - read a line of text into [edi], max ecx chars
; Returns eax=length (0 = cancelled by Esc)
; ============================================================================
ReadLineInput:
    push ebx
    push ecx
    push edx
    push esi
    mov ebx, edi                ; buffer start
    mov esi, ecx                ; max length
    xor ecx, ecx               ; current length

.rli_loop:
    push ecx
    call ReadKey
    pop ecx

    cmp eax, VK_ESCAPE
    je .rli_cancel

    cmp eax, VK_RETURN
    je .rli_done

    cmp eax, VK_BACK
    je .rli_backspace

    ; Regular char
    cmp ecx, esi
    jge .rli_loop               ; buffer full
    cmp byte [input_rec+14], 32
    jb .rli_loop
    mov al, [input_rec+14]
    mov [ebx + ecx], al
    inc ecx

    ; Echo char on status bar
    push ecx
    push eax

    mov eax, [screen_rows]
    sub eax, 2                 ; status row (hotkey row is last row)
    shl eax, 16
    mov edx, [status_input_col]
    add edx, ecx
    dec edx                    ; current char position
    or eax, edx

    push num_written
    push eax
    push 1
    lea eax, [ebx + ecx - 1]
    push eax
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20

    pop eax
    pop ecx
    jmp .rli_loop

.rli_backspace:
    test ecx, ecx
    jz .rli_loop
    dec ecx
    ; Erase char on screen
    push ecx
    mov eax, [screen_rows]
    sub eax, 2                 ; status row
    shl eax, 16
    mov edx, [status_input_col]
    add edx, ecx
    or eax, edx

    push num_written
    push eax
    push 1
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20
    pop ecx
    jmp .rli_loop

.rli_done:
    mov byte [ebx + ecx], 0
    mov eax, ecx
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

.rli_cancel:
    mov byte [ebx], 0
    xor eax, eax
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

; ============================================================================
; ShowStatusMessage - show string at [esp+4] on status bar
; ============================================================================
ShowStatusMessage:
    push ebp
    mov ebp, esp
    pushad

    mov esi, [ebp+8]

    ; Get string length
    xor ecx, ecx
.ssm_len:
    cmp byte [esi + ecx], 0
    je .ssm_len_done
    inc ecx
    jmp .ssm_len
.ssm_len_done:
    mov [status_input_col], ecx

    ; Write on status bar
    mov eax, [screen_rows]
    sub eax, 2
    shl eax, 16                ; Y in high word, X=0

    ; First clear status bar
    push num_written
    push eax
    push dword [screen_cols]
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    mov eax, [screen_rows]
    sub eax, 2
    shl eax, 16

    push num_written
    push eax
    push dword [screen_cols]
    push COLOR_STATUS
    push dword [h_stdout]
    call _FillConsoleOutputAttribute@20

    mov eax, [screen_rows]
    sub eax, 2
    shl eax, 16

    push num_written
    push eax
    push ecx
    push esi
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20

    mov dword [msg_timer], 50

    popad
    pop ebp
    ret 4

; ============================================================================
; ShowMessage / ShowHelp
; ============================================================================
ShowMessage:
    ret

ShowHelp:
    pushad

    ; Draw help text in center of screen
    ; Just overwrite a few lines
    mov edi, 3                  ; start at row 3

    ; Draw 6 help lines
    push help_line0
    push edi
    call DrawHelpLine
    inc edi
    push help_line1
    push edi
    call DrawHelpLine
    inc edi
    push help_line2
    push edi
    call DrawHelpLine
    inc edi
    push help_line3
    push edi
    call DrawHelpLine
    inc edi
    push help_line4
    push edi
    call DrawHelpLine
    inc edi
    push help_line5
    push edi
    call DrawHelpLine

    ; Wait for key
.help_wait:
    call ReadKey
    test eax, eax
    jz .help_wait

    popad
    ret

; DrawHelpLine: [esp+4]=row, [esp+8]=string
DrawHelpLine:
    push ebp
    mov ebp, esp
    pushad

    mov edi, [ebp+8]           ; row
    mov esi, [ebp+12]          ; string

    ; Get string length
    xor ecx, ecx
.dhl_len:
    cmp byte [esi + ecx], 0
    je .dhl_done_len
    inc ecx
    jmp .dhl_len
.dhl_done_len:

    ; Center position
    mov eax, [screen_cols]
    sub eax, ecx
    shr eax, 1                 ; col

    ; First fill row background
    mov edx, edi
    shl edx, 16

    push num_written
    push edx
    push dword [screen_cols]
    push COLOR_STATUS
    push dword [h_stdout]
    call _FillConsoleOutputAttribute@20

    mov edx, edi
    shl edx, 16

    push num_written
    push edx
    push dword [screen_cols]
    push ' '
    push dword [h_stdout]
    call _FillConsoleOutputCharacterA@20

    ; Write text
    mov edx, edi
    shl edx, 16
    or edx, eax                ; col

    push num_written
    push edx
    push ecx
    push esi
    push dword [h_stdout]
    call _WriteConsoleOutputCharacterA@20

    popad
    pop ebp
    ret 8

; ============================================================================
; Block Operations
; ============================================================================

BlockCopy:
    pushad

    cmp dword [block_start], -1
    je .bc_done
    cmp dword [block_end], -1
    je .bc_done

    ; Ensure start <= end
    mov eax, [block_start]
    mov ebx, [block_end]
    cmp eax, ebx
    jle .bc_ordered
    xchg eax, ebx
.bc_ordered:
    ; eax=start, ebx=end
    ; Copy lines after cursor_y
    mov ecx, ebx
    sub ecx, eax
    inc ecx                     ; number of lines to copy

    ; First make room: shift lines down by ecx starting from cursor_y+1
    mov edx, [num_lines]
    add edx, ecx
    cmp edx, MAX_LINES
    jge .bc_done

    ; Shift from end
    mov edx, [num_lines]
    dec edx
    mov edi, edx
    add edi, ecx               ; target
.bc_shift:
    cmp edx, [cursor_y]
    jle .bc_shift_done
    mov esi, [line_ptrs + edx*4]
    mov [line_ptrs + edi*4], esi
    dec edx
    dec edi
    jmp .bc_shift
.bc_shift_done:

    ; Copy the block lines (allocate new lines)
    mov esi, eax                ; source line index
    mov edi, [cursor_y]
    inc edi                     ; insert position
    mov edx, ecx               ; count
.bc_copy_loop:
    test edx, edx
    jz .bc_copy_done

    push eax
    push edx
    push esi
    push edi

    call AllocLine
    mov ebx, eax               ; new line

    pop edi
    pop esi

    ; Copy source line to new line
    mov ecx, [line_ptrs + esi*4]
    movzx eax, word [ecx]      ; length
    mov [ebx], ax

    ; Copy data
    xor edx, edx
.bc_data_copy:
    cmp edx, eax
    jge .bc_data_done
    mov cl, [ecx + 2 + edx]
    mov [ebx + 2 + edx], cl
    ; Reload ecx (clobbered)
    push edx
    mov ecx, [line_ptrs + esi*4]
    pop edx
    inc edx
    jmp .bc_data_copy
.bc_data_done:

    mov [line_ptrs + edi*4], ebx

    inc esi
    inc edi
    pop edx
    pop eax
    dec edx
    jmp .bc_copy_loop

.bc_copy_done:
    mov eax, ebx               ; just keep ecx count from earlier
    ; Update num_lines
    ; ecx was count at start, need to recalculate
    mov eax, [block_end]
    sub eax, [block_start]
    cmp eax, 0
    jl .bc_fix
    inc eax
    add [num_lines], eax
    jmp .bc_finish
.bc_fix:
    neg eax
    inc eax
    add [num_lines], eax
.bc_finish:
    mov dword [modified], 1
    mov dword [block_start], -1
    mov dword [block_end], -1

    push block_copy_str
    call ShowStatusMessage

.bc_done:
    popad
    ret

BlockMove:
    pushad
    ; Block move = copy + delete original
    ; Simplified: just show message for now
    ; TODO: implement properly
    call BlockCopy
    ; Would need to delete the original block, but that's complex
    ; when the cursor could be inside the block
    push block_move_str
    call ShowStatusMessage
    popad
    ret

BlockDelete:
    pushad

    cmp dword [block_start], -1
    je .bd_done
    cmp dword [block_end], -1
    je .bd_done

    mov eax, [block_start]
    mov ebx, [block_end]
    cmp eax, ebx
    jle .bd_ordered
    xchg eax, ebx
.bd_ordered:
    ; Delete lines eax..ebx
    mov ecx, ebx
    sub ecx, eax
    inc ecx                     ; count to delete

    ; Shift remaining lines up
    lea edi, [eax]              ; dest = block_start
    lea esi, [ebx + 1]         ; src = block_end + 1
.bd_shift:
    cmp esi, [num_lines]
    jge .bd_shift_done
    mov edx, [line_ptrs + esi*4]
    mov [line_ptrs + edi*4], edx
    inc esi
    inc edi
    jmp .bd_shift
.bd_shift_done:
    sub [num_lines], ecx

    ; Ensure at least 1 line
    cmp dword [num_lines], 0
    jg .bd_lines_ok
    mov dword [num_lines], 1
    call AllocLine
    mov [line_ptrs], eax
    mov word [eax], 0
.bd_lines_ok:

    ; Adjust cursor
    cmp [cursor_y], eax
    jl .bd_cursor_ok
    mov [cursor_y], eax
    cmp eax, [num_lines]
    jl .bd_cursor_ok
    mov eax, [num_lines]
    dec eax
    mov [cursor_y], eax
.bd_cursor_ok:

    mov dword [modified], 1
    mov dword [block_start], -1
    mov dword [block_end], -1

    push block_del_str
    call ShowStatusMessage

.bd_done:
    popad
    ret

; ============================================================================
; Helpers
; ============================================================================

; SkipArg - skip past current argument (handles quotes)
SkipArg:
    cmp byte [esi], '"'
    je .skip_quoted
.skip_normal:
    cmp byte [esi], 0
    je .skip_done
    cmp byte [esi], ' '
    je .skip_done
    inc esi
    jmp .skip_normal
.skip_quoted:
    inc esi                     ; skip opening quote
.skip_q_loop:
    cmp byte [esi], 0
    je .skip_done
    cmp byte [esi], '"'
    je .skip_q_end
    inc esi
    jmp .skip_q_loop
.skip_q_end:
    inc esi                     ; skip closing quote
.skip_done:
    ret

; SkipSpaces
SkipSpaces:
    cmp byte [esi], ' '
    jne .ss_done
    inc esi
    jmp SkipSpaces
.ss_done:
    ret
