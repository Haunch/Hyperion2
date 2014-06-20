

; -----------------------------------------------
; void *FindKernel32Base(void)
; tries to find the base address of kernel32.dll
; returns NULL on error
; -----------------------------------------------
K32Base:
   mov    eax, [fs:0x30]   ; address of PEB
   mov    eax, [eax + 0x0C]   ; PEB->Ldr
   mov    eax, [eax + 0x1C]    ; Ldr->InMemoryOrderModuleList (first element is ntdll.dll)
   mov    eax, [eax]      ; InMemoryOrderModuleList->Flink (second element is kernel32.dll)
   mov    eax, [eax + 0x08]   ; DllBase
   cmp word [eax], 'MZ'   ; check for MZ header
   je    FindKernel32Base_end
   xor    eax, eax      ; zero eax if not found
FindKernel32Base_end:
   ret


;Dynamically load the needed APIs
;Strings are created on stack

;dllname: zero terminated string with dll name
;store: save the dll image base here
;Jumps to LoadLogAPIsExit if an Error Occurs
macro loadDLL dllname, store, exit
{
        lea eax,[dllname]
        invoke LoadLibrary,eax   ; replace with custom
        mov [retval],eax
        test eax,eax
        jz exit
        mov [store],eax
}

;functionname: zero terminated string with functions name
;dll_imagebase: imagebase of the dll
;returns: function pointer in eax
macro loadAPI functionname, dll_imagebase, exit
{
        lea eax,[functionname]
        invoke GetProcAddress,dword [dll_imagebase],eax   ; Replace with custom
        mov [retval],eax
        test eax,eax
        jz exit
}

;write str1 and newline to logfile
;exit: function exit if an error occurs
macro writeStr1AndNewline exit
{
        ;lea eax,[str1]
        ;stdcall writeLog,[APITable],eax
        ;mov [retval],eax
        ;test eax,eax
        ;jz exit
        ;stdcall writeNewLineToLog, [APITable]
        ;mov [retval],eax
        ;test eax,eax
        ;jz exit
}


;Loads all necessary APISs
proc loadRegularAPIs stdcall APITable:DWORD

local str1[256]:BYTE, kernel32_imagebase:DWORD, retval:DWORD

        pushad
       ;createStringLoading str1
        ;writeStr1AndNewline LoadRegularAPIsExit

        ;Get Kernel32.Dll Imagebase
        ;createStringKernel32 str1
        ;writeStr1AndNewline LoadRegularAPIsExit
        ;loadDLL str1, kernel32_imagebase, LoadRegularAPIsExit
        ;;;;;;;;;;;
        ;new- working
        call K32Base
        cmp eax, 0
        je LoadRegularAPIsExit
        mov [kernel32_imagebase],eax


        ;Load the APIs

        createStringGetModuleHandle str1

        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit
        mov edx,[APITable]
        mov [edx+GetModuleHandle],eax

        createStringVirtualAlloc str1
        ;writeStr1AndNewline LoadRegularAPIsExit
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit
        mov edx,[APITable]
        mov [edx+VirtualAlloc],eax

        createStringVirtualProtect str1
        ;writeStr1AndNewline LoadRegularAPIsExit
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit
        mov edx,[APITable]
        mov [edx+VirtualProtect],eax

        createStringVirtualFree str1
        ;writeStr1AndNewline LoadRegularAPIsExit
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit
        mov edx,[APITable]
        mov [edx+VirtualFree],eax


        ;
        ;Load more APIs here...
        ;createstrings.inc macro also added.
        ;Experimental sleep

        createStringSleep str1
        ;writeStr1AndNewline LoadRegularAPIsExit
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit
        mov edx,[APITable]
        mov [edx+Sleep],eax

        ;
        ;

        mov [retval],1

LoadRegularAPIsExit:
        popad
        mov eax,[retval]
        ret
endp
