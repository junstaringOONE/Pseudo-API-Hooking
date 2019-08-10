# Pseudo API Hooking
###### • Hooking what the API calls (or at least tries to)

## What it does & how it works
###### • It simply searches for a call/jmp to a function ptr, which many API calls result in

For example
```
.text:0000000180037410                         ; BOOL __stdcall TerminateThreadStub(HANDLE hThread, DWORD dwExitCode)
.text:0000000180037410                                         public TerminateThreadStub
.text:0000000180037410                         TerminateThreadStub proc near           ; DATA XREF: .rdata:000000018007C0B5↓o
.text:0000000180037410                                                                 ; .rdata:off_1800901B8↓o
.text:0000000180037410 48 FF 25 99 21 04 00                    jmp     cs:__imp_TerminateThread
.text:0000000180037410                         TerminateThreadStub endp
```

`TerminateThread` simply calls a function pointer.
```
.idata:00000001800795A8                                                                 ; DATA XREF: TerminateProcessStub↑r
.idata:00000001800795B0                         ; BOOL __stdcall TerminateThread(HANDLE hThread, DWORD dwExitCode)
.idata:00000001800795B0 ?? ?? ?? ?? ?? ?? ?? ??                 extrn __imp_TerminateThread:qword
.idata:00000001800795B0                                                                 ; DATA XREF: TerminateThreadStub↑r
```

The hook will replace `__imp_TerminateThread` with the specified hook.

The code in `main` will produce the following output:

![Imgur Image](https://i.imgur.com/enplQIY.png)
