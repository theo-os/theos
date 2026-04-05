.intel_syntax noprefix
.text

.macro nt_stub name, number
.globl \name
\name:
    mov eax, \number
    mov rdi, rcx
    mov rsi, rdx
    mov rdx, r8
    mov r10, r9
    mov r8, [rsp + 0x28]
    mov r9, [rsp + 0x30]
    syscall
    ret
.endm

nt_stub NtClose, 0
nt_stub NtQueryInformationProcess, 1
nt_stub NtQueryInformationFile, 2
nt_stub NtReadFile, 3
nt_stub NtWriteFile, 4
nt_stub NtCreateFile, 5
nt_stub NtOpenFile, 6
nt_stub NtCreateSection, 7
nt_stub NtMapViewOfSection, 8
nt_stub NtUnmapViewOfSection, 9
nt_stub NtAllocateVirtualMemory, 10
nt_stub NtFreeVirtualMemory, 11
nt_stub NtProtectVirtualMemory, 12
nt_stub NtCreateEvent, 13
nt_stub NtSetEvent, 14
nt_stub NtWaitForSingleObject, 15
nt_stub NtCreateUserProcess, 16
nt_stub NtTerminateProcess, 17
nt_stub NtTerminateThread, 18
nt_stub NtDelayExecution, 19
nt_stub NtQuerySystemTime, 20
nt_stub NtOpenSection, 21
nt_stub NtDeviceIoControlFile, 22
nt_stub NtQueryVirtualMemory, 23
nt_stub NtYieldExecution, 24
nt_stub NtClearEvent, 25
nt_stub NtResetEvent, 26
nt_stub NtCreateThreadEx, 27
