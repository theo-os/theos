#define NULL ((void *)0)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef long long NTSTATUS;
typedef unsigned long long HANDLE;
typedef unsigned long long ULONG_PTR;
typedef unsigned long long SIZE_T;
typedef SIZE_T *PSIZE_T;
typedef void *PVOID;
typedef unsigned long ULONG;
typedef unsigned char BOOLEAN;
typedef HANDLE *PHANDLE;

#define STATUS_SUCCESS 0
#define STATUS_END_OF_FILE ((NTSTATUS)0xC0000011u)
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102u)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010u)
#define PROCESS_BASIC_INFORMATION_CLASS 0
#define MEMORY_BASIC_INFORMATION_CLASS 0
#define FILE_GENERIC_READ 0x00120089u
#define FILE_OPEN 0x00000001u
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020u
#define EVENT_TYPE_NOTIFICATION 0
#define MEM_COMMIT 0x1000u

typedef struct {
    u16 Length;
    u16 MaximumLength;
    u16 *Buffer;
} UNICODE_STRING;

typedef struct {
    u32 Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    u32 Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct {
    NTSTATUS Status;
    unsigned long long Information;
} IO_STATUS_BLOCK;

typedef struct {
    unsigned long long BaseAddress;
    unsigned long long AllocationBase;
    u32 AllocationProtect;
    u16 PartitionId;
    u16 SharedReserved;
    unsigned long long RegionSize;
    u32 State;
    u32 Protect;
    u32 Type;
    u32 Padding;
} MEMORY_BASIC_INFORMATION;

typedef struct {
    unsigned long long Reserved1;
    unsigned long long PebBaseAddress;
    unsigned long long Reserved2[2];
    unsigned long long UniqueProcessId;
    unsigned long long InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct {
    u32 Length;
    u32 MaximumLength;
    u32 Flags;
    u32 DebugFlags;
    unsigned long long ConsoleHandle;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS;

typedef struct {
    u8 Reserved[16];
    unsigned long long ImageBaseAddress;
    unsigned long long Ldr;
    RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
} PEB;

extern NTSTATUS NtClose(HANDLE Handle);
extern NTSTATUS NtQueryInformationProcess(
    HANDLE ProcessHandle,
    u32 ProcessInformationClass,
    void *ProcessInformation,
    u32 ProcessInformationLength,
    u32 *ReturnLength
);
extern NTSTATUS NtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    void *ApcRoutine,
    void *ApcContext,
    IO_STATUS_BLOCK *IoStatusBlock,
    void *Buffer,
    unsigned long long Length,
    void *ByteOffset,
    void *Key
);
extern NTSTATUS NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    void *ApcRoutine,
    void *ApcContext,
    IO_STATUS_BLOCK *IoStatusBlock,
    const void *Buffer,
    unsigned long long Length,
    void *ByteOffset,
    void *Key
);
extern NTSTATUS NtCreateFile(
    HANDLE *FileHandle,
    u32 DesiredAccess,
    OBJECT_ATTRIBUTES *ObjectAttributes,
    IO_STATUS_BLOCK *IoStatusBlock,
    i64 *AllocationSize,
    u32 FileAttributes,
    u32 ShareAccess,
    u32 CreateDisposition,
    u32 CreateOptions,
    void *EaBuffer,
    u32 EaLength
);
extern NTSTATUS NtCreateEvent(
    HANDLE *EventHandle,
    u32 DesiredAccess,
    OBJECT_ATTRIBUTES *ObjectAttributes,
    u32 EventType,
    BOOLEAN InitialState
);
extern NTSTATUS NtSetEvent(HANDLE EventHandle, long *PreviousState);
extern NTSTATUS NtResetEvent(HANDLE EventHandle, long *PreviousState);
extern NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, i64 *Timeout);
extern NTSTATUS NtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    u32 ProcessDesiredAccess,
    u32 ThreadDesiredAccess,
    OBJECT_ATTRIBUTES *ProcessObjectAttributes,
    OBJECT_ATTRIBUTES *ThreadObjectAttributes,
    u32 ProcessFlags,
    u32 ThreadFlags,
    RTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    void *CreateInfo,
    void *AttributeList
);
extern NTSTATUS NtDelayExecution(BOOLEAN Alertable, i64 *DelayInterval);
extern NTSTATUS NtQuerySystemTime(i64 *SystemTime);
extern NTSTATUS NtOpenSection(
    HANDLE *SectionHandle,
    u32 DesiredAccess,
    OBJECT_ATTRIBUTES *ObjectAttributes
);
extern NTSTATUS NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    void **BaseAddress,
    unsigned long long ZeroBits,
    unsigned long long CommitSize,
    i64 *SectionOffset,
    SIZE_T *ViewSize,
    u32 InheritDisposition,
    u32 AllocationType,
    u32 Win32Protect
);
extern NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, void *BaseAddress);
extern NTSTATUS NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    void *BaseAddress,
    u32 MemoryInformationClass,
    void *MemoryInformation,
    SIZE_T MemoryInformationLength,
    SIZE_T *ReturnLength
);
extern NTSTATUS NtYieldExecution(void);
extern NTSTATUS NtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    void *ApcRoutine,
    void *ApcContext,
    IO_STATUS_BLOCK *IoStatusBlock,
    u32 IoControlCode,
    void *InputBuffer,
    u32 InputBufferLength,
    void *OutputBuffer,
    u32 OutputBufferLength
);
extern NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

static void init_unicode_string(UNICODE_STRING *out, u16 *buffer) {
    u32 len = 0;
    while (buffer[len] != 0) {
        len++;
    }
    out->Length = (u16)(len * 2);
    out->MaximumLength = (u16)(len * 2 + 2);
    out->Buffer = buffer;
}

static NTSTATUS write_console(HANDLE out, const char *text) {
    IO_STATUS_BLOCK iosb;
    u64 len = 0;
    while (text[len] != 0) {
        len++;
    }
    return NtWriteFile(out, 0, NULL, NULL, &iosb, text, len, NULL, NULL);
}

static HANDLE query_stdout(void) {
    PROCESS_BASIC_INFORMATION pbi;
    u32 ret_len = 0;
    NTSTATUS status = NtQueryInformationProcess(
        (HANDLE)-1,
        PROCESS_BASIC_INFORMATION_CLASS,
        &pbi,
        (u32)sizeof(pbi),
        &ret_len
    );
    if (status != STATUS_SUCCESS) {
        return 0;
    }
    PEB *peb = (PEB *)pbi.PebBaseAddress;
    return peb->ProcessParameters->StandardOutput;
}

void start(void) {
    static u16 init_path[] = {
        '\\','S','y','s','t','e','m','R','o','o','t','\\','S','y','s','t','e','m','3','2','\\',
        'i','n','i','t','.','e','x','e',0
    };
    static u16 child_path[] = {
        '\\','S','y','s','t','e','m','R','o','o','t','\\','S','y','s','t','e','m','3','2','\\',
        'c','h','i','l','d','.','e','x','e',0
    };
    static u16 known_dll_path[] = {
        '\\','K','n','o','w','n','D','l','l','s','\\','n','t','d','l','l','.','d','l','l',0
    };

    HANDLE stdout_handle = query_stdout();
    HANDLE file = 0;
    HANDLE event = 0;
    HANDLE known_dll = 0;
    HANDLE child_process = 0;
    HANDLE child_thread = 0;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES attrs;
    UNICODE_STRING path;
    UNICODE_STRING child_us;
    UNICODE_STRING known_dll_us;
    char buffer[96];
    long previous_state = 0;
    NTSTATUS status;
    RTL_USER_PROCESS_PARAMETERS child_params;
    i64 system_time_before = 0;
    i64 system_time_after = 0;
    i64 delay_interval = -100000;
    void *mapped_base = NULL;
    SIZE_T mapped_size = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T mbi_len = 0;

    init_unicode_string(&path, init_path);
    init_unicode_string(&known_dll_us, known_dll_path);
    attrs.Length = (u32)sizeof(attrs);
    attrs.RootDirectory = 0;
    attrs.ObjectName = &path;
    attrs.Attributes = 0x40;
    attrs.SecurityDescriptor = NULL;
    attrs.SecurityQualityOfService = NULL;

    write_console(stdout_handle, "native init: starting\r\n");

    status = NtQuerySystemTime(&system_time_before);
    if (status == STATUS_SUCCESS) {
        status = NtDelayExecution(0, &delay_interval);
        if (status == STATUS_SUCCESS && NtQuerySystemTime(&system_time_after) == STATUS_SUCCESS &&
            system_time_after >= system_time_before) {
            write_console(stdout_handle, "native init: time query/delay succeeded\r\n");
        }
    }

    attrs.ObjectName = &known_dll_us;
    status = NtOpenSection(&known_dll, 0x000f001fu, &attrs);
    if (status == STATUS_SUCCESS) {
        status = NtMapViewOfSection(
            known_dll,
            (HANDLE)-1,
            &mapped_base,
            0,
            0,
            NULL,
            &mapped_size,
            1,
            0,
            0x20
        );
        if (status == STATUS_SUCCESS && mapped_base != NULL &&
            ((u8 *)mapped_base)[0] == 'M' && ((u8 *)mapped_base)[1] == 'Z') {
            write_console(stdout_handle, "native init: known dll section map succeeded\r\n");
        }
        status = NtQueryVirtualMemory(
            (HANDLE)-1,
            mapped_base,
            MEMORY_BASIC_INFORMATION_CLASS,
            &mbi,
            sizeof(mbi),
            &mbi_len
        );
        if (status == STATUS_SUCCESS && mbi.State == MEM_COMMIT && mbi.RegionSize != 0) {
            write_console(stdout_handle, "native init: query virtual memory succeeded\r\n");
        }
        if (mapped_base != NULL) {
            NtUnmapViewOfSection((HANDLE)-1, mapped_base);
        }
        NtClose(known_dll);
    }

    attrs.ObjectName = &path;

    status = NtCreateFile(
        &file,
        FILE_GENERIC_READ,
        &attrs,
        &iosb,
        NULL,
        0,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (status == STATUS_SUCCESS) {
        status = NtReadFile(file, 0, NULL, NULL, &iosb, buffer, sizeof(buffer) - 1, NULL, NULL);
        if (status == STATUS_SUCCESS || status == STATUS_END_OF_FILE) {
            buffer[iosb.Information < sizeof(buffer) - 1 ? iosb.Information : sizeof(buffer) - 1] = 0;
            write_console(stdout_handle, "native init: opened image path successfully\r\n");
        }
        NtClose(file);
    } else {
        write_console(stdout_handle, "native init: NtCreateFile failed\r\n");
    }

    init_unicode_string(&child_us, child_path);
    child_params.Length = (u32)sizeof(child_params);
    child_params.MaximumLength = (u32)sizeof(child_params);
    child_params.Flags = 0;
    child_params.DebugFlags = 0;
    child_params.ConsoleHandle = 0;
    child_params.StandardInput = 0;
    child_params.StandardOutput = stdout_handle;
    child_params.StandardError = stdout_handle;
    child_params.ImagePathName = child_us;
    child_params.CommandLine = child_us;

    status = NtCreateUserProcess(
        &child_process,
        &child_thread,
        0x001fffffu,
        0x001fffffu,
        NULL,
        NULL,
        0,
        0,
        &child_params,
        NULL,
        NULL
    );
    if (status == STATUS_SUCCESS) {
        i64 poll_timeout = 0;
        NTSTATUS poll = NtWaitForSingleObject(child_process, 0, &poll_timeout);
        if (poll == STATUS_TIMEOUT) {
            write_console(stdout_handle, "native init: child poll timed out as expected\r\n");
        }
        status = NtWaitForSingleObject(child_process, 0, NULL);
        if (status == STATUS_SUCCESS) {
            write_console(stdout_handle, "native init: child process completed\r\n");
        } else {
            write_console(stdout_handle, "native init: child wait failed\r\n");
        }
        NtClose(child_thread);
        NtClose(child_process);
    } else {
        write_console(stdout_handle, "native init: NtCreateUserProcess failed\r\n");
    }

    status = NtCreateEvent(&event, 0x1f0003u, NULL, EVENT_TYPE_NOTIFICATION, 0);
    if (status == STATUS_SUCCESS) {
        NtSetEvent(event, &previous_state);
        status = NtResetEvent(event, &previous_state);
        if (status == STATUS_SUCCESS && previous_state != 0) {
            write_console(stdout_handle, "native init: reset event succeeded\r\n");
        }
        NtSetEvent(event, &previous_state);
        status = NtWaitForSingleObject(event, 0, NULL);
        if (status == STATUS_SUCCESS) {
            write_console(stdout_handle, "native init: event round-trip succeeded\r\n");
        } else {
            write_console(stdout_handle, "native init: event wait failed\r\n");
        }
        NtClose(event);
    }

    status = NtYieldExecution();
    if (status == STATUS_SUCCESS) {
        write_console(stdout_handle, "native init: yield execution succeeded\r\n");
    }

    status = NtDeviceIoControlFile(
        stdout_handle,
        0,
        NULL,
        NULL,
        &iosb,
        0,
        NULL,
        0,
        NULL,
        0
    );
    if (status == STATUS_INVALID_DEVICE_REQUEST) {
        write_console(stdout_handle, "native init: ioctl unsupported as expected\r\n");
    }

    write_console(stdout_handle, "native init: exiting\r\n");
    NtTerminateProcess((HANDLE)-1, 0);
    for (;;) {}
}
