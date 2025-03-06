#ifndef GLOBALS_H
#define GLOBALS_H

#include <windows.h>
#include <unordered_map>
#include <string>
#include <winternl.h>

// Define function pointer typedefs
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG
);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
);

// Global function pointers
extern NtAllocateVirtualMemory_t pNtAllocateVirtualMemory;
extern NtProtectVirtualMemory_t pNtProtectVirtualMemory;
extern NtCreateThreadEx_t pNtCreateThreadEx;

typedef struct _LDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_EX, *PLDR_DATA_TABLE_ENTRY_EX;

PEB* get_peb();

// Global map to track loaded DLLs
extern std::unordered_map<std::string, HMODULE> loadedDlls;
#define CURRENT_PROCESS_HANDLE ((HANDLE)-1)

#endif // GLOBALS_H
