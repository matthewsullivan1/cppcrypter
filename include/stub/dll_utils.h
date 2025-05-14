#ifndef DLL_UTILS_H
#define DLL_UTILS_H

#include "globals.h"  // Includes PEB struct
#include <shlwapi.h>

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


HMODULE get_dll_base(const wchar_t* name);


bool findDllPath(const char* dllName, wchar_t* outPath, size_t outSize);
std::vector<unsigned char> read_dll(const wchar_t* dllPath);

#endif