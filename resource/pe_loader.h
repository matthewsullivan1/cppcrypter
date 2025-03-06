#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include "globals.h"
#include "dll_utils.h"
#include "utils.h"

void* load_pe(PIMAGE_NT_HEADERS ntHeaders, const std::vector<unsigned char>& data);
void relocate_pe(PIMAGE_NT_HEADERS ntHeaders, void* baseAddress);
bool resolve_imports(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders);
HMODULE map_dll(const char* dllName);
void* resolve_addr(HMODULE hModule, const char* name, DWORD hash);
void execute_tls(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders);



#endif PE_LOADER_H