#ifndef DLL_UTILS_H
#define DLL_UTILS_H

#include <windows.h>
#include <iostream>
#include <vector>
#include "globals.h"
#include <shlwapi.h>  // For PathFileExists

std::vector<unsigned char> read_dll(const wchar_t* dllPath);
HMODULE get_dll_base(const wchar_t* name);
bool findDllPath(const char* dllName, wchar_t* outPath, size_t outSize);

#endif DLL_UTILS_H