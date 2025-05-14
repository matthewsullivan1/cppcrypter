#ifndef RESOLVE_H
#define RESOLVE_H

#include <cstdint>
#include "globals.h"

DWORD getHashFromString(const char *string);
void* resolve_addr(HMODULE hModule, const char* name, DWORD hash);
void resolve_func_pointers(DWORD *hashes, HMODULE handle);

#endif