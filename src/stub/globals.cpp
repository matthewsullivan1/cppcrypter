#include "globals.h"

// Define global function pointers
NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = NULL;
NtProtectVirtualMemory_t pNtProtectVirtualMemory = NULL;
NtCreateThreadEx_t pNtCreateThreadEx = NULL;

PEB* get_peb() {
    return (PEB*)__readgsqword(0x60);  
}
// Define loaded DLLs map
std::unordered_map<std::string, HMODULE> loadedDlls;
