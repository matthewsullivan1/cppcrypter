#include "pe_loader.h"

using namespace std;

void* load_pe(PIMAGE_NT_HEADERS ntHeaders, const std::vector<unsigned char>& data){
    void* baseAddress = NULL;
    SIZE_T regionSize = (SIZE_T)ntHeaders->OptionalHeader.SizeOfImage;
    NTSTATUS status = pNtAllocateVirtualMemory(
        CURRENT_PROCESS_HANDLE,
        (PVOID*)&baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        cerr << "NtAllocateVirtualMemory failed with status: " << status << endl;
        return nullptr;
    }
    cout << "Memory allocation at: " << baseAddress << endl;

    memcpy(baseAddress, data.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        void* sectionDest = (void*)((BYTE*)baseAddress + section->VirtualAddress);
        void* sectionSrc = (void*)((BYTE*)data.data() + section->PointerToRawData);
        memcpy(sectionDest, sectionSrc, section->SizeOfRawData);
        cout << "Section " << section->Name << " copied to " << sectionDest << endl;
    }

    relocate_pe(ntHeaders, baseAddress);
    cout << "Resolving imports" << endl;
    if(!resolve_imports(baseAddress, ntHeaders)){
        cerr << "Failed to resolve imports" << endl;
        return NULL;
    }

    return baseAddress;
}

void relocate_pe(PIMAGE_NT_HEADERS ntHeaders, void* baseAddress){
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (relocation->VirtualAddress > 0) {
            uintptr_t delta = (uintptr_t)((BYTE*)baseAddress - ntHeaders->OptionalHeader.ImageBase);

            int count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocEntry = (PWORD)((BYTE*)relocation + sizeof(IMAGE_BASE_RELOCATION));
            for (int i = 0; i < count; i++, relocEntry++) {
                if (*relocEntry & 0xF000) {
                    uintptr_t* patchAddr = (uintptr_t*)((BYTE*)baseAddress + relocation->VirtualAddress + (*relocEntry & 0xFFF));
                    *patchAddr += delta;
                    //printf("Applying relocation at: %p, Original: %p, Patched: %p\n", patchAddr, *patchAddr, *patchAddr + delta);                 
                }
            }
            relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
        }
    }
    cout << "Relocations applied" << endl;
    return;/**/
}

bool resolve_imports(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders){
    if(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0){
        return true;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)mappedBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (importDescriptor->Name) {
        cout << "Resolving import " << importDescriptor->Name << endl;
        const char* dllName = (char*)((BYTE*)mappedBase + importDescriptor->Name);
        HMODULE module = NULL;
        // Same as earlier, check if its been seen, and will be processed eventually, then try and get a handle from the PEB
        // By the time this is called for the PE, all DLLs should have their handle in the loadedDlls map or be in the PEB
        auto it = loadedDlls.find(dllName);
        if(it != loadedDlls.end() && it->second != (HMODULE)0x1){
            cout << "Module found in loadedDlls" << endl;
            module = it->second;
        } else {
            wchar_t wDllName[MAX_PATH];
            MultiByteToWideChar(CP_UTF8, 0, dllName, -1, wDllName, MAX_PATH);
            module = get_dll_base(wDllName);

            if(!module){
                // Search for the module like LLA would
                module = map_dll(dllName);
                if(!module){
                    cerr << "Failed to map dependency " << dllName << endl;
                    return false;
                }
            } else {
                cout << "Module found in PEB" << endl;
            }
        }

        // Once the recursive calls hit a base case, patch the IAT for that DLL, work back up the callstack
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)mappedBase + importDescriptor->FirstThunk);
        while (thunk->u1.AddressOfData) {
            PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)mappedBase + thunk->u1.AddressOfData);
            FARPROC func = (FARPROC)resolve_addr(module, import->Name, 0);
            if (!func) {
                cerr << "Failed to get address of function: " << import->Name  << endl;
                return false;
            }
            
            thunk->u1.Function = (uintptr_t)func;
            thunk++;
        }
        importDescriptor++;
    }

    return true;
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
                if(strcmp(fn_name, "NtAllocateVirtualMemory") == 0 || strcmp(fn_name, "NtCreateThreadEx") == 0){
                    for(uint16_t j = 0; j < 21; j++){
                        cout << "0x" << (int)*((BYTE*)hModule + fn_rva + j) << " ";
                    }
                }

                return ((BYTE*)hModule + fn_rva);
            }
        }

    }
    cout << "Failed to resolve address for:\nHash:" << hash << "\nname:" << name << endl;
    return nullptr;
}


void execute_tls(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders){
    if(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0){
        PIMAGE_TLS_DIRECTORY tlsDir = (PIMAGE_TLS_DIRECTORY)((HMODULE)mappedBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tlsDir->AddressOfCallBacks;

        while(callback && *callback){
            (*callback)((LPVOID)mappedBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }

    }
}

// Need to check if the DLL has already been 'seen' and is up the recursion tree, or if its in the PEB 
// In both cases just return the handle to it 
// In any other case it needs to be read from disk, mapped into memory, and we need to recursively check its imports 
// Base case: DLL has no imports, can apply relocations, execute TLS callbacks, execute dllmain, return to caller
HMODULE map_dll(const char* dllName){
    cout << "Mapping " << dllName << endl;
    auto it = loadedDlls.find(dllName);
    if(it != loadedDlls.end()){
        cout << dllName << " found in loadedDlls" << endl;
        return it->second;
        // if the DLL name is found in loadDlls, return the base address (second field of each map entry)
    }
    loadedDlls[dllName] = (HMODULE)0x1; // Mark the DLL as loading

    // Convert dllName to wide char, check if its already loaded in the process, but hasnt been seen yet
    wchar_t wDllName[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, dllName, -1, wDllName, MAX_PATH);
    HMODULE module = get_dll_base(wDllName);

    // Return base and add to dll map 
    if(module){
        cout << dllName << " found in PEB" << endl;
        loadedDlls[dllName] = module;
        return module;
    }

    wchar_t dllPath[MAX_PATH];
    if(!findDllPath(dllName, dllPath, MAX_PATH)){
        cerr << "Failed to locate DLL: " << dllName << endl;
        return NULL;
    }

    // DLL was located, read from disk 
    vector<unsigned char> data = read_dll(dllPath);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);

    void* mappedBase = load_pe(ntHeaders, data);
    if(!mappedBase){
        cerr << "Failed to write DLL to address space" << endl;
        return NULL;
    }

    execute_tls(mappedBase, ntHeaders);

    typedef BOOL(WINAPI* DllEntry)(HINSTANCE, DWORD, LPVOID);
    DllEntry entry = (DllEntry)((BYTE*)mappedBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    entry((HINSTANCE)mappedBase, DLL_PROCESS_ATTACH, NULL);

    loadedDlls[dllName] = (HMODULE)mappedBase;

    return (HMODULE)mappedBase;
}