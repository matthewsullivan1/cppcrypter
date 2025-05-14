#include "dll_utils.h"

using namespace std;

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