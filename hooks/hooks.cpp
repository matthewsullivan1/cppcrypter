#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>




/*
Pre hash NtAllocateVirtualMemory, NtCreateThreadEx, LdrLoadDll
Get ntdll.dll base address
Parse headers to find export directory
For each function, check if the hashed name matches a target hash
    On a match, read in the copy to a buffer. This is the copy of the function that will be used if called
        Need to compute the difference between the next function address and the target function address, to get the size of the function
After iterating through each function, read a copy of ntdll.dll from disk (C:\Windows\System32\ntdll.dll)
    (using manual GetModuleHandle)
Follow the same process, read a copy of the function into a buffer 

Compare functions to detect hooks

To remove the hooks, we need to update the permissions of the region starting at the base address of the function
Write the clean copy 
Update memory protections
Call function normally




*/
using namespace std;

typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle, //in
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, //optional
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument, //optional
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList //optional
); 

typedef NTSTATUS (NTAPI* LdrLoadDll_t)(
    PWCHAR PathToFile, //optional ? online said this will cause an exception access violation
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
);

/*
void* NtAllocateVirtualMemory = nullptr;
void* NtCreateThreadEx = nullptr;
void* LdrLoadDll = nullptr;
*/

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

void* resolveAddr(HMODULE hModule, const char* name, DWORD hash){
    auto dos_header = (PIMAGE_DOS_HEADER)hModule;
    auto nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos_header->e_lfanew);
    auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + export_dir_rva);
    auto num = export_dir->NumberOfFunctions;
    cout << "Number of names: " << num << endl;

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



                /*
                TODO : print prologues for demonstration 
                    NOTE: LdrLoadDll might have relative jumps, so copying the clean version from disk might not work
                
                */
                //DWORD next_rva = functions[ordinal+1];



                return ((BYTE*)hModule + fn_rva);
            }
        }

    }
    cout << "Failed to resolve address for:\nHash:" << hash << "\nname:" << name << endl;
    return nullptr;
}




NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = nullptr;
NtCreateThreadEx_t pNtCreateThreadEx = nullptr;
LdrLoadDll_t pLdrLoadDll = nullptr;

void resolveFuncPointers(DWORD *hashes, HMODULE handle){
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)resolveAddr(handle, 0, hashes[0]);
    pNtCreateThreadEx = (NtCreateThreadEx_t)resolveAddr(handle, 0, hashes[1]);
    pLdrLoadDll = (LdrLoadDll_t)resolveAddr(handle, 0, hashes[2]);

    void* realNtAVM = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    void* realNtCTE = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    void* realLLD = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");

    printf("pNtAllocateVirtualMemory: %p : %p\n", pNtAllocateVirtualMemory, realNtAVM);
    printf("pNtCreateThreadEx: %p : %p\n", pNtCreateThreadEx, realNtCTE);
    printf("pLdrLoadDll: %p : %p\n", pLdrLoadDll, realLLD);
}
/*
Codes 
    NtAllocateVirtualMemory : 18 (same)
    NtCreateThread : 4e
    LdrLoadDll : 





*/

void checkNtdll(HMODULE ntdll, const char*){
	PDWORD functionAddress = (PDWORD)0;
	
	// Get ntdll base address
	//HMODULE libraryBase = LoadLibraryA("ntdll");
    HMODULE libraryBase = LoadLibraryA("ntdll");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	// Locate export address table
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Offsets to list of exported functions and their names
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions of ntdll
	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
	{
		// Resolve exported function name
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		
		// Resolve exported function address
		DWORD_PTR functionAddressRVA = 0;
		functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

		// Syscall stubs start with these bytes
		unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

		// Only interested in Nt|Zw functions
		if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0)
		//if (strncmp(functionName, (char*)"NtAllocateVirtualMemory", 23) == 0)
        {
			
        //cout << "Checking "<< functionName << endl;
        // Check if the first 4 instructions of the exported function are the same as the sycall's prologue
        if (memcmp(functionAddress, syscallPrologue, 4) != 0) {

            unsigned char firstByte = *((unsigned char*)functionAddress);

            if(firstByte == 0xE9){
                DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));
                PDWORD jumpTarget = functionAddress + 5;
                char moduleNameBuffer[512];
                GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
                
                printf("Hooked with relative jump: %s : %p into module %s\n", functionName, functionAddress, moduleNameBuffer);
            } else if (firstByte == 0x48 && *((unsigned char*)functionAddress + 1) == 0xB8) {
                // Check for mov rax, <address>
                void* hookAddress = *(void**)((char*)functionAddress + 2);
                printf("Hooked with absolute JMP via rax: %s : %p, Hook Address: %p\n", functionName, functionAddress, hookAddress);
            } else {
                // Unusual prologue, potentially hooked
                printf("Potentially hooked: %s : %p\n", functionName, functionAddress);
            }
			

                /*
				if (*((unsigned char*)functionAddress) == 0xE9) // first byte is a jmp instruction, where does it jump to?
				{
					DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));
					PDWORD jumpTarget = functionAddress + 5  + jumpTargetRelative; //Instruction pointer after our jmp instruction  
					char moduleNameBuffer[512];
					GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
					
					printf("Hooked: %s : %p into module %s\n", functionName, functionAddress, moduleNameBuffer);
				}
				else
				{
					printf("Potentially hooked: %s : %p\n", functionName, functionAddress);
				}
                */
			}
		}
	}
}

int main()
{
    cout << "inject dll\n";
    cin.get();

    HMODULE ntdll = get_dll_base(L"ntdll.dll");
    if(!ntdll){
        cerr << "Failed to get ntdll.dll base" << endl;
        return 1;
    }
    cout << "ntdll.dll base: " << hex << ntdll << endl;

    cout << getHashFromString("NtAllocateVirtualMemory") << endl;
    cout << getHashFromString("NtCreateThreadEx") << endl;
    cout << getHashFromString("LdrLoadDll") << endl;

    DWORD hashes[3] = {0xafacbb9d, 0x87b688c5, 0x40a18b0d};

    resolveFuncPointers(hashes, ntdll);

    /*
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)resolveAddr(ntdll, 0, hashes[0]);
    NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)resolveAddr(ntdll, 0, hashes[1]);
    LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)resolveAddr(ntdll, 0, hashes[2]);
    */

    HANDLE processHandle = GetCurrentProcess();
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;
    ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_READWRITE;

    NTSTATUS status = pNtAllocateVirtualMemory(
        processHandle,
        &baseAddress,
        0,
        &regionSize,
        allocationType,
        protect
    );

    // Print the results after the call
    if (status == 0 /* STATUS_SUCCESS */) {
        std::cout << "Memory allocated successfully.\n";
        std::cout << "Base Address: " << baseAddress << "\n";
        std::cout << "Requested Region Size: 0x" << std::hex << regionSize << "\n";

        // Query the memory region to verify the actual size and protection
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQuery(baseAddress, &memInfo, sizeof(memInfo))) {
            std::cout << "Allocated Region Size: 0x" << std::hex << memInfo.RegionSize << "\n";
            std::cout << "Memory State: " << memInfo.State << " (Commit: " << MEM_COMMIT << ")\n";
            std::cout << "Memory Protection: 0x" << std::hex << memInfo.Protect << "\n";
        } else {
            std::cerr << "Failed to query allocated memory.\n";
        }
    } else {
        std::cerr << "NtAllocateVirtualMemory failed with status: 0x" << std::hex << status << "\n";
    }
    if(baseAddress){
        VirtualFree(baseAddress, 0, MEM_RELEASE);
    }



	return 0;
}