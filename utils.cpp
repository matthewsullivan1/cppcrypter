#include "utils.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <filesystem>
#include <random>

using namespace std;

string bytesToHexString(const vector<unsigned char>& bytes) {
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
vector<unsigned char> readBinary(string& path_to_payload) {
    ifstream file(path_to_payload, ios::binary | ios::ate);
    if (!file) {
        cerr << "could not open binary\n";
        return {};
    }

    streamsize len = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buf(len);
    if (!file.read(buf.data(), len)) {
        std::cerr << "error reading the binary\n";
        return {};
    }

    file.close();
    
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

vector<unsigned char> encrypt(const vector<unsigned char>& buf, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if (!ctx) {
        cerr << "Error creating context!" << endl;
        exit(1);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "Error initializing encryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> ciphertext(buf.size());
    int len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "Error during encryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}


vector<unsigned char> decrypt(const vector<unsigned char>& buf, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating context!" << endl;
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "Error initializing decryption!" << endl;
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


void writeStub(string& stubTemplatePath, string& outputDirPath, const vector<unsigned char>& payloadBytes, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
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

        outputFile << line << endl;
    }

    file.close();
    outputFile.close();

    cout << "\nSuccessfully wrote stub to: " << outputPath;
}