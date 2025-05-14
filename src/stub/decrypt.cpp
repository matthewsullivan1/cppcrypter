#include "decrypt.h"

using namespace std;

vector<unsigned char> decrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "error creating EVP context" << endl;
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "error initializing decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    vector<unsigned char> plaintext(buf.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "decryption call failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

EVP_CIPHER_CTX* create_ctx(){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        cerr << "Failed to create EVP cipher context" << endl;
        exit(1);
    }

    return ctx;
}

void d_init(EVP_CIPHER_CTX* ctx, const vector<unsigned char>& key, const vector<unsigned char>& iv, const vector<unsigned char>& buf){
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) != 1) {
        cerr << "error initializing decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
}


void d(EVP_CIPHER_CTX* ctx, const vector<unsigned char>& buf, vector<unsigned char> &plaintext){
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, buf.data(), buf.size()) != 1) {
        cerr << "decryption call failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
}

vector<unsigned char> routine(const vector<unsigned char> &buf, const vector<unsigned char>& key, const vector<unsigned char>& iv){
    EVP_CIPHER_CTX* ctx = create_ctx();
    
    vector<unsigned char> plaintext(buf.size());
    d_init(ctx, key, iv, buf);
    d(ctx, buf, plaintext);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

