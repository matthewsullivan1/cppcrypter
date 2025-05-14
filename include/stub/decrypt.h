#ifndef DECRYPT_H
#define DECRYPT_H

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>

std::vector<unsigned char> decrypt(const std::vector<unsigned char> &buf, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv);
EVP_CIPHER_CTX* create_ctx();
void d_init(EVP_CIPHER_CTX* ctx, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& buf);
void d(EVP_CIPHER_CTX* ctx, const std::vector<unsigned char>& buf, std::vector<unsigned char> &plaintext);
std::vector<unsigned char> routine(const std::vector<unsigned char> &buf, const std::vector <unsigned char>& key, const std::vector<unsigned char>& iv);
std::vector<unsigned char> Xor(std::vector<unsigned char> &encrypted, uint16_t key);

#endif