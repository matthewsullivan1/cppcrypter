#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <windows.h>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

void resolveFuncPointers(DWORD *hashes, HMODULE handle);
DWORD getHashFromString(const char *string);
std::vector<unsigned char> decrypt(const std::vector<unsigned char> &buf, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv);

#endif UTILS_H