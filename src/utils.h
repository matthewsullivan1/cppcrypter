// utils.h
#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#undef byte

#include <vector>
#include <string>
#include <utility>
#include <map>

using namespace std;

void setColor(const int COLOR);
void resetColor();
string bytesToHexString(const vector<unsigned char> &bytes);
string generateRandomString(size_t len);
DWORD getHashFromString(const char *string);

vector<unsigned char> readBinary(string &path_to_payload);

pair <vector<unsigned char>, vector<unsigned char>> generateKeyAndIV(size_t keySize, size_t ivSize);
vector<unsigned char> encrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv);
vector<unsigned char> decrypt(const vector<unsigned char> &buf, const vector<unsigned char> &key, const vector<unsigned char> &iv);
//
void replaceAPICalls(const string &filePath, const map<string, string> &replacements);
void writeStub(bool *flags, string &stub_name, string &stubTemplatePath, string &outputDirPath, const vector<unsigned char> &payloadBytes, const vector<unsigned char> &key, const vector<unsigned char> &iv);

#endif // UTILS_H
