#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <utility>

using namespace std;


string bytesToHexString(const vector<unsigned char>& bytes);
string generateRandomString(size_t len);

vector<unsigned char> readBinary(string& path_to_payload);

pair <vector<unsigned char>, vector<unsigned char>> generateKeyAndIV(size_t keySize, size_t ivSize);

vector<unsigned char> encrypt(const vector<unsigned char>& buf, const vector<unsigned char>& key, const vector<unsigned char>& iv);
vector<unsigned char> decrypt(const vector<unsigned char>& buf, const vector<unsigned char>& key, const vector<unsigned char>& iv);

void writeStub(string& stubTemplatePath, string& outputDirPath, const vector<unsigned char>& payloadBytes, const vector<unsigned char>& key, const vector<unsigned char>& iv);

#endif // UTILS_H
