// main.cpp
#include "utils.h"
#include "flags.h"
#include "constant.h"

#include <iostream>
#include <cstring>
// #include <string>
// #include <vector>
// #include <openssl/aes.h>
// #include <openssl/rand.h>
#include <fstream>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

bool flags[FLAG_COUNT] = {false};

void displayHelp(const int COLOR){
    setColor(COLOR);
    cout << "\nUsage: ./main.exe [options]\nOptions:\n";
    cout << "\t-h, --help                 show all options, and exit\n";
    cout << "\t-p                         display paths for payload, stub output directory, stub template, and exit\n";
    cout << "\t-c, --compile              compile generated stub immediately. makefile must be configured properly\n";
    cout << "\t--payload <C:\\\\path>       specify payload. first exe in ./bin will be used otherwise\n";
    cout << "\t--stub <C:\\\\stub>          specify stub template. by default /resource/stub.cpp is used\n";
    cout << "\t--rand                     enable random memory allocations\n";
    cout << "\t--vm                       enable anti-VM mode\n";
    cout << "\t--db                       enable anti-debugger mode\n";
    cout << "\t--dyn                      enable dynamic API call resolution\n";
    cout << "\t--pdb                      enable print debugging mode on stub\n";
    cout << "\tFlags cannot be combined\n";
    resetColor();
}

void parseArgs(int argc, char* argv[], string *path_to_payload, string *path_to_output_dir, string *path_to_stub_template){
    string tmpPl = *path_to_payload;

    resetColor();
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            flags[HELP] = true;
            return;

        } else if(strcmp(argv[i], "-p") == 0){
            flags[PATH] = true;
            return;

        } else if(strcmp(argv[i], "--payload") == 0){
            if(i + 1 >= argc){
                setColor(COLOR_ERROR);
                cerr << "No path to payload specified\n\tUsage: ./main --payload \"C:\\\\path\\\\to\\\\payload\"\n";
                displayHelp(COLOR_ERROR);
                exit(1);
            }
            if(!filesystem::exists(argv[i+1])){
                setColor(COLOR_ERROR);
                cerr << "Invalid payload path: " << argv[i+1] << "\n";
                displayHelp(COLOR_ERROR);
                exit(1);
            } else if (!filesystem::is_regular_file(argv[i+1])){
                setColor(COLOR_ERROR);
                cerr << "Invalid payload path: " << argv[i+1] << "\n";
                displayHelp(COLOR_ERROR);
                exit(1);
            } else {
                flags[PAYLOAD] = true;
                *path_to_payload = argv[i+1];
                continue;
            }
        } else if(strcmp(argv[i], "--stub") == 0){
            if(i + 1 >= argc){
                setColor(COLOR_ERROR);
                cerr << "No path to stub specified\n\tUsage: ./main --stub \"C:\\\\path\\\\to\\\\stub\"\n";
                //displayHelp(COLOR_ERROR);
                exit(1);
            }
            if(!filesystem::exists(argv[i+1])){
                setColor(COLOR_ERROR);
                cerr << "Invalid stub path: " << argv[i+1] << "\n";
                //displayHelp(COLOR_ERROR);
                exit(1);
            } else if (!filesystem::is_regular_file(argv[i+1])){
                setColor(COLOR_ERROR);
                cerr << "Invalid stub path: " << argv[i+1] << "\n";
                displayHelp(COLOR_ERROR);
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
        } else if(strcmp(argv[i], "--pdb") == 0){
            flags[PDB] = true;
            continue;
        }
    }

    // /bin has already been checked, if no payload is specified using --payload, search /bin for the first .exe
    if (tmpPl == *path_to_payload) {
        setColor(COLOR_INFO);
        cout << "searching ./bin...\n";
        if (fs::exists("./bin") && fs::is_directory("./bin")) {
            for (const auto& entry : fs::directory_iterator("./bin")) {
                if (fs::is_regular_file(entry) && ((entry.status().permissions() & fs::perms::owner_exec) != fs::perms::none ||
                                                   (entry.status().permissions() & fs::perms::group_exec) != fs::perms::none ||
                                                   (entry.status().permissions() & fs::perms::others_exec) != fs::perms::none)) {
                    *path_to_payload = entry.path().string();
                    setColor(COLOR_SUCCESS);
                    cout << "Found " << *path_to_payload << "\n";
                    resetColor();
                    return;
                }
            }
            setColor(COLOR_ERROR);
            cerr << "No exe found in ./bin. Move payload to ./bin or specify full path with --payload\n";
            resetColor();
            exit(1);
        }
    }
}

void displayOptions(string *path_to_payload, string *path_to_output_dir, string *path_to_stub_template){
    if(flags[HELP]==true){
        displayHelp(COLOR_INFO);
        exit(0);
    }
    if(flags[PATH]==true){
        setColor(COLOR_INFO);
        cout << "Paths:\n\tPath to payload: " << *path_to_payload << "\n\tPath to output directory: " << *path_to_output_dir << "\n\tPath to stub template: " << *path_to_stub_template << "\n";
        resetColor();
        exit(0);
    }
    if(flags[COMPILE]==true){
        resetColor();
        cout << "Compilation enabled\n";
    }
    if(flags[PAYLOAD]==true){
        resetColor();
        cout << "Payload set to: " << *path_to_payload << "\n";
    }
    if(flags[RAND]==true){
        resetColor();
        cout << "Stub randomization mode enabled\n";
    }
    if(flags[VM]==true){
        resetColor();
        cout << "Anti-VM mode enabled\n";
    }
    if(flags[DB]==true){
        resetColor();
        cout << "Anti-Debugger mode enabled\n";
    }
    if(flags[DYN]==true){
        resetColor();
        cout << "Dynamic API call resolution enabled\n";
    }    
}

int main(int argc, char * argv[]){

    fs::path executable_path = fs::absolute(argv[0]);
    fs::path base_path = executable_path.parent_path().parent_path()/"cppcrypter";  // Assuming the executable is two levels deep from the base path

    // Path to payload is initially just the directory where any payload should be placed
    // If no payload is specified with --payload, /bin will be iterated through for an exe
    // which is why /bin needs to exist first before moving forward
    // stub template has an option but its not completely ne
    string path_to_payload = (base_path / "bin").string();
    string path_to_output_dir = (base_path / "stub").string() + "\\";
    string path_to_stub_template = (base_path / "resource\\stub.cpp").string();

    // Make sure the defaults exist before parsing arguments
    setColor(COLOR_ERROR);
    if(!filesystem::exists(path_to_payload)){
        cerr << "./bin directory not found\n";
        resetColor();
        exit(1);
    }
    if(!filesystem::exists(path_to_output_dir)){
        cerr << "./out directory not found\n";
        resetColor();
        exit(1);
    }
    if(!filesystem::exists(path_to_stub_template)){
        cout << "./resource/stub.cpp not found\n";
        exit(1);
    }
    resetColor();

    parseArgs(argc, argv, &path_to_payload, &path_to_output_dir, &path_to_stub_template);
    displayOptions(&path_to_payload, &path_to_output_dir, &path_to_stub_template);

    // reading bytes of payload
    vector<unsigned char> buf = readBinary(path_to_payload);
    if(buf.empty()){
        setColor(COLOR_ERROR);
        cerr << "could not read binary\n";
        resetColor();
        exit(1);
    }

    // key and IV gen
    auto [key, iv] = generateKeyAndIV(LEN, LEN);
    vector<unsigned char> payloadBytes = encrypt(buf, key, iv);
    writeStub(flags, path_to_stub_template, path_to_output_dir, payloadBytes, key, iv);

    return 0;
}
