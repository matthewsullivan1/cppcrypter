#ifndef CONFIG_H
#define CONFIG_H


#include <string>

struct Config
{
    bool help = false;
    bool rand = false;
    bool db = false;
    bool vm = false;
    bool dyn = false;
    bool compile = false;
    bool pdb = false;
    bool name = false;
    bool paths = false;
    
    bool payload = false;
    bool stub = false;
    bool out = false;


    std::string payload_path = "./bin/";
    std::string stub_path = "./resource/stub_template.cpp";
    std::string output_dir = "./out/";
    std::string stub_name;
};

#endif // CONFIG_H