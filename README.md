# Disclaimer

This project is intended for educational and research purposes only. The tools and techniques demonstrated here are designed to improve understanding of reverse engineering and malware analysis concepts, and to help in developing defensive measures against malicious software. 

**Use responsibly**: This software must not be used for malicious or illegal purposes. Any misuse of the information provided and the code available in this repository is solely the responsibility of the user. The author is not responsible for any direct or indirect damage caused by the use or misuse of this software.

By using this software, you agree to abide by all applicable local, state, and federal laws and regulations.
   
The default payload search path in main is in /bin, so any 64 bit executable payload should be placed there. This is done automatically if the payload is built using the TARGET_PL Makefile rule. The stub template that the complete stub is built from is in /resource, and the compiled stubs are placed in /out. When using additional options for the stub, the same template is always used and the additional options are written in using commented placeholders in the template. 

Project Directory Structure
    bin - binaries of payloads. Default search path when using --payload flag
    include - contains openssl header files needed for compilation
    lib - contains openssl libraries needed for linking
    out - default output directory for compiled stubs
    resource - contains stub template file and payload source files
    src - contains main source files 

Usage: 
    1. Initial Setup
        - Compile main program
            make main.exe
        - main.exe will be placed in the base project directory. For help:
            ./main.exe --help 
            ./main.exe -h

    2. Building Payload
        - Update the Makefile variable PL_SRC to point to the payload.cpp source file in /resource
        - Update any g++ flags needed for compiling the payload in PL_FLAGS 
        - The source file for the payload should be in /resource
            make bin/payload.exe
        - payload.exe will be compiled and placed in /bin



    3. Building a Stub with no Flags
        - When main.exe is run with no flags, it will look for a payload 'bin.exe' in /bin
            ./main.exe
        - The resulting stub source file will be written to /stub as stub_*.cpp
            - Note: Sometimes the stub does not write out properly. Simply rename it with .cpp or rerun main.exe. 

        - The stub can be compiled using
            make stub           (to build every stub_*.cpp)
            make stub_*.exe     (to build a specific stub)
        - The compiled stub.exe(s) will be in /out


    4. Additional Flags
        - To compile the stub in the same run that the source is written, use -c
            ./main.exe -c 

        - To specify a payload that isn't bin.exe, use --payload 
            ./main.exe --payload pl.exe
            ./main.exe --payload "C:\\Users\\local\\Desktop\\pl.exe"
        - Either the full path or the name of the payload in /bin can be used

        - Currently, these are the additional options for stub obfuscation
            --rand  :   adds two random memory allocations between 50-100mb, and verifies that malloc() succeeded on both before executing the payload. Also changes names 
