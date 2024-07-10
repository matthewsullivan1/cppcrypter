#Disclaimer

This project is intended for educational and research purposes only. The tools and techniques demonstrated here are designed to improve understanding of reverse engineering and malware analysis concepts, and to help in developing defensive measures against malicious software. 

**Use responsibly**: This software must not be used for malicious or illegal purposes. Any misuse of the information provided and the code available in this repository is solely the responsibility of the user. The author is not responsible for any direct or indirect damage caused by the use or misuse of this software.

By using this software, you agree to abide by all applicable local, state, and federal laws and regulations.
   
#Usage
##main.cpp
make main.exe: compiles main program
./main.exe [args]: encrypts and embeds payload into stub_\*.cpp, written to /stub
make clean: deletes main.exe, clears /stub and /out directories
##Flags
-h --help: display all flags
-p: display paths for payload, stub output dir, stub template, and exit
-n <name>: set a name for the stub. output will be stub_name.cpp/exe
-c --compile: compile stub immediately. makefile must be configured properly 
--payload <C:\Path\To\Payload>: specify payload. first exe found in /bin will be used by default 
##Obfuscation flags 
--rand: adds two random memory allocations before payload is executed 
--vm: checks if the application is being ran in a virtual machine, and exits if so
--db: checks if the application is being ran in a debugger, and exits if so
--dyn: dynamically resolves certain Windows API calls at runtime
stub_\*.cpp
make stub: compiles each stub_*.cpp in /stub. stub_*.exe is placed in /out

