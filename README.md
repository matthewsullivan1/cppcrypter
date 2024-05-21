usage:
    update procinj.cpp with new PID of 64 bit process to inject shellcode into
    make bin/procinj.exe
    make main.exe(if not built already)
    make stub.exe - sometimes random name gen will mess up - just run main again 

main:
    By default, the 'stub' directory is the output directory for the stub source file that main generates, and where the stub is compiled to with the makefile. Bin is the default directory where a binaries to pack should be placed. lib and include both contain openssl headers and libraries for static linking. 

stub:
    