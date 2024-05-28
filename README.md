Building
    - Update the Makefile build rule for building the payload
    - Build the main program
        make main.exe
    - Run main with any options to write the stub. The default payload main looks for is bin.exe in /bin, and the complete stub source file is written to /stub
        ./main.exe --help
            - Note: Sometimes the stub does not write out properly. Simply rename it with .cpp or rerun main.exe. 
    - Compile the stub
        make stub
    - The compiled stub will be placed in /out. 
The default payload search path is in /bin, so any 64 bit executable payload should be placed there. The default stub template that the complete stub is built from is in /resource, and the compiled stubs are placed in /out. When using additional options for the stub, the same template is always used and the additional options are written in using commented placeholders in the template. 



Disclaimer: 
