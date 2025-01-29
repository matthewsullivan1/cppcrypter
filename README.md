# Overview
Encrypts a 64-bit Windows Portable Executable payload and writes it to a stub, which when ran decrypts and executes the payload in memory using a manual mapping PE injection technique. Contains four additional options to make static and dynamic analysis more difficult. 
# Usage

## `main.cpp`

- **`make main.exe`** → Compiles main.cpp and dependencies (crypter)
- **`./main.exe [args]`** → Encrypts and embeds the payload into `stub_*.cpp`, output is written to `/stub`
- **`make clean`** → Deletes `main.exe`, clears `/stub` and `/out` directories

### Flags

- `-h, --help` → Display all flags
- `-p` → Show paths for the payload, stub output directory, and stub template
- `-n <name>` → Set a name for the stub (output will be `stub_name.cpp/exe`)
- `-c, --compile` → Compile stub immediately after writing (Makefile must be configured properly)
- `--payload <C:\Path\To\Payload>` → Specify payload (default: first `.exe` found in `/bin`)

### Obfuscation Flags

- `--rand` → Adds two random memory allocations before payload execution
- `--vm` → Checks registry keys that indicate a VirtualBox, Hyper-V, or VMware environment and exits if any are detected before payload execution
- `--db` → Checks if the stub is running in a debugger and exits if so
- `--dyn` → Dynamically resolves Windows API calls from kernel32.dll at runtime

## `stub_*.cpp`

- **`make stub`** → Compiles each `stub_*.cpp` in `/stub`
- **Output:** `stub_*.exe` is placed in `/out`

# Disclaimer

This project is intended for educational and research purposes only. The tools and techniques demonstrated here are designed to improve understanding of reverse engineering and malware analysis concepts, and to help in developing defensive measures against malicious software. 

**Use responsibly**: This software must not be used for malicious or illegal purposes. Any misuse of the information provided and the code available in this repository is solely the responsibility of the user. The author is not responsible for any direct or indirect damage caused by the use or misuse of this software.

By using this software, you agree to abide by all applicable local, state, and federal laws and regulations.
