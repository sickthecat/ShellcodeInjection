# ShellcodeInjection
Blatantly stolen ideas!


# Probably garbage and untested.

Shoot me. 

Windows console application that takes two command-line arguments: the process ID of the target process and the filename of a file containing the shellcode to inject. It uses a combination of OpenProcess, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread to inject the specified shellcode into the target process. If any of these operations fail, the program prints an error message and returns a non-zero exit code. If everything succeeds, the program prints a success message and returns 0.
