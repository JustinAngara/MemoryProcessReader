#include "read_memory.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

// Function to find process ID by name
DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD processId = 0;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    
    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            processId = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return processId;
}

// Function to read memory from a process
BOOL ReadProcessMemoryRange(DWORD processId, LPVOID baseAddress, SIZE_T size) {
    HANDLE hProcess;
    BYTE* buffer;
    SIZE_T bytesRead;
    BOOL success = FALSE;
    
    // Open the target process
    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        printf("Failed to open process. Error: %lu\n", GetLastError());
        printf("Note: You may need to run as administrator\n");
        return FALSE;
    }
    
    // Allocate buffer for reading
    buffer = (BYTE*)malloc(size);
    if (buffer == NULL) {
        printf("Failed to allocate memory\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Read memory from the process
    if (ReadProcessMemory(hProcess, baseAddress, buffer, size, &bytesRead)) {
        printf("Successfully read %zu bytes from address 0x%p\n", bytesRead, baseAddress);

        // Display memory contents in hex format
        printf("Memory contents:\n");
        for (SIZE_T i = 0; i < bytesRead; i++) {
            if (i % 16 == 0) printf("\n0x%016llX: ", (unsigned long long)((uintptr_t)baseAddress + i));
            printf("%02X ", buffer[i]);
        }
        
        // Display as ASCII (printable characters only)
        printf("\n\nASCII representation:\n");
        for (SIZE_T i = 0; i < bytesRead; i++) {
            if (buffer[i] >= 32 && buffer[i] <= 126) {
                printf("%c", buffer[i]);
            } else {
                printf(".");
            }
        }
        printf("\n");
        
        success = TRUE;
    } else {
        printf("Failed to read memory. Error: %lu\n", GetLastError());
    }
    
    free(buffer);
    CloseHandle(hProcess);
    return success;
}

// function to enumerate memory regions
void EnumerateMemoryRegions(DWORD processId) {
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;
    
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        printf("Failed to open process for enumeration\n");
        return;
    }


    printf("This is the size %d", sizeof(mbi));
    printf("\nMemory regions for process %lu:\n", processId);
    printf("Base Address    Size        State       Type        Protection\n");
    printf("============    ========    ==========  ==========  ==========\n");

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        printf("0x%016llX  0x%08X  ", (unsigned long long)(uintptr_t)mbi.BaseAddress, (unsigned int)mbi.RegionSize);

        
        // Print state
        switch (mbi.State) {
            case MEM_COMMIT: printf("COMMIT      "); break;
            case MEM_FREE: printf("FREE        "); break;
            case MEM_RESERVE: printf("RESERVE     "); break;
            default: printf("UNKNOWN     "); break;
        }
        
        // Print type
        switch (mbi.Type) {
            case MEM_IMAGE: printf("IMAGE       "); break;
            case MEM_MAPPED: printf("MAPPED      "); break;
            case MEM_PRIVATE: printf("PRIVATE     "); break;
            default: printf("            "); break;
        }
        
        // Print protection
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) printf("RWX");
        else if (mbi.Protect & PAGE_EXECUTE_READ) printf("RX ");
        else if (mbi.Protect & PAGE_READWRITE) printf("RW ");
        else if (mbi.Protect & PAGE_READONLY) printf("R  ");
        else printf("   ");
        
        printf("\n");

        address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);

    }
    
    CloseHandle(hProcess);
}

int run() {
    DWORD processId;
    LPVOID targetAddress;
    SIZE_T readSize;
    
    printf("Simple Process Memory Reader\n");
    printf("============================\n\n");
    
    // Find Notepad process
    processId = FindProcessId("Notepad.exe");
    if (processId == 0) {
        printf("notepad.exe not found. Please start Notepad first.\n");
        printf("Press Enter to exit...");
        getchar();
        return 1;
    }
    
    printf("Found notepad.exe with PID: %lu\n", processId);
    
    // Show memory regions (optional)
    char choice;
    printf("\nWould you like to see memory regions? (y/n): ");
    scanf("%c", &choice);
    
    if (choice == 'y' || choice == 'Y') {
        EnumerateMemoryRegions(processId);
    }
    
    // Read specific memory address
    printf("\nEnter memory address to read (hex, e.g., 0x400000): ");
    scanf("%p", &targetAddress);
    
    printf("Enter number of bytes to read (e.g., 256): ");
    scanf("%zu", &readSize);
    
    if (readSize > 4096) {
        printf("Limiting read size to 4096 bytes for safety\n");
        readSize = 4096;
    }
    
    printf("\nAttempting to read %zu bytes from address 0x%p...\n", readSize, targetAddress);
    
    if (!ReadProcessMemoryRange(processId, targetAddress, readSize)) {
        printf("Memory read failed. This could be due to:\n");
        printf("- Insufficient privileges (try running as administrator)\n");
        printf("- Invalid memory address\n");
        printf("- Memory protection settings\n");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    getchar(); // Extra getchar to handle newline
    return 0;
}

// Compilation instructions:
// gcc -o memory_reader.exe memory_reader.c -lpsapi
// 
// Usage:
// 1. Start Notepad
// 2. Run this program as administrator
// 3. Follow the prompts to read memory