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

void EnumerateMemoryRegions(DWORD processId) {
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;

    // dynamic array setup
    process_data* regions = NULL;
    size_t count = 0;
    size_t capacity = 0;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        printf("Failed to open process for enumeration\n");
        return;
    }

    printf("Memory regions for process %lu:\n", processId);
    printf("%-18s %-12s %-10s %-10s %-12s\n", "Base Address", "Size", "State", "Type", "Protection");
    printf("────────────────── ──────────── ────────── ────────── ─────────────\n");

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        uintptr_t pid_ptr = (uintptr_t)mbi.BaseAddress;
        uintptr_t pid_size = (uintptr_t)mbi.RegionSize;

        char pid_state[16] = "UNKNOWN";
        char pid_type[16] = "";
        char pid_protection[16] = "";

        switch (mbi.State) {
            case MEM_COMMIT:  strncpy(pid_state, "COMMIT", sizeof(pid_state)); break;
            case MEM_RESERVE: strncpy(pid_state, "RESERVE", sizeof(pid_state)); break;
            case MEM_FREE:    strncpy(pid_state, "FREE", sizeof(pid_state)); break;
        }

        switch (mbi.Type) {
            case MEM_IMAGE:   strncpy(pid_type, "IMAGE", sizeof(pid_type)); break;
            case MEM_MAPPED:  strncpy(pid_type, "MAPPED", sizeof(pid_type)); break;
            case MEM_PRIVATE: strncpy(pid_type, "PRIVATE", sizeof(pid_type)); break;
        }

        if (mbi.Protect & PAGE_EXECUTE_READWRITE)
            strncpy(pid_protection, "RWX", sizeof(pid_protection));
        else if (mbi.Protect & PAGE_EXECUTE_READ)
            strncpy(pid_protection, "RX", sizeof(pid_protection));
        else if (mbi.Protect & PAGE_READWRITE)
            strncpy(pid_protection, "RW", sizeof(pid_protection));
        else if (mbi.Protect & PAGE_READONLY)
            strncpy(pid_protection, "R", sizeof(pid_protection));
        else
            strncpy(pid_protection, "-", sizeof(pid_protection));

        printf("0x%016llX  0x%010llX  %-10s %-10s %-12s\n",
            (unsigned long long)pid_ptr,
            (unsigned long long)pid_size,
            pid_state,
            pid_type[0] ? pid_type : "-",
            pid_protection);

        // dynamically grow array
        if (count >= capacity) {
            capacity = capacity == 0 ? 16 : capacity * 2;
            regions = realloc(regions, capacity * sizeof(process_data));
            if (!regions) {
                fprintf(stderr, "Memory allocation failed.\n");
                CloseHandle(hProcess);
                return;
            }
        }

        // store the region
        regions[count].mem_ptr = pid_ptr;
        regions[count].mem_size = pid_size;
        strncpy(regions[count].mem_state, pid_state, sizeof(regions[count].mem_state));
        strncpy(regions[count].mem_type, pid_type, sizeof(regions[count].mem_type));
        strncpy(regions[count].mem_protection, pid_protection, sizeof(regions[count].mem_protection));
        count++;

        address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hProcess);

    // print summary
    printf("\nTotal regions stored: %zu\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("Region %3zu: 0x%016llX  size: 0x%010llX  %-8s  %-8s  %-6s\n",
            i,
            (unsigned long long)regions[i].mem_ptr,
            (unsigned long long)regions[i].mem_size,
            regions[i].mem_state,
            regions[i].mem_type,
            regions[i].mem_protection);
    }

    // cleanup
    free(regions);
}




int run() {
    DWORD processId;
    LPVOID targetAddress;
    SIZE_T readSize;
    
    printf("Simple Process Memory Reader\n");
    printf("============================\n\n");


    char process[] = "Notepad.exe";
    // Find Notepad process
    processId = FindProcessId(process);
    if (processId == 0) {
        printf("%s not found. Please start Notepad first.\n", process);
        printf("Press Enter to exit...");
        getchar();
        return 1;
    }
    
    printf("Found %s with PID: %lu\n", process, processId);
    
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
