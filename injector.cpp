#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

int getProcessId(const wchar_t* target) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;  // Wide version of PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Enable SeDebugPrivilege
    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable SeDebugPrivilege!" << std::endl;
        return 0;
    }

    // Create a snapshot of running processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cerr << "Failed to create snapshot! Error: " << error << std::endl;
        return 0;
    }

    // Start process iteration
    if (!Process32FirstW(hSnap, &pe32)) {
        DWORD error = GetLastError();
        std::cerr << "Process32First failed! Error: " << error << std::endl;
        CloseHandle(hSnap);
        return 0;
    }

    // Loop through the processes
    do {
        // Use case-insensitive comparison to find the process
        if (_wcsicmp(pe32.szExeFile, target) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnap, &pe32));

    CloseHandle(hSnap);
    return pid;
}

int main(int argc, char* argv[]) {
    const wchar_t* process = L"osclient.exe";
    int pID = getProcessId(process);

    if (pID == 0) {
        std::cerr << "Process not found!" << std::endl;
        return 1;
    }

    char dll[] = "libBeginnerDLL.dll";
    char dllpath[MAX_PATH] = {0};

    if (!GetFullPathNameA(dll, MAX_PATH, dllpath, NULL)) {
        std::cerr << "Failed to get full DLL path!" << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(
     PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
     PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_DUP_HANDLE |
     PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME,
     FALSE,
     pID
 ); if (!hProcess) {
        std::cerr << "Failed to open process! Error: " << GetLastError() << std::endl;
        return 1;
    }

    LPVOID pszLibFileRemote = VirtualAllocEx(hProcess, NULL, strlen(dllpath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pszLibFileRemote) {
        std::cerr << "Failed to allocate memory in target process!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, pszLibFileRemote, dllpath, strlen(dllpath) + 1, NULL)) {
        std::cerr << "Failed to write DLL path to target process!" << std::endl;
        VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pszLibFileRemote, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread!" << std::endl;
        VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully!" << std::endl;
    return 0;
}
