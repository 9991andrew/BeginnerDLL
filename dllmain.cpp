#include <iostream>
#include <ostream>
#include <Windows.h>
#include <tchar.h>

[[noreturn]] DWORD WINAPI MainThread(LPVOID param) {
    while (true) {
        SHORT keyState = GetAsyncKeyState(VK_F6);
        std::cout << keyState << std::endl;
        if (keyState) {  // Check if F6 is pressed
#ifdef _WIN64
            MessageBoxA(NULL, "Running as 64-bit", "Architecture", MB_OK);
#else
            MessageBoxA(NULL, "Running as 32-bit", "Architecture", MB_OK);
#endif
        } else {
            // Debug log to check if the key is not pressed
            OutputDebugStringA("F6 not pressed\n");
        }
        Sleep(100);  // Sleep for 100 ms to check more frequently
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "DLL Injected Successfully!", "DLL Injected", MB_OK);
        // Create a thread to check key presses
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        break;
        case DLL_PROCESS_DETACH:
            // Perform cleanup here if necessary
                break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
