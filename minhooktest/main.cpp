#include <iostream>
#include <vector>
#include "minhook/MinHook.h"

uintptr_t myPlayer;

DWORD WINAPI cheat(LPVOID lpvParam);
std::uint8_t* PatternScan(void* module, const char* signature);

typedef __int64(__fastcall *SubValuesFnc)(__int64, int);
SubValuesFnc oSubValues = nullptr; // original function

__int64 __fastcall SubValues(__int64 playerPtr, int num) {
    if (playerPtr != (__int64)myPlayer)
        return oSubValues(playerPtr, 100);
    else {
        *(uintptr_t*)(myPlayer + 0x60) += num;
    }
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hInstance);
        HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)cheat, hInstance, 0, NULL);
        
        if (thread) CloseHandle(thread);
	}

    return true;
}


DWORD WINAPI cheat(LPVOID lpvParam) {
    const auto functionAddress = PatternScan((void*)GetModuleHandleA("gtutorial-x86_64.exe"), "48 89 C8 29 50");
    if (!functionAddress) return 1;
    myPlayer = *(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)((uintptr_t)GetModuleHandle(NULL) + 0x3BED50) + 0x7c0) + 0x28);
    if (!myPlayer) return 1;

    if (MH_Initialize() != MH_OK) return 1;
    if (MH_CreateHook((LPVOID)functionAddress, &SubValues, (LPVOID*)&oSubValues) != MH_OK) return 1;
    if (MH_EnableHook((LPVOID)functionAddress) != MH_OK) return 1;

    while (true) {
        // You can add a key to uninject/unhook here
        if (GetAsyncKeyState(VK_DELETE) & 1) {
            break;
        }
        Sleep(100);
    }

    MH_DisableHook((LPVOID)functionAddress);
    MH_Uninitialize();
    
    FreeLibraryAndExitThread((HMODULE)lpvParam, EXIT_SUCCESS);
    return 0;
}

/*
     * @brief Scan for a given byte pattern on a module
     *
     * @Param module    Base of the module to search
     * @Param signature IDA-style byte array pattern
     *
     * @Returns Address of the first occurence
     */
std::uint8_t* PatternScan(void* module, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern) { // convert those bytes
        auto bytes = std::vector<int>{};
        const char* current = pattern;
        const char* end = pattern + strlen(pattern);

        while (current < end) {
            if (*current == ' ') { ++current; continue; }
            if (*current == '?') { // single double wildcard support
                ++current;
                if (*current == '?') ++current;
                bytes.push_back(-1);
                continue;
            }
            char* next = nullptr;
            bytes.push_back(static_cast<int>(strtoul(current, &next, 16)));
            if (next == current) break;
            current = next;
        }
        return bytes;
    };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return &scanBytes[i];
        }
    }
    return nullptr;
}