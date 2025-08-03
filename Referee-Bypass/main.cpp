#include <Windows.h>
#include <thread>
#include <chrono>
#include "Stuff.h"

// This is just a base to show you how to bypass Referee!

void main() {
    Carpet::CreateConsole();
    Carpet::RefereeBypass(); // Disables Every Thread inside Referee.dll
    Carpet::Hooks(); // Initialize & Enable
    std::this_thread::sleep_for(std::chrono::seconds(5));
    MH_DisableHook((void**)(GameAssembly + get_isflyingenabled));
    Carpet::DisableRefereeBypass(); // Bring the suspended threads back
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD ulReason, LPVOID lpReserved) {
    switch (ulReason) {
    case DLL_PROCESS_ATTACH:
        std::thread(&main).detach();
        break;
    }
    return TRUE;
}