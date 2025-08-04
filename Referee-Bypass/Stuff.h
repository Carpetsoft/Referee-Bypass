#include <MinHook.h>
#include "offsets.h"
#include <stdint.h>
#include "stdio.h"
#include "Psapi.h"
#include "TlHelp32.h"

typedef enum _THREADINFOCLASS {
    ThreadQuerySetWin32StartAddress = 9
} THREADINFOCLASS;

typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

uintptr_t GameAssembly = (uintptr_t)GetModuleHandle(L"GameAssembly.dll");


// sig "RecRoom_Core_Locomotion_PlayerMovement_o* __this, const MethodInfo* method"
bool(*get_isflyingenabled_O)(DWORD*, DWORD*);
bool (get_isflyingenabled_H)(DWORD* __this, const DWORD* method) {
	return true;
}

namespace Carpet {
	void Hooks() {
		printf("Doing Hooks!\n");
		MH_Initialize();

		MH_CreateHook((void**)(GameAssembly + get_isflyingenabled), &get_isflyingenabled_H, (void**)&get_isflyingenabled_O);

                MH_EnableHook((void**)(GameAssembly + get_isflyingenabled));

		printf("Hooks Done :D\n");
	}

    void CreateConsole() {
        AllocConsole();
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
    }

    bool IsAddressInModuleRange(void* addr, uintptr_t moduleBase, size_t moduleSize) {
        uintptr_t address = (uintptr_t)addr;
        return address >= moduleBase && address < (moduleBase + moduleSize);
    }

    void RefereeBypass() {
        HMODULE hModule = GetModuleHandleA("Referee.dll");

        MODULEINFO modInfo{};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return;
        }

        uintptr_t moduleBase = (uintptr_t)modInfo.lpBaseOfDll;
        size_t moduleSize = modInfo.SizeOfImage;

        NtQueryInformationThread_t NtQueryInformationThread =
            (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
        if (!NtQueryInformationThread) {
            return;
        }

        DWORD currentProcessId = GetCurrentProcessId();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        THREADENTRY32 threadEntry;
        threadEntry.dwSize = sizeof(threadEntry);

        size_t suspendedCount = 0;

        if (Thread32First(snapshot, &threadEntry)) {
            do {
                if (threadEntry.th32OwnerProcessID == currentProcessId) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID);
                    if (hThread) {
                        void* startAddress = nullptr;
                        ULONG retLen = 0;
                        NTSTATUS status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), &retLen);
                        if (NT_SUCCESS(status) && startAddress != nullptr) {
                            if (IsAddressInModuleRange(startAddress, moduleBase, moduleSize)) {
                                SuspendThread(hThread);
                                suspendedCount++;
                            }
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(snapshot, &threadEntry));
        }

        CloseHandle(snapshot);
    }

    void DisableRefereeBypass() {
        DWORD pid = GetCurrentProcessId();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        HMODULE hModule = NULL;
        MODULEINFO modInfo = {};
        if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)&DisableRefereeBypass, &hModule)) {
            GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo));
        }
        else {
            CloseHandle(snapshot);
            return;
        }

        uintptr_t dllStart = (uintptr_t)modInfo.lpBaseOfDll;
        uintptr_t dllEnd = dllStart + modInfo.SizeOfImage;

        THREADENTRY32 entry = { sizeof(entry) };
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == GetCurrentThreadId())
                    continue;

                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID);
                if (!hThread) continue;

                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_CONTROL;

                if (SuspendThread(hThread) != (DWORD)-1) {
                    if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
                        uintptr_t ip = ctx.Rip;
#else
                        uintptr_t ip = ctx.Eip;
#endif
                        if (ip >= dllStart && ip <= dllEnd) {
                            ResumeThread(hThread);
                        }
                    }
                    ResumeThread(hThread);
                }

                CloseHandle(hThread);
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
    }

};
