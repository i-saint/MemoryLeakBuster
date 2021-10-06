
#include "../MemoryLeakBuster.cpp"
#include "mlbInternal.h"


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        ::Sleep(1000);

        mlb::g_mlb = new mlb::MemoryLeakBuster();

        HANDLE process = GetCurrentProcess();
        HMODULE kernel32 = ::GetModuleHandleA("kernel32.dll");
        UnsetThreadTrap(process, ::GetProcAddress(kernel32, "SetUnhandledExceptionFilter"));
        EnumerateThreads(process, [&](DWORD tid) {
            if (tid == GetCurrentThreadId()) { return; }
            if (HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, tid)) {
                DWORD ret = ::ResumeThread(thread);
            }
            });
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        delete mlb::g_mlb;
    }
    return TRUE;
}