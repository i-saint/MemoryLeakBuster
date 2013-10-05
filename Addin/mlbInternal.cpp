#include "mlbInternal.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

namespace mlb {

void EnumerateModules(HANDLE process, const std::function<void (HMODULE)> &f)
{
    std::vector<HMODULE> modules;
    DWORD num_modules = 0;
    ::EnumProcessModules(process, nullptr, 0, &num_modules);
    modules.resize(num_modules/sizeof(HMODULE));
    ::EnumProcessModules(process, &modules[0], num_modules, &num_modules);
    for(size_t i=0; i<modules.size(); ++i) {
        f(modules[i]);
    }
}

void EnumerateThreads(HANDLE process, const std::function<void (DWORD threadid)> &f)
{
    DWORD pid = ::GetProcessId(process);
    HANDLE ss = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(ss!=INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if(::Thread32First(ss, &te)) {
            do {
                if(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID)+sizeof(te.th32OwnerProcessID) &&
                    te.th32OwnerProcessID==pid)
                {
                    f(te.th32ThreadID);
                }
                te.dwSize = sizeof(te);
            } while(::Thread32Next(ss, &te));
        }
        ::CloseHandle(ss);
    }
}

HMODULE FindModule(HANDLE process, const char* dllname)
{
    HMODULE ret = nullptr;
    EnumerateModules(process, [&](HMODULE mod){
        char path[MAX_PATH];
        ::GetModuleFileNameExA(process, mod, path, MAX_PATH);
        if(strstr(path, dllname)) {
            ret = mod;
        }
    });
    return ret;
}

} // namespace mlb
