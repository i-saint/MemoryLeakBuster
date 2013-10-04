#include "stdafx.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <functional>
#include <algorithm>

#include "mlbInjector.h"

#define AddInDir "\\Documents\\Visual Studio 2012\\Addins\\"
#ifdef _M_IX64
#   define MLBDllFileName "mlb64.dll"
#else  // _M_IX64
#   define MLBDllFileName "mlb.dll"
#endif // _M_IX64
#define KernelDLLFileName "kernel32.dll"

namespace mlbInjector {

// F: [](HMODULE mod)->void
template<class F>
inline void EnumerateModules(HANDLE process, const F &f)
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

// F: [](DWORD thread_id)->void
template<class F>
inline void EnumerateThreads(DWORD pid, const F &f)
{
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

static bool InjectDLL(HANDLE process, const char* dllname)
{
    SIZE_T bytesRet = 0;
    DWORD oldProtect = 0;
    LPVOID remote_addr = NULL;
    HANDLE hThread = NULL;
    size_t len = strlen(dllname) + 1;

    remote_addr = ::VirtualAllocEx(process, 0, 1024, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(remote_addr==NULL) { return false; }
    ::VirtualProtectEx(process, remote_addr, len, PAGE_EXECUTE_READWRITE, &oldProtect);
    ::WriteProcessMemory(process, remote_addr, dllname, len, &bytesRet);
    ::VirtualProtectEx(process, remote_addr, len, oldProtect, &oldProtect);

    HMODULE kernel32 = ::LoadLibraryA(KernelDLLFileName);
    void *loadlib = ::GetProcAddress(kernel32, "LoadLibraryA");
    void *entrypoint = nullptr;
    EnumerateModules(process, [&](HMODULE mod){
        char path[MAX_PATH];
        ::GetModuleFileNameExA(process, mod, path, MAX_PATH);
        if(strstr(path, KernelDLLFileName)) {
            entrypoint = (void*) ((size_t)mod+((size_t)loadlib-(size_t)kernel32));
        }
    });

    hThread = ::CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)entrypoint, remote_addr, 0, NULL);
    // ÉfÉoÉbÉKÇ™ÉXÉåÉbÉhé~ÇﬂÇƒÇÈÇÃÇ≈à»â∫ÇÃ Wait ÇÕâiãví‚é~ÇèµÇ≠
    //::WaitForSingleObject(hThread, INFINITE); 
    //::VirtualFreeEx(process, remote_addr, 0, MEM_RELEASE);
    return hThread!=nullptr;
}

static bool DoInject(DWORD processID)
{
    //EnumerateThreads(processID, [&](DWORD tid){
    //    if(HANDLE thread=::OpenThread(THREAD_ALL_ACCESS, FALSE, tid)) {
    //        ::SuspendThread(thread);
    //        ::CloseHandle(thread);
    //    }
    //});

    std::string dll_path = std::getenv("USERPROFILE");
    dll_path += AddInDir;
    dll_path += MLBDllFileName;

    HANDLE process = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if(!process) {
        return false;
    }
    bool result = InjectDLL(process, dll_path.c_str());
    ::CloseHandle(process);
    return result;

}

bool Injector::Inject(DWORD processID)
{
    return DoInject(processID);
}

} // namespace mlbInjector
