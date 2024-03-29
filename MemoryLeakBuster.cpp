﻿// created by i-saint
// distributed under Creative Commons Attribution (CC BY) license.
// https://github.com/i-saint/MemoryLeakBuster

// メモリリーク検出器。
// この .cpp をプロジェクトに含めるだけで有効になり、プログラム終了時にリーク箇所の確保時のコールスタックをデバッグ出力に表示します。
// 
// また、実行中にイミディエイトウィンドウから使える便利機能をいくつか提供します。
// 
// ・mlbInspect((void*)address)
//  指定メモリ領域の確保時のコールスタックや近隣領域を出力します。
//  (stack 領域、static 領域の場合それぞれ "stack memory", "static memory" と出力します)
// 
// ・mlbBeginScope() & mlbEndScope()
//  mlbBeginScope() を呼んでから mlbEndScope() を呼ぶまでの間に確保され、開放されなかったメモリがあればそれを出力します。
// 
// ・mlbBeginCount() & mlbEndCount()
//  mlbBeginCount() を呼んでから mlbEndCount() を呼ぶまでの間に発生したメモリ確保のコールスタックとそこで呼ばれた回数を出力します。
//  デバッグというよりもプロファイル用機能です。
// 
// ・mlbOutputToFile
//  leak 情報出力をファイル (mlbLog.txt) に切り替えます。
//  デバッグ出力は非常に遅いので、長大なログになる場合ファイルに切り替えたほうがいいでしょう。
// 
// 
// 設定ファイル (mlbConfig.txt) を書くことで外部から挙動を変えることができます。
// 設定ファイルは以下の書式を受け付けます。
// 
// ・disable: 0/1
//  リークチェックを無効化します。
// 
// ・fileoutput: 0/1
//  出力先をファイル (mlbLog.txt) にします。
// 
// ・module: "hoge.dll"
//  指定モジュールをリークチェックの対象にします。
// 
// ・ignore: "!functionname"
//  指定パターンを含むコールスタックのリークを表示しないようにします。
// 
// 
// 
// リークチェックの仕組みは CRT の HeapAlloc/Free を hook することによって実現しています。
// CRT を static link したモジュールの場合追加の手順が必要で、下の g_crtdllnames に対象モジュールを追加する必要があります。

// 設定
namespace mlb {

// 保持する callstack の最大段数
static const size_t MaxCallstackDepth = 32;

// リークチェッカを仕掛ける対象となるモジュール名のリスト。(dll or exe)
// EnumProcessModules でロードされている全モジュールに仕掛けることもできるが、色々誤判定されるので絞ったほうがいいと思われる。
// /MT や /MTd でビルドされたモジュールのリークチェックをしたい場合、このリストに対象モジュールを書けばいけるはず。
static const char* g_target_modules[] = {
    "ucrtbase.dll",
    "ucrtbased.dll",

    "msvcr120.dll",
    "msvcr120d.dll",
    "msvcr110.dll",
    "msvcr110d.dll",
    "msvcr100.dll",
    "msvcr100d.dll",
    "msvcrt.dll",
};

// 以下の関数群はリーク判定しないようにする。
// 一部の CRT 関数などは確保したメモリをモジュール開放時にまとめて開放する仕様になっており、
// リーク情報を出力する時点ではモジュールはまだ開放されていないため、リーク判定されてしまう。そういう関数を無視できるようにしている。
// (たぶん下記以外にもある)
static const char* g_ignore_list[] = {
    "!unlock",
    "!fopen",
    "!setlocale",
    "!gmtime32_s",
    "!_getmainargs",
    "!mbtowc_l",
    "!std::time_get",
    "!std::time_put",
    "!fullpath",
};

} // namespace mlb



#pragma warning(disable: 4996) // _s じゃない CRT 関数使うとでるやつ
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

#define NOMINMAX
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <chrono>
#include <cstdint>

#define mlbForceLink   __declspec(dllexport)
#ifdef _M_X64
    #define fHex "llx"
#else
    #define fHex "x"
#endif

namespace mlb {

using nanosec = uint64_t;
using HeapAllocT = LPVOID (WINAPI *)( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
using HeapReAllocT = LPVOID (WINAPI *)( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes );
using HeapFreeT = BOOL (WINAPI *)( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem );

// 乗っ取り前の HeapAlloc/Free
static HeapAllocT      HeapAlloc_Orig = nullptr;
static HeapReAllocT    HeapReAlloc_Orig = nullptr;
static HeapFreeT       HeapFree_Orig = nullptr;

// 乗っ取り後の HeapAlloc/Free
static LPVOID WINAPI HeapAlloc_Hooked( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
static LPVOID WINAPI HeapReAlloc_Hooked( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes );
static BOOL   WINAPI HeapFree_Hooked( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem );


static nanosec mlbNow()
{
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

static void* mlbMalloc(size_t size)    { return HeapAlloc_Orig((HANDLE)_get_heap_handle(), 0, size); }
static void  mlbFree(void *p)          { HeapFree_Orig((HANDLE)_get_heap_handle(), 0, p); }

template<class T> static T* mlbNew()
{
    return new (mlbMalloc(sizeof(T))) T();
}

template<class T> static void mlbDelete(T *v)
{
    if (v) {
        v->~T();
        mlbFree(v);
    }
}

static bool InitializeDebugSymbol(HANDLE proc = ::GetCurrentProcess())
{
    if(!::SymInitialize(proc, nullptr, TRUE)) {
        return false;
    }
    ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    return true;
}

static void FinalizeDebugSymbol(HANDLE proc=::GetCurrentProcess())
{
    ::SymCleanup(proc);
}

// 指定のアドレスが現在のモジュールの static 領域内であれば true
// ** 呼び出し元モジュールの static 領域しか判別しない **
static bool IsStaticMemory(void *addr)
{
    MODULEINFO modinfo;
    {
        HMODULE mod = 0;
        void *retaddr = *(void**)_AddressOfReturnAddress();
        ::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)retaddr, &mod);
        ::GetModuleInformation(::GetCurrentProcess(), mod, &modinfo, sizeof(modinfo));
    }
    return addr>=modinfo.lpBaseOfDll && addr<reinterpret_cast<char*>(modinfo.lpBaseOfDll)+modinfo.SizeOfImage;
}

// 指定アドレスが現在のスレッドの stack 領域内であれば true
// ** 現在のスレッドの stack しか判別しない **
static bool IsStackMemory(void* addr)
{
    NT_TIB *tib = reinterpret_cast<NT_TIB*>(::NtCurrentTeb());
    return addr>=tib->StackLimit && addr<tib->StackBase;
}

static int GetCallstack(void **callstack, size_t callstack_size)
{
    return CaptureStackBackTrace(1, (DWORD)callstack_size, callstack, nullptr);
}
template<size_t N>
static int GetCallstack(void* (&callstack)[N])
{
    return GetCallstack(callstack, N);
}

template<class String>
static void AddressToSymbolName(String& out_text, void* address, HANDLE proc = ::GetCurrentProcess())
{
#ifdef _WIN64
    typedef DWORD64 DWORDX;
    typedef PDWORD64 PDWORDX;
#else
    typedef DWORD DWORDX;
    typedef PDWORD PDWORDX;
#endif

    char buf[2048];
    HANDLE process = proc;
    IMAGEHLP_MODULE imageModule = { sizeof(IMAGEHLP_MODULE) };
    IMAGEHLP_LINE line = { sizeof(IMAGEHLP_LINE) };
    DWORDX dispSym = 0;
    DWORD dispLine = 0;

    char symbolBuffer[sizeof(IMAGEHLP_SYMBOL) + MAX_PATH] = {0};
    IMAGEHLP_SYMBOL * imageSymbol = (IMAGEHLP_SYMBOL*)symbolBuffer;
    imageSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
    imageSymbol->MaxNameLength = MAX_PATH;

    if(!::SymGetModuleInfo(process, (DWORDX)address, &imageModule)) {
        snprintf(buf, std::size(buf), "[0x%p]\n", address);
    }
    else if(!::SymGetSymFromAddr(process, (DWORDX)address, &dispSym, imageSymbol)) {
        snprintf(buf, std::size(buf), "%s + 0x%" fHex " [0x%p]\n", imageModule.ModuleName, ((size_t)address-(size_t)imageModule.BaseOfImage), address);
    }
    else if(!::SymGetLineFromAddr(process, (DWORDX)address, &dispLine, &line)) {
        snprintf(buf, std::size(buf), "%s!%s + 0x%" fHex " [0x%p]\n", imageModule.ModuleName, imageSymbol->Name, ((size_t)address-(size_t)imageSymbol->Address), address);
    }
    else {
        snprintf(buf, std::size(buf), "%s(%d): %s!%s + 0x%" fHex " [0x%p]\n", line.FileName, line.LineNumber,
            imageModule.ModuleName, imageSymbol->Name, ((size_t)address-(size_t)imageSymbol->Address), address);
    }
    out_text += buf;
}

template<class String>
static void CallstackToSymbolNamesStripped(String& out_text, void* const* callstack, int callstack_size, String& buf)
{
    buf.clear();
    for (int i = 0; i < callstack_size; ++i)
        AddressToSymbolName(buf, callstack[i]);

    size_t begin = 0;
    size_t end = buf.size();
    {
        size_t pos = buf.find("!aligned_malloc ");
        if (pos == String::npos)
            pos = buf.find("!malloc ");
        if (pos != String::npos) {
            for (;;) {
                if (buf[++pos] == '\n') {
                    begin = ++pos;
                    break;
                }
            }
        }
    }
    {
        size_t pos = buf.find("!__tmainCRTStartup ", begin);
        if (pos == String::npos)
            pos = buf.find("!endthreadex ", begin);
        if (pos == String::npos)
            pos = buf.find("!BaseThreadInitThunk ", begin); 
        if (pos != String::npos) {
            for (;;) {
                if (buf[--pos] == '\n') {
                    end = ++pos;
                    break;
                }
            }
        }
    }
    out_text.insert(out_text.end(), buf.begin() + begin, buf.begin() + end);
}


template<class T>
class ScopedLock
{
public:
    ScopedLock(T &m) : m_mutex(m) { m_mutex.lock(); }
    ~ScopedLock() { m_mutex.unlock(); }

private:
    T &m_mutex;
};

class Mutex
{
public:
    using ScopedLock = ScopedLock<Mutex>;
    using Handle = CRITICAL_SECTION;

    Mutex(const Mutex&) = delete;
    Mutex& operator=(const Mutex&) = delete;

    Mutex()        { ::InitializeCriticalSection(&m_lockobj); }
    ~Mutex()       { ::DeleteCriticalSection(&m_lockobj); }
    void lock()    { ::EnterCriticalSection(&m_lockobj); }
    bool tryLock() { return ::TryEnterCriticalSection(&m_lockobj) == TRUE; }
    void unlock()  { ::LeaveCriticalSection(&m_lockobj); }

private:
    Handle m_lockobj;
};

// アロケーション情報を格納するコンテナのアロケータが new / delete を使うと永久再起するので、
// hook を通さないメモリ確保を行うアロケータを用意
template<typename T>
class OrigHeapAllocator {
public : 
    // for C++17 or newer
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;

    OrigHeapAllocator() {}
    template <class U> OrigHeapAllocator(const OrigHeapAllocator<U>&) noexcept {}
    template <class U> bool operator==(const OrigHeapAllocator<U>&) const { return true; }
    template <class U> bool operator!=(const OrigHeapAllocator<U>&) const { return false; }

    T* allocate(size_type cnt, const void* = nullptr) { return (T*)mlbMalloc(cnt * sizeof(T)); }
    void deallocate(T* p, size_type) { mlbFree(p); }

public:
    // for C++14 or older
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    template<typename U> struct rebind { typedef OrigHeapAllocator<U> other; };

    pointer address(reference r) { return &r; }
    const_pointer address(const_reference r) { return &r; }
    size_type max_size() const { return std::numeric_limits<size_type>::max() / sizeof(T); }
    void construct(pointer p, const T& t) { new(p) T(t); }
    void destroy(pointer p) { p; p->~T(); }
};

using TempString = std::basic_string<char, std::char_traits<char>, OrigHeapAllocator<char> >;
using StringCont = std::vector<TempString, OrigHeapAllocator<TempString> >;




// write protect がかかったメモリ領域を強引に書き換える
template<class T>
static inline void ForceWrite(T &dst, const T &src)
{
    DWORD old_flag;
    ::VirtualProtect(&dst, sizeof(T), PAGE_EXECUTE_READWRITE, &old_flag);
    dst = src;
    ::VirtualProtect(&dst, sizeof(T), old_flag, &old_flag);
}


// F: [](const char *dllname, const char *funcname, void *&func) -> void
template<class F>
static bool EachImportFunction(HMODULE module, const F& f)
{
    if (!module)
        return false;

    size_t ImageBase = (size_t)module;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(ImageBase + pDosHeader->e_lfanew);
    size_t RVAImports = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (RVAImports == 0)
        return false;

    IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(ImageBase + RVAImports);
    while (pImportDesc->Name != 0) {
        auto dllname = (const char*)(ImageBase + pImportDesc->Name);
        IMAGE_IMPORT_BY_NAME** func_names = (IMAGE_IMPORT_BY_NAME**)(ImageBase + pImportDesc->Characteristics);
        void** import_table = (void**)(ImageBase + pImportDesc->FirstThunk);
        for (size_t i = 0; ; ++i) {
            if ((size_t)func_names[i] == 0)
                break;
            auto* funcname = (const char*)(ImageBase + (size_t)func_names[i]->Name);
            f(dllname, funcname, import_table[i]);
        }
        ++pImportDesc;
    }
    return true;
}


// HeapAlloc() を提供する dll なら true
static bool IsKernelModule(const char* modulename)
{
    const char* patterns[] = {
        "kernel32.dll",
        "api-ms-win-core-heap", // api-ms-win-core-heap-l1-1-0.dll など
    };
    for (auto* pattern : patterns) {
        if (strstr(modulename, pattern))
            return true;

    }
    return false;
}

static void SaveOrigHeapAlloc()
{
    HeapAlloc_Orig  = &HeapAlloc;
    HeapReAlloc_Orig= &HeapReAlloc;
    HeapFree_Orig   = &HeapFree;
}

static void HookHeapAlloc(const char *modulename)
{
    const std::pair<const char*, void*> table[] = {
        {"HeapAlloc", HeapAlloc_Hooked},
        {"HeapReAlloc", HeapReAlloc_Hooked},
        {"HeapFree", HeapFree_Hooked},
    };

    auto do_hook = [&table](const char* dllname, const char* funcname, void*& func) {
        if (!IsKernelModule(dllname))
            return;
        for (auto& v : table) {
            if (strcmp(funcname, v.first) == 0) {
                ForceWrite<void*>(func, v.second);
                break;
            }
        }
    };

    EachImportFunction(::GetModuleHandleA(modulename), do_hook);
}

static void HookHeapAlloc(const StringCont &modules)
{
    HookHeapAlloc(nullptr); // exe を hook
    for (auto& mod : modules) {
        HookHeapAlloc(mod.c_str());
    }
}

static void UnhookHeapAlloc(const StringCont &modules)
{
    const std::pair<const char*, void*> table[] = {
        {"HeapAlloc", HeapAlloc_Orig},
        {"HeapReAlloc", HeapReAlloc_Orig},
        {"HeapFree", HeapFree_Orig},
    };

    auto do_unhook = [&table](const char* dllname, const char* funcname, void*& func) {
        if (!IsKernelModule(dllname))
            return;
        for (auto& v : table) {
            if (strcmp(funcname, v.first) == 0) {
                ForceWrite<void*>(func, v.second);
                break;
            }
        }
    };

    for (auto& mod : modules) {
        EachImportFunction(::GetModuleHandleA(mod.c_str()), do_unhook);
    }
}


class MemoryLeakBuster
{
public:
    struct HeapInfo
    {
        void *address = nullptr;
        size_t size = 0;
        nanosec time = 0;
        void* callstack[MaxCallstackDepth]{};
        uint32_t callstack_size = 0;
        uint32_t id = 0;
        uint32_t count = 0;
    };

    struct less_callstack
    {
        bool operator()(const HeapInfo &a, const HeapInfo &b) const
        {
            if (a.callstack_size == b.callstack_size) {
                return memcmp(a.callstack, b.callstack, sizeof(void*) * a.callstack_size) < 0;
            }
            else {
                return a.callstack_size < b.callstack_size;
            }
        };
    };
    using HeapTable = std::map<void*, HeapInfo, std::less<void*>, OrigHeapAllocator<std::pair<void* const, HeapInfo> > >;
    using CountTable = std::set<HeapInfo, less_callstack, OrigHeapAllocator<HeapInfo> >;

    union Flags
    {
        struct {
            uint32_t enable_leakcheck: 1;
            uint32_t enable_scopedcheck: 1;
            uint32_t enable_counter: 1;
        };
        uint32_t i;
    };

public:
    MemoryLeakBuster(const MemoryLeakBuster&) = delete;
    MemoryLeakBuster& operator=(const MemoryLeakBuster&) = delete;

    MemoryLeakBuster();
    ~MemoryLeakBuster();

    bool loadConfig();
    void enbaleFileOutput(bool v);
    void addHeapInfo(void* p, size_t size);
    void eraseHeapInfo(void* p);

    // lock しない。内部実装用
    HeapTable::const_iterator _findHeapInfo(void* p) const;
    const HeapInfo* getHeapInfo(void* p);
    void inspect(void* p) const;
    void printLeakInfo() const;

    void beginScope();
    void endScope();
    void beginCount();
    void endCount();
    bool shouldBeIgnored(const TempString& callstack) const;
    void output(const char* str, size_t len = 0) const;

private:
    FILE *m_logfile = nullptr;
    Mutex *m_mutex = nullptr;
    HeapTable *m_heapinfo = nullptr;
    CountTable *m_counter = nullptr;
    StringCont *m_modules = nullptr;
    StringCont *m_ignores = nullptr;
    uint32_t m_idgen = 0;
    uint32_t m_scope = INT_MAX;
    Flags m_flags{};
};

MemoryLeakBuster::MemoryLeakBuster()
{
    SaveOrigHeapAlloc();
    m_flags.i = 0;
    m_flags.enable_leakcheck = 1;
    m_mutex = mlbNew<Mutex>();
    m_heapinfo = mlbNew<HeapTable>();
    m_counter = mlbNew<CountTable>();
    m_modules = mlbNew<StringCont>();
    m_ignores = mlbNew<StringCont>();
    loadConfig();
    InitializeDebugSymbol();
    HookHeapAlloc(*m_modules);
}

MemoryLeakBuster::~MemoryLeakBuster()
{
    if (!m_mutex)
        return;
    Mutex::ScopedLock l(*m_mutex);

    UnhookHeapAlloc(*m_modules);
    printLeakInfo();

    // 解放後もアクセスされる可能性がある点に注意
    // 全チェックを無効化して他のメンバ変数にアクセスされないようにする
    m_flags.i = 0;
    mlbDelete(m_ignores);  m_ignores = nullptr;
    mlbDelete(m_modules);  m_modules = nullptr;
    mlbDelete(m_counter);  m_counter = nullptr;
    mlbDelete(m_heapinfo); m_heapinfo = nullptr;

    // m_mutex は開放しない
    // 別スレッドから HeapFree_Hooked() が呼ばれて mutex を待ってる間に
    // ここでその mutex を破棄してしまうとクラッシュしてしまうため

    enbaleFileOutput(false);
    FinalizeDebugSymbol();
}

bool MemoryLeakBuster::loadConfig()
{
    for (auto* mod : g_target_modules)
        m_modules->push_back(mod);

    for (auto* pattern : g_ignore_list)
        m_ignores->push_back(pattern);

    char buf[256];
    if (FILE* f = fopen("mlbConfig.txt", "r")) {
        int i;
        char s[128]{};
        while (fgets(buf, (int)std::size(buf), f)) {
            if (sscanf(buf, "disable: %d", &i) == 1) { m_flags.enable_leakcheck = (i != 1); }
            else if (sscanf(buf, "fileoutput: %d", &i) == 1) { enbaleFileOutput(i != 0); }
            else if (sscanf(buf, "ignore: \"%[^\"]\"", s) == 1) { m_ignores->push_back(s); }
            else if (sscanf(buf, "module: \"%[^\"]\"", s) == 1) { m_modules->push_back(s); }
        }
        fclose(f);
        return true;
    }
    return false;
}

void MemoryLeakBuster::enbaleFileOutput(bool v)
{
    if (v && !m_logfile) {
        m_logfile = fopen("mlbLog.txt", "wb");
    }
    else if (!v && m_logfile) {
        fclose(m_logfile);
        m_logfile = nullptr;
    }
}

void MemoryLeakBuster::addHeapInfo(void* p, size_t size)
{
    if (!p || m_flags.i == 0)
        return;

    HeapInfo cs;
    cs.address = p;
    cs.size = size;
    cs.time = mlbNow();
    cs.callstack_size = GetCallstack(cs.callstack);
    cs.count = 0;
    {
        Mutex::ScopedLock l(*m_mutex);
        if (m_flags.enable_leakcheck || m_flags.enable_scopedcheck) {
            cs.id = ++m_idgen;
            (*m_heapinfo)[p] = cs;
        }
        if (m_flags.enable_counter) {
            auto r = m_counter->insert(cs);
            const_cast<HeapInfo&>(*r.first).count++;
        }
    }
}

void MemoryLeakBuster::eraseHeapInfo(void* p)
{
    if (!p || (m_flags.enable_leakcheck == 0 && m_flags.enable_scopedcheck == 0))
        return;
    Mutex::ScopedLock l(*m_mutex);
    if (m_heapinfo)
        m_heapinfo->erase(p);
}

// lock しない。内部実装用
MemoryLeakBuster::HeapTable::const_iterator MemoryLeakBuster::_findHeapInfo(void* p) const
{
    if (m_heapinfo->empty())
        return m_heapinfo->end();

    auto i = m_heapinfo->lower_bound(p);
    if (i == m_heapinfo->end() || (p != i->first && i != m_heapinfo->begin()))
        --i;

    auto& hi = i->second;
    if (p >= hi.address && p <= (void*)((size_t)hi.address + hi.size))
        return i;
    return m_heapinfo->end();
}

const MemoryLeakBuster::HeapInfo* MemoryLeakBuster::getHeapInfo(void* p)
{
    Mutex::ScopedLock l(*m_mutex);
    if (!m_heapinfo)
        return nullptr;

    auto i = _findHeapInfo(p);
    if (i == m_heapinfo->end())
        return nullptr;
    return &i->second;
}

void MemoryLeakBuster::inspect(void* p) const
{
    if (IsStaticMemory(p)) {
        ::OutputDebugStringA("static memory\n");
        return;
    }
    if (IsStackMemory(p)) {
        ::OutputDebugStringA("stack memory\n");
        return;
    }

    const HeapInfo* r = nullptr;
    const void* neighbor[2]{};
    {
        Mutex::ScopedLock l(*m_mutex);
        if (!m_heapinfo)
            return;

        auto li = _findHeapInfo(p);
        if (li != m_heapinfo->end()) {
            const HeapInfo& ai = li->second;
            r = &ai;
            if (li != m_heapinfo->begin()) {
                auto prev = li; --prev;
                neighbor[0] = prev->second.address;
            }
            {
                auto next = li; ++next;
                if (next != m_heapinfo->end()) {
                    neighbor[1] = next->second.address;
                }
            }
        }
    }

    if (!r) {
        ::OutputDebugStringA("no information.\n");
        return;
    }

    char buf[128];
    TempString text, bufstr;
    text.reserve(1024 * 16);
    snprintf(buf, std::size(buf), "0x%p (%zu byte) ", r->address, r->size); text += buf;
    snprintf(buf, std::size(buf), "prev: 0x%p next: 0x%p\n", neighbor[0], neighbor[1]); text += buf;
    CallstackToSymbolNamesStripped(text, r->callstack, r->callstack_size, bufstr);
    ::OutputDebugStringA(text.c_str());
}

void MemoryLeakBuster::printLeakInfo() const
{
    Mutex::ScopedLock l(*m_mutex);
    if (!m_heapinfo)
        return;

    char buf[128];
    TempString text, bufstr;
    text.reserve(1024 * 16);
    for (auto& kvp : *m_heapinfo) {
        const auto& ai = kvp.second;

        text.clear();
        snprintf(buf, std::size(buf), "memory leak: 0x%p (%zu byte)\n", ai.address, ai.size);
        text += buf;
        CallstackToSymbolNamesStripped(text, ai.callstack, ai.callstack_size, bufstr);
        text += "\n";
        if (!shouldBeIgnored(text)) {
            output(text.c_str(), text.size());
        }
    }
}


void MemoryLeakBuster::beginScope()
{
    Mutex::ScopedLock l(*m_mutex);
    m_flags.enable_scopedcheck = 1;
    m_scope = m_idgen;
}

void MemoryLeakBuster::endScope()
{
    Mutex::ScopedLock l(*m_mutex);
    if (!m_heapinfo)
        return;

    char buf[128];
    TempString text, bufstr;
    text.reserve(1024 * 16);
    for (auto& kvp : *m_heapinfo) {
        const auto& ai = kvp.second;
        if (ai.id < m_scope)
            continue;

        text.clear();
        snprintf(buf, std::size(buf), "maybe a leak: 0x%p (%zu byte)\n", ai.address, ai.size);
        text += buf;
        CallstackToSymbolNamesStripped(text, ai.callstack, ai.callstack_size, bufstr);
        text += "\n";
        if (!shouldBeIgnored(text)) {
            output(text.c_str(), text.size());
        }
    }
    m_scope = INT_MAX;
    m_flags.enable_scopedcheck = 0;
}


void MemoryLeakBuster::beginCount()
{
    Mutex::ScopedLock l(*m_mutex);
    m_flags.enable_counter = 1;
}

void MemoryLeakBuster::endCount()
{
    Mutex::ScopedLock l(*m_mutex);
    if (!m_flags.enable_counter)
        return;

    int total = 0;
    char buf[128];
    TempString text, bufstr;
    text.reserve(1024 * 16);
    for (auto& kvp : *m_heapinfo) {
        const auto& ai = kvp.second;

        text.clear();
        snprintf(buf, std::size(buf), "%d times from\n", ai.count);
        text += buf;
        CallstackToSymbolNamesStripped(text, ai.callstack, ai.callstack_size, bufstr);
        text += "\n";
        output(text.c_str(), text.size());
        total += ai.count;
    }
    snprintf(buf, std::size(buf), "total %d times\n", total);
    output(buf);

    m_flags.enable_counter = 0;
}


bool MemoryLeakBuster::shouldBeIgnored(const TempString& callstack) const
{
    for (auto& ignore : *m_ignores) {
        if (callstack.find(ignore.c_str()) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void MemoryLeakBuster::output(const char* str, size_t len) const
{
    if (m_logfile) {
        if (len == 0)
            len = strlen(str);
        fwrite(str, 1, len, m_logfile);
    }
    else {
        ::OutputDebugStringA(str);
    }
}

static MemoryLeakBuster *g_mlb;

static LPVOID WINAPI HeapAlloc_Hooked(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    LPVOID p = HeapAlloc_Orig(hHeap, dwFlags, dwBytes);
    g_mlb->addHeapInfo(p, dwBytes);
    return p;
}

static LPVOID WINAPI HeapReAlloc_Hooked(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    g_mlb->eraseHeapInfo(lpMem);
    LPVOID p = HeapReAlloc_Orig(hHeap, dwFlags, lpMem, dwBytes);
    g_mlb->addHeapInfo(p, dwBytes);
    return p;
}

static BOOL WINAPI HeapFree_Hooked(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    BOOL r = HeapFree_Orig(hHeap, dwFlags, lpMem);
    g_mlb->eraseHeapInfo(lpMem);
    return r;
}

} /// namespace mlb

mlbForceLink void mlbInitialize()
{
    if (!mlb::g_mlb)
        mlb::g_mlb = new mlb::MemoryLeakBuster();
}

mlbForceLink void mlbFinalize()
{
    delete mlb::g_mlb;
    mlb::g_mlb = nullptr;
}

// イミディエイトウィンドウから実行可能な関数群
using HeapInfo = mlb::MemoryLeakBuster::HeapInfo;
mlbForceLink const HeapInfo* mlbGetHeapInfo(void *p)
{
    return mlb::g_mlb->getHeapInfo(p);
}

mlbForceLink void mlbInspect(void *p)     { mlb::g_mlb->inspect(p); }
mlbForceLink void mlbBeginScope()         { mlb::g_mlb->beginScope(); }
mlbForceLink void mlbEndScope()           { mlb::g_mlb->endScope(); }
mlbForceLink void mlbBeginCount()         { mlb::g_mlb->beginCount(); }
mlbForceLink void mlbEndCount()           { mlb::g_mlb->endCount(); }
mlbForceLink void mlbOutputToFile(bool v) { mlb::g_mlb->enbaleFileOutput(v); }

#ifndef mlbDLL
namespace mlb {
class Initializer
{
public:
    Initializer() { mlbInitialize(); }
    ~Initializer() { mlbFinalize(); }
};

#pragma warning(disable: 4073) // init_seg(lib) 使うと出る warning。正当な理由があるので黙らせる
#pragma init_seg(lib) // global オブジェクトの初期化の優先順位上げる
// global 変数にすることで main 開始前に初期化、main 抜けた後に終了処理をさせる。
mlbForceLink Initializer g_initializer;
} // namespace mlb
#endif // mlbDLL
