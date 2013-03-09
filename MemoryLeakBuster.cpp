// this code is public domain.
// latest version: https://github.com/i-saint/MemoryLeakBuster
// written by i-saint ( http://primitive-games.jp )
// 
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


#pragma warning(disable: 4073) // init_seg(lib) 使うと出る warning。正当な理由があるので黙らせる
#pragma warning(disable: 4996) // _s じゃない CRT 関数使うとでるやつ
#pragma init_seg(lib) // global オブジェクトの初期化の優先順位上げる
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#define mlbForceLink   __declspec(dllexport)

namespace mlb {

// 保持する callstack の最大段数
const size_t MaxCallstackDepth = 64;

// リークチェッカを仕掛ける対象となるモジュール名のリスト。(dll or exe)
// EnumProcessModules でロードされている全モジュールに仕掛けることもできるが、
// 色々誤判定されるので絞ったほうがいいと思われる。
// /MT や /MTd でビルドされたモジュールのリークチェックをしたい場合、このリストに対象モジュールを書けばいけるはず。
const char *g_target_modules[] = {
    "msvcr110.dll",
    "msvcr110d.dll",
    "msvcr100.dll",
    "msvcr100d.dll",
    "msvcr90.dll",
    "msvcr90d.dll",
    "msvcr80.dll",
    "msvcr80d.dll",
    "msvcrt.dll",
};

// 以下の関数群はリーク判定しないようにする。
// 一部の CRT 関数などは確保したメモリをモジュール開放時にまとめて開放する仕様になっており、
// リーク情報を出力する時点ではモジュールはまだ開放されていないため、リーク判定されてしまう。そういう関数を無視できるようにしている。
// (たぶん下記以外にもあるはず)
const char *g_ignore_list[] = {
    "!unlock",
    "!fopen",
    "!setlocale",
    "!gmtime32_s",
    "!_getmainargs",
    "!mbtowc_l",
    "!std::time_get",
    "!std::time_put",
};


typedef LPVOID (WINAPI *HeapAllocT)( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
typedef BOOL (WINAPI *HeapFreeT)( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem );

// 乗っ取り前の HeapAlloc/Free
HeapAllocT HeapAlloc_Orig = NULL;
HeapFreeT HeapFree_Orig = NULL;

// 乗っ取り後の HeapAlloc/Free
LPVOID WINAPI HeapAlloc_Hooked( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
BOOL WINAPI HeapFree_Hooked( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem );

template<class T> T* mlbNew()
{
    return new (HeapAlloc_Orig((HANDLE)_get_heap_handle(), 0, sizeof(T))) T();
}

template<class T> void mlbDelete(T *v)
{
    if(v!=NULL) {
        v->~T();
        HeapFree_Orig((HANDLE)_get_heap_handle(), 0, v);
    }
}

bool InitializeDebugSymbol(HANDLE proc=::GetCurrentProcess())
{
    if(!::SymInitialize(proc, NULL, TRUE)) {
        return false;
    }
    ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

    return true;
}

void FinalizeDebugSymbol(HANDLE proc=::GetCurrentProcess())
{
    ::SymCleanup(proc);
}

// 指定のアドレスが現在のモジュールの static 領域内であれば true
// * 呼び出し元モジュールの static 領域しか判別できません
bool IsStaticMemory(void *addr)
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
// * 現在のスレッド以外の stack は判別できません
bool IsStackMemory(void *addr)
{
    NT_TIB *tib = reinterpret_cast<NT_TIB*>(::NtCurrentTeb());
    return addr>=tib->StackLimit && addr<tib->StackBase;
}

int GetCallstack(void **callstack, int callstack_size, int skip_size)
{
    return CaptureStackBackTrace(skip_size, callstack_size, callstack, NULL);
}

template<class String>
void AddressToSymbolName(String &out_text, void *address, HANDLE proc=::GetCurrentProcess())
{
#ifdef _WIN64
    typedef DWORD64 DWORDX;
    typedef PDWORD64 PDWORDX;
#else
    typedef DWORD DWORDX;
    typedef PDWORD PDWORDX;
#endif

    char buf[1024];
    HANDLE process = proc;
    IMAGEHLP_MODULE imageModule = { sizeof(IMAGEHLP_MODULE) };
    IMAGEHLP_LINE line ={sizeof(IMAGEHLP_LINE)};
    DWORDX dispSym = 0;
    DWORD dispLine = 0;

    char symbolBuffer[sizeof(IMAGEHLP_SYMBOL) + MAX_PATH] = {0};
    IMAGEHLP_SYMBOL * imageSymbol = (IMAGEHLP_SYMBOL*)symbolBuffer;
    imageSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
    imageSymbol->MaxNameLength = MAX_PATH;

    if(!::SymGetModuleInfo(process, (DWORDX)address, &imageModule)) {
        sprintf_s(buf, "[0x%p]\n", address);
    }
    else if(!::SymGetSymFromAddr(process, (DWORDX)address, &dispSym, imageSymbol)) {
        sprintf_s(buf, "%s + 0x%x [0x%p]\n", imageModule.ModuleName, ((size_t)address-(size_t)imageModule.BaseOfImage), address);
    }
    else if(!::SymGetLineFromAddr(process, (DWORDX)address, &dispLine, &line)) {
        sprintf_s(buf, "%s!%s + 0x%x [0x%p]\n", imageModule.ModuleName, imageSymbol->Name, ((size_t)address-(size_t)imageSymbol->Address), address);
    }
    else {
        sprintf_s(buf, "%s(%d): %s!%s + 0x%x [0x%p]\n", line.FileName, line.LineNumber,
            imageModule.ModuleName, imageSymbol->Name, ((size_t)address-(size_t)imageSymbol->Address), address);
    }
    out_text += buf;
}

template<class String>
void CallstackToSymbolNames(String &out_text, void * const *callstack, int callstack_size, int clamp_head=0, int clamp_tail=0, const char *indent="")
{
    int begin = std::max<int>(0, clamp_head);
    int end = std::max<int>(0, callstack_size-clamp_tail);
    for(int i=begin; i<end; ++i) {
        out_text += indent;
        AddressToSymbolName(out_text, callstack[i]);
    }
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
    typedef ScopedLock<Mutex> ScopedLock;
    typedef CRITICAL_SECTION Handle;

    Mutex()          { InitializeCriticalSection(&m_lockobj); }
    ~Mutex()         { DeleteCriticalSection(&m_lockobj); }
    void lock()      { EnterCriticalSection(&m_lockobj); }
    bool tryLock()   { return TryEnterCriticalSection(&m_lockobj)==TRUE; }
    void unlock()    { LeaveCriticalSection(&m_lockobj); }

    Handle getHandle() const { return m_lockobj; }

private:
    Handle m_lockobj;
    Mutex(const Mutex&);
    Mutex& operator=(const Mutex&);
};

#ifdef max
#   undef max
#endif// max

// アロケーション情報を格納するコンテナのアロケータが new / delete を使うと永久再起するので、
// hook を通さないメモリ確保を行うアロケータを用意
template<typename T>
class OrigHeapAllocator {
public : 
    //    typedefs
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

public : 
    //    convert an allocator<T> to allocator<U>
    template<typename U>
    struct rebind {
        typedef OrigHeapAllocator<U> other;
    };

public : 
    OrigHeapAllocator() {}
    OrigHeapAllocator(const OrigHeapAllocator&) {}
    template<typename U> OrigHeapAllocator(const OrigHeapAllocator<U>&) {}
    ~OrigHeapAllocator() {}

    pointer address(reference r) { return &r; }
    const_pointer address(const_reference r) { return &r; }

    pointer allocate(size_type cnt, const void *p=NULL) { p; return (pointer)HeapAlloc_Orig((HANDLE)_get_heap_handle(), 0, cnt * sizeof(T)); }
    void deallocate(pointer p, size_type) {  HeapFree_Orig((HANDLE)_get_heap_handle(), 0, p); }

    size_type max_size() const { return std::numeric_limits<size_type>::max() / sizeof(T); }

    void construct(pointer p, const T& t) { new(p) T(t); }
    void destroy(pointer p) { p; p->~T(); }

    bool operator==(OrigHeapAllocator const&) { return true; }
    bool operator!=(OrigHeapAllocator const& a) { return !operator==(a); }
};
template<class T, typename Alloc> inline bool operator==(const OrigHeapAllocator<T>& l, const OrigHeapAllocator<T>& r) { return (l.equals(r)); }
template<class T, typename Alloc> inline bool operator!=(const OrigHeapAllocator<T>& l, const OrigHeapAllocator<T>& r) { return (!(l == r)); }
typedef std::basic_string<char, std::char_traits<char>, OrigHeapAllocator<char> > TempString;
typedef std::vector<TempString, OrigHeapAllocator<TempString> > StringCont;




// write protect がかかったメモリ領域を強引に書き換える
template<class T> inline void ForceWrite(T &dst, const T &src)
{
    DWORD old_flag;
    VirtualProtect(&dst, sizeof(T), PAGE_EXECUTE_READWRITE, &old_flag);
    dst = src;
    VirtualProtect(&dst, sizeof(T), old_flag, &old_flag);
}


// dllname: 大文字小文字区別しません
// F: functor。引数は (const char *funcname, void *&imp_func)
template<class F>
bool EachImportFunction(HMODULE module, const char *dllname, const F &f)
{
    if(module==0) { return false; }

    size_t ImageBase = (size_t)module;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE) { return false; }
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(ImageBase + pDosHeader->e_lfanew);

    size_t RVAImports = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(RVAImports==0) { return false; }

    IMAGE_IMPORT_DESCRIPTOR *pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(ImageBase + RVAImports);
    while(pImportDesc->Name != 0) {
        if(stricmp((const char*)(ImageBase+pImportDesc->Name), dllname)==0) {
            IMAGE_IMPORT_BY_NAME **func_names = (IMAGE_IMPORT_BY_NAME**)(ImageBase+pImportDesc->Characteristics);
            void **import_table = (void**)(ImageBase+pImportDesc->FirstThunk);
            for(size_t i=0; ; ++i) {
                if((size_t)func_names[i] == 0) { break;}
                const char *funcname = (const char*)(ImageBase+(size_t)func_names[i]->Name);
                f(funcname, import_table[i]);
            }
        }
        ++pImportDesc;
    }
    return true;
}

template<class F>
void EachImportFunctionInEveryModule(const char *dllname, const F &f)
{
    std::vector<HMODULE> modules;
    DWORD num_modules;
    ::EnumProcessModules(::GetCurrentProcess(), NULL, 0, &num_modules);
    modules.resize(num_modules/sizeof(HMODULE));
    ::EnumProcessModules(::GetCurrentProcess(), &modules[0], num_modules, &num_modules);
    for(size_t i=0; i<modules.size(); ++i) {
        EachImportFunction<F>(modules[i], dllname, f);
    }
}


void HookHeapAlloc(const StringCont &modules)
{
    for(size_t i=0; i<modules.size(); ++i) {
        EachImportFunction(::GetModuleHandleA(modules[i].c_str()), "kernel32.dll", [](const char *funcname, void *&imp_func){
            if(strcmp(funcname, "HeapAlloc")==0) {
                ForceWrite<void*>(imp_func, HeapAlloc_Hooked);
            }
            else if(strcmp(funcname, "HeapFree")==0) {
                ForceWrite<void*>(imp_func, HeapFree_Hooked);
            }
        });
    }
}

void UnhookHeapAlloc(const StringCont &modules)
{
    for(size_t i=0; i<modules.size(); ++i) {
        EachImportFunction(::GetModuleHandleA(modules[i].c_str()), "kernel32.dll", [](const char *funcname, void *&imp_func){
            if(strcmp(funcname, "HeapAlloc")==0) {
                ForceWrite<void*>(imp_func, HeapAlloc_Orig);
            }
            else if(strcmp(funcname, "HeapFree")==0) {
                ForceWrite<void*>(imp_func, HeapFree_Orig);
            }
        });
    }
}

class MemoryLeakBuster
{
public:
    // アロケート時の callstack を保持
    struct AllocInfo
    {
        void *location;
        size_t bytes;
        void *callstack[MaxCallstackDepth];
        int callstack_size;
        int id;
        int count;

        bool less_callstack(const AllocInfo &v) const {
            if(callstack_size==v.callstack_size) {
                return memcmp(callstack, v.callstack, sizeof(void*)*callstack_size)<0;
            }
            else {
                return callstack_size < v.callstack_size;
            }
        }
        bool equal_callstack(const AllocInfo &v) const {
            return callstack_size==v.callstack_size && memcmp(callstack, v.callstack, sizeof(void*)*callstack_size)==0;
        }
    };
    struct less_callstack { bool operator()(const AllocInfo &a, const AllocInfo &b) { return a.less_callstack(b); }; };
    typedef std::map<void*, AllocInfo, std::less<void*>, OrigHeapAllocator<std::pair<const void*, AllocInfo> > > AllocTable;
    typedef std::set<AllocInfo, less_callstack, OrigHeapAllocator<AllocInfo> > CountTable;

    MemoryLeakBuster()
        : m_logfile(NULL)
        , m_mutex(NULL)
        , m_leakinfo(NULL)
        , m_counter(NULL)
        , m_idgen(0)
        , m_scope(INT_MAX)
    {
        HeapAlloc_Orig = &HeapAlloc;
        HeapFree_Orig = &HeapFree;

        if(!loadConfig()) { return; }

        InitializeDebugSymbol();

        // CRT モジュールの中の import table の HeapAlloc/Free を塗り替えて hook を仕込む
        HookHeapAlloc(*m_modules);
        m_mutex = mlbNew<Mutex>();
        m_leakinfo = mlbNew<AllocTable>();
    }

    ~MemoryLeakBuster()
    {
        if(!m_mutex) { return; }
        Mutex::ScopedLock l(*m_mutex);

        printLeakInfo();

        // hook を解除
        // 解除しないとアンロード時にメモリ解放する系の dll などが g_memory_leak_buster 破棄後に
        // eraseAllocationInfo() を呼ぶため、問題が起きる
        UnhookHeapAlloc(*m_modules);

        mlbDelete(m_leakinfo); m_leakinfo=NULL;
        mlbDelete(m_ignores);  m_ignores=NULL;
        mlbDelete(m_modules);  m_modules=NULL;

        // m_mutex は開放しません
        // 別スレッドから HeapFree_Hooked() が呼ばれて mutex を待ってる間に
        // ここでその mutex を破棄してしまうとクラッシュしてしまうためです。

        enbaleFileOutput(false);
        FinalizeDebugSymbol();
    }

    bool loadConfig()
    {
        m_modules = mlbNew<StringCont>();
        m_ignores = mlbNew<StringCont>();
        for(size_t i=0; i<_countof(g_target_modules); ++i) {
            m_modules->push_back(g_target_modules[i]);
        }
        for(size_t i=0; i<_countof(g_ignore_list); ++i) {
            m_ignores->push_back(g_ignore_list[i]);
        }

        bool ret = true;
        char buf[256];
        if(FILE *f=fopen("mlbConfig.txt", "r")) {
            int i;
            char s[128];
            while(fgets(buf, _countof(buf), f)) {
                if     (sscanf_s(buf, "disable: %d", &i)==1)        { if(i==1) { ret=false; break; } }
                else if(sscanf_s(buf, "fileoutput: %d", &i)==1)     { enbaleFileOutput(i!=0); }
                else if(sscanf_s(buf, "ignore: \"%[^\"]\"", s)==1)  { m_ignores->push_back(s); }
                else if(sscanf_s(buf, "module: \"%[^\"]\"", s)==1)  { m_modules->push_back(s); }
            }
            fclose(f);
        }
        if(!ret) {
            mlbDelete(m_ignores); m_ignores=NULL;
            mlbDelete(m_modules); m_modules=NULL;
        }
        return ret;
    }

    void enbaleFileOutput(bool v)
    {
        if(v && m_logfile==NULL) {
            m_logfile = fopen("mlbLog.txt", "wb");
        }
        else if(!v && m_logfile!=NULL) {
            fclose(m_logfile);
            m_logfile = NULL;
        }
    }

    void addAllocInfo(void *p, size_t size)
    {
        AllocInfo cs;
        cs.location = p;
        cs.bytes = size;
        cs.callstack_size = GetCallstack(cs.callstack, _countof(cs.callstack), 3);
        cs.count = 0;
        {
            Mutex::ScopedLock l(*m_mutex);
            if(m_leakinfo==NULL) { return; } // マルチスレッドの時デストラクタが呼ばれた後に来る可能性があるので必要なチェック
            cs.id = ++m_idgen;
            (*m_leakinfo)[p] = cs;

            if(m_counter) {
                auto r = m_counter->insert(cs);
                const_cast<AllocInfo&>(*r.first).count++;
            }
        }
    }

    void eraseAllocInfo(void *p)
    {
        Mutex::ScopedLock l(*m_mutex);
        if(m_leakinfo==NULL) { return; }
        m_leakinfo->erase(p);
    }

    void inspect(void *p) const
    {
        if(IsStaticMemory(p)) { OutputDebugStringA("static memory\n"); return; }
        if(IsStackMemory(p))  { OutputDebugStringA("stack memory\n");  return; }

        const AllocInfo *r = NULL;
        const void *neighbor[2] = {NULL, NULL};
        {
            Mutex::ScopedLock l(*m_mutex);
            if(m_leakinfo==NULL) { return; }
            for(auto li=m_leakinfo->begin(); li!=m_leakinfo->end(); ++li) {
                const AllocInfo &ai = li->second;
                if(p>=ai.location && (size_t)p<=(size_t)ai.location+ai.bytes) {
                    r = &ai;
                    if(li!=m_leakinfo->begin()) { auto prev=li; --prev; neighbor[0]=prev->second.location; }
                    if(li!=m_leakinfo->end())   { auto next=li; ++next; neighbor[1]=next->second.location; }
                    break;
                }
            }
        }

        if(r==NULL) {
            OutputDebugStringA("no information.\n");
            return;
        }
        char buf[128];
        TempString text;
        text.reserve(1024*16);
        sprintf_s(buf, "0x%p (%llu byte) ", r->location, (unsigned long long)r->bytes); text+=buf;
        sprintf_s(buf, "prev: 0x%p next: 0x%p\n", neighbor[0], neighbor[1]); text+=buf;
        CallstackToSymbolNames(text, r->callstack, r->callstack_size);
        text += "\n";

        OutputDebugStringA(text.c_str());
    }

    void printLeakInfo() const
    {
        Mutex::ScopedLock l(*m_mutex);
        if(m_leakinfo==NULL) { return; }

        char buf[128];
        TempString text;
        text.reserve(1024*16);
        for(auto li=m_leakinfo->begin(); li!=m_leakinfo->end(); ++li) {
            const AllocInfo &ai = li->second;

            text.clear();
            sprintf_s(buf, "memory leak: 0x%p (%llu byte)\n", ai.location, (unsigned long long)ai.bytes);
            text += buf;
            CallstackToSymbolNames(text, ai.callstack, ai.callstack_size);
            text += "\n";
            if(!shouldBeIgnored(text)) {
                output(text.c_str(), text.size());
            }
        }
    }


    void beginScope()
    {
        m_scope = m_idgen;
    }

    void endScope()
    {
        Mutex::ScopedLock l(*m_mutex);
        if(m_leakinfo==NULL) { return; }

        char buf[128];
        TempString text;
        text.reserve(1024*16);
        for(auto li=m_leakinfo->begin(); li!=m_leakinfo->end(); ++li) {
            const AllocInfo &ai = li->second;
            if(ai.id<m_scope) { continue; }

            text.clear();
            sprintf_s(buf, "maybe a leak: 0x%p (%llu byte)\n", ai.location, (unsigned long long)ai.bytes);
            text += buf;
            CallstackToSymbolNames(text, ai.callstack, ai.callstack_size);
            text += "\n";
            if(!shouldBeIgnored(text)) {
                output(text.c_str(), text.size());
            }
        }
        m_scope = INT_MAX;
    }


    void beginCount()
    {
        Mutex::ScopedLock l(*m_mutex);
        if(m_counter!=NULL) { return; }
        m_counter = mlbNew<CountTable>();
    }

    void endCount()
    {
        Mutex::ScopedLock l(*m_mutex);
        if(m_counter==NULL) { return; }

        int total = 0;
        char buf[128];
        TempString text;
        text.reserve(1024*16);
        for(auto li=m_counter->begin(); li!=m_counter->end(); ++li) {
            const AllocInfo &ai = *li;

            text.clear();
            sprintf_s(buf, "%d times from\n", ai.count);
            text += buf;
            CallstackToSymbolNames(text, ai.callstack, ai.callstack_size);
            text += "\n";
            output(text.c_str(), text.size());
            total += ai.count;
        }
        sprintf_s(buf, "total %d times\n", total);
        output(buf);

        mlbDelete(m_counter); m_counter=NULL;
    }


    bool shouldBeIgnored(const TempString &callstack) const
    {
        for(size_t i=0; i<m_ignores->size(); ++i) {
            if(callstack.find((*m_ignores)[i].c_str())!=std::string::npos) {
                return true;
            }
        }
        return false;
    }

    void output(const char *str, size_t len=0) const
    {
        if(m_logfile) {
            if(len==0) { len=strlen(str); }
            fwrite(str, 1, len, m_logfile);
        }
        else {
            OutputDebugStringA(str);
        }
    }

private:
    FILE *m_logfile;
    Mutex *m_mutex;
    AllocTable *m_leakinfo;
    CountTable *m_counter;
    StringCont *m_modules;
    StringCont *m_ignores;
    int m_idgen;
    int m_scope;
};

// global 変数にすることで main 開始前に初期化、main 抜けた後に終了処理をさせる。
MemoryLeakBuster g_mlb;


LPVOID WINAPI HeapAlloc_Hooked( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes )
{
    LPVOID p = HeapAlloc_Orig(hHeap, dwFlags, dwBytes);
    g_mlb.addAllocInfo(p, dwBytes);
    return p;
}

BOOL WINAPI HeapFree_Hooked( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem )
{
    BOOL r = HeapFree_Orig(hHeap, dwFlags, lpMem);
    g_mlb.eraseAllocInfo(lpMem);
    return r;
}

} /// namespace mlb

using namespace mlb;


// イミディエイトウィンドウから実行可能な関数群
mlbForceLink void mlbInspect(void *p)       { g_mlb.inspect(p); }
mlbForceLink void mlbBeginScope()           { g_mlb.beginScope(); }
mlbForceLink void mlbEndScope()             { g_mlb.endScope(); }
mlbForceLink void mlbBeginCount()           { g_mlb.beginCount(); }
mlbForceLink void mlbEndCount()             { g_mlb.endCount(); }
mlbForceLink void mlbOutputToFile(bool v)   { g_mlb.enbaleFileOutput(v); }
