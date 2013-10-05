#include <windows.h>

// 指定の関数の先頭に現在のスレッドを suspend するコードをねじ込む
bool SetThreadTrap(HANDLE process, void *target); // target: hotpatch 可能な関数のアドレス
bool SetThreadTrap(HANDLE process, const char *sym_name); // sym_name: hotpatch 可能な関数のシンボル名

// SetThreadTrap() でねじ込んだ suspend コードを解除
bool UnsetThreadTrap(HANDLE process, void *target);
bool UnsetThreadTrap(HANDLE process, const char *sym_name);
