#ifndef WVB_TEST_WINDOWS_H
#define WVB_TEST_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>
#define WINAPI
#define __cdecl
#define TRUE 1
#define FALSE 0
#define DLL_PROCESS_ATTACH 1
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 0x100
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS 0x1000
#define ERROR_INVALID_DATA 13
#define ERROR_PROC_NOT_FOUND 127
#define ERROR_DLL_INIT_FAILED 1114
typedef int BOOL;
typedef uint32_t DWORD;
typedef int32_t NTSTATUS;
typedef void *HINSTANCE;
typedef void *HMODULE;
typedef void (*FARPROC)(void);
BOOL DisableThreadLibraryCalls(HINSTANCE instance);
HMODULE LoadLibraryExW(const wchar_t *path, void *file, DWORD flags);
FARPROC GetProcAddress(HMODULE module, const char *name);
BOOL FreeLibrary(HMODULE module);
void SetLastError(DWORD error);
DWORD GetLastError(void);
DWORD GetCurrentProcessId(void);
DWORD GetModuleFileNameW(HMODULE module, wchar_t *path, DWORD capacity);
void Sleep(DWORD milliseconds);
#endif
