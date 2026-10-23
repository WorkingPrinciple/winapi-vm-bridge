#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>

int wmain(void) {
  HMODULE module =
      LoadLibraryExW(L"wvb_autoconfig.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!module) {
    printf("a08-loader=failed stage=load error=%lu\n",
           (unsigned long)GetLastError());
    return 70;
  }

  FARPROC entry = GetProcAddress(module, "wvb_builtin_load_config");
  if (!entry) {
    const DWORD error = GetLastError();
    FreeLibrary(module);
    printf("a08-loader=failed stage=export error=%lu\n", (unsigned long)error);
    return 71;
  }

  wchar_t path[1024];
  const DWORD length =
      GetModuleFileNameW(module, path, (DWORD)(sizeof(path) / sizeof(path[0])));
  if (!length || length >= sizeof(path) / sizeof(path[0])) {
    const DWORD error = GetLastError();
    FreeLibrary(module);
    printf("a08-loader=failed stage=module-path error=%lu\n",
           (unsigned long)error);
    return 72;
  }

  printf("a08-loader=loaded export=present windows-pid=%lu module=%ls\n",
         (unsigned long)GetCurrentProcessId(), path);
  fflush(stdout);
  Sleep(10000);
  if (!FreeLibrary(module)) {
    printf("a08-loader=failed stage=unload error=%lu\n",
           (unsigned long)GetLastError());
    return 73;
  }
  puts("a08-loader=unloaded");
  return 0;
}
