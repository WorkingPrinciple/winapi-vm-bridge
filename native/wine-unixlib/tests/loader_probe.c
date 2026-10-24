#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv) {
  if (argc < 1 || argc > 2 ||
      (argc == 2 &&
       (wcslen(argv[1]) < 3 ||
        !((argv[1][0] >= L'A' && argv[1][0] <= L'Z') ||
          (argv[1][0] >= L'a' && argv[1][0] <= L'z')) ||
        argv[1][1] != L':' ||
        (argv[1][2] != L'\\' && argv[1][2] != L'/')))) {
    fputs("expected no argument or one absolute Windows proxy path\n", stderr);
    return 74;
  }
  const wchar_t *requested = argc == 2 ? argv[1] : L"wvb_autoconfig.dll";
  const char *export_name = argc == 2 ? "add" : "wvb_builtin_load_config";
  HMODULE module =
      LoadLibraryExW(requested, NULL, 0);
  if (!module) {
    printf("a08-loader=failed stage=load error=%lu\n",
           (unsigned long)GetLastError());
    return 70;
  }

  FARPROC entry = GetProcAddress(module, export_name);
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

  printf("a08-loader=loaded export=present windows-pid=%lu module=%ls selected-export=%s\n",
         (unsigned long)GetCurrentProcessId(), path, export_name);
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
