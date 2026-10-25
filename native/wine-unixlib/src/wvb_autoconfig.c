#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <string.h>

#include "wvb_autoconfig.h"

typedef int32_t (__cdecl *builtin_load_fn)(const char *, WvbAutoConfig *);

int32_t wvb_auto_config_load(const wchar_t *builtin_path,
                            const char *account,
                            WvbAutoConfig *config) {
  if (!builtin_path || !builtin_path[0] || !account || !account[0] ||
      !config || strlen(account) >= 128) {
    return WVB_AUTOCONFIG_INVALID_ARGUMENT;
  }
  HMODULE module = LoadLibraryExW(
      builtin_path, NULL,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  if (!module) {
    return WVB_AUTOCONFIG_UNIXLIB_LOAD_FAILED;
  }
  const FARPROC symbol = GetProcAddress(module, "wvb_builtin_load_config");
  builtin_load_fn load = NULL;
  _Static_assert(sizeof(load) == sizeof(symbol), "function pointer size");
  memcpy(&load, &symbol, sizeof(load));
  int32_t status;
  DWORD error;
  if (load) {
    status = load(account, config);
    error = GetLastError();
  } else {
    status = WVB_AUTOCONFIG_WINE_API_UNAVAILABLE;
    error = ERROR_PROC_NOT_FOUND;
  }
  FreeLibrary(module);
  SetLastError(error);
  return status;
}
