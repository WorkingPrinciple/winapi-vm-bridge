#include <windows.h>
#include <wine/unixlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "wvb_autoconfig.h"
#include "wvb_unix_runtime.h"

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved);
int32_t wvb_builtin_load_config(const char *account, WvbAutoConfig *config);

uint64_t __wine_unixlib_handle;
static NTSTATUS init_status;
static NTSTATUS unix_status;
static int empty_handle;
static int missing_export;
static int malformed_record;
static unsigned int init_calls;
static unsigned int unix_calls;
static unsigned int unload_calls;
static DWORD last_error;
static char module;

BOOL DisableThreadLibraryCalls(HINSTANCE instance) {
  assert(instance == &module);
  return TRUE;
}

NTSTATUS __wine_init_unix_call(void) {
  init_calls++;
  __wine_unixlib_handle = !init_status && !empty_handle ? 42 : 0;
  return init_status;
}

NTSTATUS wvb_test_unix_call(unsigned int code, void *value) {
  WvbUnixLoadArgs *args = value;
  assert(__wine_unixlib_handle == 42);
  assert(code == 0 && strcmp(args->account, "test-account") == 0);
  unix_calls++;
  args->record.magic = WVB_KEYCHAIN_RECORD_MAGIC;
  args->record.version = WVB_KEYCHAIN_RECORD_VERSION;
  args->record.state = WVB_KEYCHAIN_RECORD_ACTIVE;
  strcpy(args->record.broker_address, "127.0.0.1:1");
  args->record.connect_timeout_ms = 100;
  args->record.call_timeout_ms = 200;
  memset(args->record.client_private_key, 0xa5, 32);
  if (malformed_record) {
    args->record.magic = 0;
  }
  return unix_status;
}

HMODULE LoadLibraryExW(const wchar_t *path, void *file, DWORD flags) {
  assert(wcscmp(path, L"Z:\\fixture\\wvb_autoconfig.dll") == 0);
  assert(!file);
  assert(flags == (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                   LOAD_LIBRARY_SEARCH_DEFAULT_DIRS));
  if (!DllMain(&module, DLL_PROCESS_ATTACH, NULL)) {
    SetLastError(1114);
    return NULL;
  }
  return &module;
}

FARPROC GetProcAddress(HMODULE loaded, const char *name) {
  assert(loaded == &module);
  assert(strcmp(name, "wvb_builtin_load_config") == 0);
  if (missing_export) {
    return NULL;
  }
  int32_t (*load)(const char *, WvbAutoConfig *) = wvb_builtin_load_config;
  FARPROC symbol;
  _Static_assert(sizeof(load) == sizeof(symbol), "function pointer size");
  memcpy(&symbol, &load, sizeof(symbol));
  return symbol;
}

BOOL FreeLibrary(HMODULE loaded) {
  assert(loaded == &module);
  unload_calls++;
  SetLastError(999);
  return TRUE;
}

void SetLastError(DWORD error) { last_error = error; }
DWORD GetLastError(void) { return last_error; }

int main(void) {
  const wchar_t *path = L"Z:\\fixture\\wvb_autoconfig.dll";
  WvbAutoConfig config;
  memset(&config, 0xa5, sizeof(config));
  const WvbAutoConfig sentinel = config;
  assert(wvb_auto_config_load(NULL, "test-account", &config) ==
         WVB_AUTOCONFIG_INVALID_ARGUMENT);
  assert(!init_calls && !unix_calls);
  init_status = -1;
  assert(wvb_auto_config_load(path, "test-account", &config) ==
         WVB_AUTOCONFIG_UNIXLIB_LOAD_FAILED);
  assert(!unix_calls && !unload_calls);
  assert(GetLastError() == 1114);
  init_status = 0;
  empty_handle = 1;
  assert(wvb_auto_config_load(path, "test-account", &config) ==
         WVB_AUTOCONFIG_UNIXLIB_LOAD_FAILED);
  assert(!unix_calls);
  empty_handle = 0;
  missing_export = 1;
  assert(wvb_auto_config_load(path, "test-account", &config) ==
         WVB_AUTOCONFIG_WINE_API_UNAVAILABLE);
  assert(GetLastError() == ERROR_PROC_NOT_FOUND && !unix_calls);
  missing_export = 0;
  unix_status = -77;
  assert(wvb_auto_config_load(path, "test-account", &config) ==
         WVB_AUTOCONFIG_KEYCHAIN_FAILED);
  assert(GetLastError() == (DWORD)-77);
  assert(memcmp(&config, &sentinel, sizeof(config)) == 0);
  unix_status = 0;
  malformed_record = 1;
  assert(wvb_auto_config_load(path, "test-account", &config) ==
         WVB_AUTOCONFIG_KEYCHAIN_FAILED);
  assert(GetLastError() == ERROR_INVALID_DATA);
  assert(memcmp(&config, &sentinel, sizeof(config)) == 0);
  malformed_record = 0;
  assert(wvb_auto_config_load(path, "test-account", &config) == WVB_AUTOCONFIG_OK);
  assert(strcmp(config.broker_address, "127.0.0.1:1") == 0);
  assert(config.connect_timeout_ms == 100 && config.call_timeout_ms == 200);
  assert(config.client_private_key[0] == 0xa5 &&
         config.client_private_key[31] == 0xa5);
  assert(init_calls == 6 && unix_calls == 3 && unload_calls == 4);
  puts("builtin loader composition source tests passed (mock Wine SDK)");
  return 0;
}
