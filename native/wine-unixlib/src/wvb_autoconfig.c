#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include <stdint.h>
#include <string.h>

#include "wvb_autoconfig.h"

#define MEMORY_WINE_LOAD_UNIX_LIB_BY_NAME 1002
#define MEMORY_WINE_UNLOAD_UNIX_LIB 1004

typedef LONG NTSTATUS;
typedef uint64_t unixlib_handle_t;
typedef uint64_t unixlib_module_t;
typedef NTSTATUS(WINAPI *unix_dispatch_fn)(unixlib_handle_t, unsigned int,
                                           void *);
typedef NTSTATUS(NTAPI *nt_query_virtual_memory_fn)(
    HANDLE, const void *, int, void *, SIZE_T, SIZE_T *);
typedef NTSTATUS(WINAPI *wine_load_unix_lib_fn)(
    const UNICODE_STRING *, unixlib_module_t *, unixlib_handle_t *);

typedef struct WvbKeychainRecordV1 {
  uint32_t magic;
  uint16_t version;
  uint16_t state;
  char broker_address[64];
  uint8_t client_private_key[32];
  uint8_t broker_public_key[32];
  uint8_t actor_id[16];
  uint8_t client_instance[16];
  uint8_t build_fingerprint[32];
  uint32_t connect_timeout_ms;
  uint32_t call_timeout_ms;
} WvbKeychainRecordV1;

typedef struct WvbUnixLoadArgs {
  char account[128];
  WvbKeychainRecordV1 record;
} WvbUnixLoadArgs;

static void zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (length--) {
    *bytes++ = 0;
  }
}

int32_t wvb_auto_config_load(const wchar_t *unixlib_path,
                             const char *account,
                             WvbAutoConfig *config) {
  if (!unixlib_path || !unixlib_path[0] || !account || !account[0] ||
      !config || strlen(account) >= 128) {
    return WVB_AUTOCONFIG_INVALID_ARGUMENT;
  }
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) {
    return WVB_AUTOCONFIG_WINE_API_UNAVAILABLE;
  }
  const FARPROC query_symbol =
      GetProcAddress(ntdll, "NtQueryVirtualMemory");
  const FARPROC dispatcher_symbol =
      GetProcAddress(ntdll, "__wine_unix_call_dispatcher");
  const FARPROC load_symbol =
      GetProcAddress(ntdll, "__wine_load_unix_lib");
  nt_query_virtual_memory_fn query = NULL;
  wine_load_unix_lib_fn load_unix_lib = NULL;
  unix_dispatch_fn *dispatcher_pointer = NULL;
  _Static_assert(sizeof(query) == sizeof(query_symbol), "function pointer size");
  _Static_assert(sizeof(dispatcher_pointer) == sizeof(dispatcher_symbol),
                 "data pointer size");
  _Static_assert(sizeof(load_unix_lib) == sizeof(load_symbol),
                 "load function pointer size");
  memcpy(&query, &query_symbol, sizeof(query));
  memcpy(&dispatcher_pointer, &dispatcher_symbol,
         sizeof(dispatcher_pointer));
  memcpy(&load_unix_lib, &load_symbol, sizeof(load_unix_lib));
  if (!query || !dispatcher_pointer || !*dispatcher_pointer) {
    return WVB_AUTOCONFIG_WINE_API_UNAVAILABLE;
  }
  UNICODE_STRING name;
  const size_t path_chars = wcslen(unixlib_path);
  if (path_chars > UINT16_MAX / sizeof(wchar_t)) {
    return WVB_AUTOCONFIG_INVALID_ARGUMENT;
  }
  name.Length = (USHORT)(path_chars * sizeof(wchar_t));
  name.MaximumLength = name.Length + sizeof(wchar_t);
  name.Buffer = (PWSTR)unixlib_path;
  uint64_t loaded[2] = {0, 0};
  NTSTATUS status;
  if (load_unix_lib) {
    status = load_unix_lib(&name, &loaded[0], &loaded[1]);
  } else {
    status = query(GetCurrentProcess(), &name,
                   MEMORY_WINE_LOAD_UNIX_LIB_BY_NAME, loaded,
                   sizeof(loaded), NULL);
  }
  if (status || !loaded[0] || !loaded[1]) {
    SetLastError((DWORD)status);
    return WVB_AUTOCONFIG_UNIXLIB_LOAD_FAILED;
  }
  WvbUnixLoadArgs args = {0};
  memcpy(args.account, account, strlen(account) + 1);
  status = (*dispatcher_pointer)(loaded[1], 0, &args);
  query(GetCurrentProcess(), &loaded[0], MEMORY_WINE_UNLOAD_UNIX_LIB,
        NULL, 0, NULL);
  if (status) {
    zero(&args, sizeof(args));
    return WVB_AUTOCONFIG_KEYCHAIN_FAILED;
  }
  memcpy(config->broker_address, args.record.broker_address,
         sizeof(config->broker_address));
  memcpy(config->client_private_key, args.record.client_private_key,
         sizeof(config->client_private_key));
  memcpy(config->broker_public_key, args.record.broker_public_key,
         sizeof(config->broker_public_key));
  memcpy(config->actor_id, args.record.actor_id, sizeof(config->actor_id));
  memcpy(config->client_instance, args.record.client_instance,
         sizeof(config->client_instance));
  memcpy(config->build_fingerprint, args.record.build_fingerprint,
         sizeof(config->build_fingerprint));
  config->connect_timeout_ms = args.record.connect_timeout_ms;
  config->call_timeout_ms = args.record.call_timeout_ms;
  zero(&args, sizeof(args));
  return WVB_AUTOCONFIG_OK;
}
