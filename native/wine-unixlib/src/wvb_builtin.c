#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wine/unixlib.h>

#include <stdint.h>
#include <string.h>

#include "wvb_autoconfig.h"
#include "wvb_unix_runtime.h"

static void zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (length--) {
    *bytes++ = 0;
  }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
    if (__wine_init_unix_call() || !__wine_unixlib_handle) {
      return FALSE;
    }
  }
  return TRUE;
}

int32_t __cdecl wvb_builtin_load_config(const char *account,
                                        WvbAutoConfig *config) {
  if (!account || !account[0] || strlen(account) >= 128 || !config) {
    return WVB_AUTOCONFIG_INVALID_ARGUMENT;
  }
  if (!__wine_unixlib_handle) {
    return WVB_AUTOCONFIG_UNIXLIB_LOAD_FAILED;
  }
  WvbUnixLoadArgs args = {0};
  memcpy(args.account, account, strlen(account) + 1);
  const NTSTATUS status = WINE_UNIX_CALL(0, &args);
  if (status) {
    zero(&args, sizeof(args));
    SetLastError((DWORD)status);
    return WVB_AUTOCONFIG_KEYCHAIN_FAILED;
  }
  if (!wvb_runtime_record_valid(&args.record)) {
    zero(&args, sizeof(args));
    SetLastError(ERROR_INVALID_DATA);
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
