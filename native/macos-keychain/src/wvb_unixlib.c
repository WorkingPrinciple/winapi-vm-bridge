#include "wvb_keychain.h"
#include "wvb_unix_runtime.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef int32_t NTSTATUS;
typedef NTSTATUS (*unixlib_entry_t)(void *args);

enum {
  STATUS_SUCCESS = 0,
  STATUS_INVALID_PARAMETER = (int32_t)0xc000000d,
  STATUS_NOT_FOUND = (int32_t)0xc0000225,
  STATUS_UNSUCCESSFUL = (int32_t)0xc0000001
};

int32_t wvb_unix_load_runtime_config(WvbUnixLoadArgs *args) {
  if (!args || !args->account[0] ||
      !memchr(args->account, '\0', sizeof(args->account))) {
    return STATUS_INVALID_PARAMETER;
  }
  size_t length = 0;
  const int32_t status =
      wvb_keychain_load(args->account, (uint8_t *)&args->record,
                        sizeof(args->record), &length);
  if (status == WVB_KEYCHAIN_NOT_FOUND) {
    return STATUS_NOT_FOUND;
  }
  if (status != WVB_KEYCHAIN_OK || length != sizeof(args->record)) {
    memset(&args->record, 0, sizeof(args->record));
    return STATUS_UNSUCCESSFUL;
  }
  if (args->record.magic != WVB_KEYCHAIN_RECORD_MAGIC ||
      args->record.version != WVB_KEYCHAIN_RECORD_VERSION ||
      args->record.state != WVB_KEYCHAIN_RECORD_ACTIVE ||
      !memchr(args->record.broker_address, '\0',
              sizeof(args->record.broker_address))) {
    memset(&args->record, 0, sizeof(args->record));
    return STATUS_INVALID_PARAMETER;
  }
  return STATUS_SUCCESS;
}

#ifndef WVB_EXTERNAL_UNIX_CALL_TABLE
static NTSTATUS load_runtime_config(void *args) {
  return wvb_unix_load_runtime_config((WvbUnixLoadArgs *)args);
}

__attribute__((visibility("default"))) const unixlib_entry_t
    __wine_unix_call_funcs[] = {load_runtime_config};

__attribute__((visibility("default"))) const unixlib_entry_t
    __wine_unix_call_wow64_funcs[] = {load_runtime_config};
#endif
