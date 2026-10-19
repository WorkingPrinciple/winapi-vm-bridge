#ifndef WVB_UNIX_RUNTIME_H
#define WVB_UNIX_RUNTIME_H

#include <stdint.h>

#define WVB_KEYCHAIN_RECORD_MAGIC 0x32425657u
#define WVB_KEYCHAIN_RECORD_VERSION 1u
#define WVB_KEYCHAIN_RECORD_ACTIVE 1u

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

#if defined(__APPLE__)
#define WVB_UNIX_EXPORT __attribute__((visibility("default")))
#else
#define WVB_UNIX_EXPORT
#endif

WVB_UNIX_EXPORT int32_t
wvb_unix_load_runtime_config(WvbUnixLoadArgs *args);

#endif
