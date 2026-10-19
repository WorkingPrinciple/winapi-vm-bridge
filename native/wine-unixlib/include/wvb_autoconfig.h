#ifndef WVB_AUTOCONFIG_H
#define WVB_AUTOCONFIG_H

#include <stddef.h>
#include <stdint.h>

typedef struct WvbAutoConfig {
  char broker_address[64];
  uint8_t client_private_key[32];
  uint8_t broker_public_key[32];
  uint8_t actor_id[16];
  uint8_t client_instance[16];
  uint8_t build_fingerprint[32];
  uint32_t connect_timeout_ms;
  uint32_t call_timeout_ms;
} WvbAutoConfig;

enum {
  WVB_AUTOCONFIG_OK = 0,
  WVB_AUTOCONFIG_INVALID_ARGUMENT = -1,
  WVB_AUTOCONFIG_WINE_API_UNAVAILABLE = -2,
  WVB_AUTOCONFIG_UNIXLIB_LOAD_FAILED = -3,
  WVB_AUTOCONFIG_KEYCHAIN_FAILED = -4
};

int32_t wvb_auto_config_load(const wchar_t *unixlib_path,
                             const char *account,
                             WvbAutoConfig *config);

#endif
