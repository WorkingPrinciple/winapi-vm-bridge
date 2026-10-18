#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef int32_t WvbStatus;
enum {
  WVB_STATUS_OK = 0,
  WVB_STATUS_INVALID_ARGUMENT = -1,
  WVB_STATUS_NOT_CONFIGURED = -2,
  WVB_STATUS_RUNTIME_ERROR = -3,
  WVB_STATUS_INSUFFICIENT_BUFFER = -4,
  WVB_STATUS_PANIC = -5
};
typedef struct WvbClientConfig {
  uint32_t struct_size;
  const uint8_t *broker_address;
  size_t broker_address_len;
  uint8_t client_private_key[32];
  uint8_t broker_public_key[32];
  uint8_t actor_id[16];
  uint8_t client_instance[16];
  uint8_t build_fingerprint[32];
  uint32_t connect_timeout_ms;
  uint32_t call_timeout_ms;
} WvbClientConfig;
WvbStatus wvb_client_configure(const WvbClientConfig *config);
WvbStatus wvb_client_call(const uint8_t adapter_hash[32], uint32_t operation_id,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t response_cap,
                          size_t *response_len);
WvbStatus wvb_client_reset(void);
#ifdef __cplusplus
}
#endif
