#pragma once
#include <stddef.h>
#include <stdint.h>
#define WVB_CLIENT_HAS_HANDLE_CLOSE 1
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
  WVB_STATUS_PANIC = -5,
  WVB_STATUS_DISPATCH_ERROR = -6,
  WVB_STATUS_PROTOCOL_ERROR = -7,
  WVB_STATUS_OPERATION_NOT_BOUND = -8
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
  /* One setup deadline for TCP, Noise and authenticated ready HELLO_ACK.
   * A listening socket alone does not mean the native backend is ready. */
  uint32_t connect_timeout_ms;
  uint32_t call_timeout_ms;
} WvbClientConfig;
WvbStatus wvb_client_configure(const WvbClientConfig *config);
/* Exact frozen/admitted schema IDs; no invocation authority is granted.
 * Configure/reset clears bindings. Rebinding with different IDs is rejected. */
WvbStatus wvb_client_bind_operation(const uint8_t adapter_hash[32],
                                    uint32_t operation_id,
                                    uint32_t request_schema_id,
                                    uint32_t response_schema_id);
WvbStatus wvb_client_call(const uint8_t adapter_hash[32], uint32_t operation_id,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t response_cap,
                          size_t *response_len);
/* dispatch_status is whiny.dispatch.v1 execution status, NOT target API status.
 * Failed dispatch/protocol/transport never copies response bytes.
 * response_len is zero on failure, except insufficient buffer reports required
 * capacity. Validate the operation-specific body length before consuming it.
 * dispatch_status is meaningful on OK, INSUFFICIENT_BUFFER or DISPATCH_ERROR. */
WvbStatus wvb_client_call_ex(const uint8_t adapter_hash[32], uint32_t operation_id,
                             const uint8_t *request, size_t request_len,
                             uint8_t *response, size_t response_cap,
                             size_t *response_len, int32_t *dispatch_status);
WvbStatus wvb_client_reset(void);
/* token is epoch[16], slot/generation/type u32LE; authenticated actor is implicit.
 * No retry. Native close status is meaningful only after a complete response. */
WvbStatus wvb_client_handle_close(const uint8_t token[28], int32_t *native_status);
#ifdef __cplusplus
}
#endif
