#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef int32_t WvbStatus;
enum { WVB_STATUS_OK = 0 };
WvbStatus wvb_client_call(const uint8_t adapter_hash[32], uint32_t operation_id,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t response_cap,
                          size_t *response_len);
#ifdef __cplusplus
}
#endif
