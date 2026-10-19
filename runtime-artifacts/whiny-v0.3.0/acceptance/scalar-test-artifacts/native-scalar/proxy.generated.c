#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "wvb_client.h"
#define WHINY_EXPORT __declspec(dllexport)
static void wvb_store_le(uint8_t *out, const void *value, size_t size) { memcpy(out, value, size); }
static void wvb_load_le(void *out, const uint8_t *value, size_t size) { memcpy(out, value, size); }

static const uint8_t WHINY_ADAPTER_HASH[32] = {0xb4,0x0c,0xa1,0x32,0x72,0xe1,0xb0,0xce,0x29,0xa8,0xdd,0x48,0x9a,0x22,0xe7,0x27,0xdb,0x28,0x79,0x81,0xa7,0xd2,0xd2,0xd2,0xe4,0x83,0x01,0xe5,0xd6,0xe9,0x6c,0x47};

WHINY_EXPORT int32_t WINAPI add(int32_t left, int32_t right) {
  uint8_t request[8] = {0};
  wvb_store_le(request + 0, &left, 4);
  wvb_store_le(request + 4, &right, 4);
  uint8_t response[4] = {0};
  size_t response_len = 0;
  WvbStatus status = wvb_client_call(WHINY_ADAPTER_HASH, 1, request, 8, response, sizeof(response), &response_len);
  if (status != WVB_STATUS_OK || response_len != sizeof(response)) { SetLastError(ERROR_GEN_FAILURE); return (int32_t)0; }
  int32_t result = (int32_t)0;
  wvb_load_le(&result, response, sizeof(result));
  return result;
}
