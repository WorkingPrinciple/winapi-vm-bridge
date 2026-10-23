#ifndef WVB_CLIENT_UNIX_H
#define WVB_CLIENT_UNIX_H

#include "wvb_client.h"

/* Private, in-process x64 Wine arguments; not a Bridge wire format. */
enum {
  WVB_UNIX_LOAD_CONFIG = 0,
  WVB_UNIX_CLIENT_CONFIGURE = 1,
  WVB_UNIX_CLIENT_BIND = 2,
  WVB_UNIX_CLIENT_CALL = 3,
  WVB_UNIX_CLIENT_CALL_EX = 4,
  WVB_UNIX_CLIENT_RESET = 5,
  WVB_UNIX_ENTRY_COUNT = 6
};

typedef struct {
  const WvbClientConfig *config;
  WvbStatus status;
} WvbUnixClientConfigure;

typedef struct {
  const uint8_t *adapter_hash;
  uint32_t operation_id;
  uint32_t request_schema_id;
  uint32_t response_schema_id;
  WvbStatus status;
} WvbUnixClientBind;

typedef struct {
  const uint8_t *adapter_hash;
  uint32_t operation_id;
  const uint8_t *request;
  size_t request_len;
  uint8_t *response;
  size_t response_cap;
  size_t *response_len;
  int32_t *dispatch_status;
  WvbStatus status;
} WvbUnixClientCall;

typedef struct {
  WvbStatus status;
} WvbUnixClientReset;

_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8,
               "client forwarding requires native x64 Wine");
_Static_assert(sizeof(WvbClientConfig) == 160 &&
                   offsetof(WvbClientConfig, broker_address) == 8 &&
                   offsetof(WvbClientConfig, connect_timeout_ms) == 152,
               "client configuration ABI");
_Static_assert(sizeof(WvbUnixClientConfigure) == 16 &&
                   offsetof(WvbUnixClientConfigure, status) == 8,
               "configure argument ABI");
_Static_assert(sizeof(WvbUnixClientBind) == 24 &&
                   offsetof(WvbUnixClientBind, status) == 20,
               "binding argument ABI");
_Static_assert(sizeof(WvbUnixClientCall) == 72 &&
                   offsetof(WvbUnixClientCall, request) == 16 &&
                   offsetof(WvbUnixClientCall, response_len) == 48 &&
                   offsetof(WvbUnixClientCall, dispatch_status) == 56 &&
                   offsetof(WvbUnixClientCall, status) == 64,
               "call argument ABI");
_Static_assert(sizeof(WvbUnixClientReset) == 4, "reset argument ABI");

typedef int32_t (*WvbUnixClientEntry)(void *);
extern const WvbUnixClientEntry __wine_unix_call_funcs[WVB_UNIX_ENTRY_COUNT];
extern const WvbUnixClientEntry
    __wine_unix_call_wow64_funcs[WVB_UNIX_ENTRY_COUNT];

#endif
