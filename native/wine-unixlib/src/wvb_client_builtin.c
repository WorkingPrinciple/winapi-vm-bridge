#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wine/unixlib.h>

#include "wvb_client_unix.h"

static int forward(unsigned int code, void *args) {
  if (!__wine_unixlib_handle) {
    SetLastError(ERROR_DLL_INIT_FAILED);
    return 0;
  }
  const NTSTATUS status = WINE_UNIX_CALL(code, args);
  if (status) {
    SetLastError((DWORD)status);
    return 0;
  }
  return 1;
}

WvbStatus wvb_client_configure(const WvbClientConfig *config) {
  WvbUnixClientConfigure args = {config, WVB_STATUS_RUNTIME_ERROR};
  return forward(WVB_UNIX_CLIENT_CONFIGURE, &args) ? args.status
                                                  : WVB_STATUS_RUNTIME_ERROR;
}

WvbStatus wvb_client_bind_operation(const uint8_t adapter_hash[32],
                                    uint32_t operation_id,
                                    uint32_t request_schema_id,
                                    uint32_t response_schema_id) {
  WvbUnixClientBind args = {adapter_hash, operation_id, request_schema_id,
                           response_schema_id, WVB_STATUS_RUNTIME_ERROR};
  return forward(WVB_UNIX_CLIENT_BIND, &args) ? args.status
                                             : WVB_STATUS_RUNTIME_ERROR;
}

static WvbStatus call(unsigned int code, WvbUnixClientCall *args) {
  if (!args->adapter_hash || !args->response_len ||
      (code == WVB_UNIX_CLIENT_CALL_EX && !args->dispatch_status) ||
      (args->request_len && !args->request) ||
      (args->response_cap && !args->response)) {
    return WVB_STATUS_INVALID_ARGUMENT;
  }
  *args->response_len = 0;
  if (args->dispatch_status) {
    *args->dispatch_status = 0;
  }
  if (!forward(code, args)) {
    *args->response_len = 0;
    if (args->dispatch_status) {
      *args->dispatch_status = 0;
    }
    return WVB_STATUS_RUNTIME_ERROR;
  }
  return args->status;
}

WvbStatus wvb_client_call(const uint8_t adapter_hash[32], uint32_t operation_id,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t response_cap,
                          size_t *response_len) {
  WvbUnixClientCall args = {
      adapter_hash, operation_id, request, request_len, response,
      response_cap, response_len, NULL, WVB_STATUS_RUNTIME_ERROR};
  return call(WVB_UNIX_CLIENT_CALL, &args);
}

WvbStatus wvb_client_call_ex(const uint8_t adapter_hash[32], uint32_t operation_id,
                             const uint8_t *request, size_t request_len,
                             uint8_t *response, size_t response_cap,
                             size_t *response_len, int32_t *dispatch_status) {
  WvbUnixClientCall args = {
      adapter_hash, operation_id, request, request_len, response,
      response_cap, response_len, dispatch_status, WVB_STATUS_RUNTIME_ERROR};
  return call(WVB_UNIX_CLIENT_CALL_EX, &args);
}

WvbStatus wvb_client_reset(void) {
  WvbUnixClientReset args = {WVB_STATUS_RUNTIME_ERROR};
  return forward(WVB_UNIX_CLIENT_RESET, &args) ? args.status
                                              : WVB_STATUS_RUNTIME_ERROR;
}

WvbStatus wvb_client_handle_close(const uint8_t token[28], int32_t *native_status) {
  if (!token || !native_status) return WVB_STATUS_INVALID_ARGUMENT;
  *native_status = 0;
  WvbUnixClientHandleClose args = {token, native_status, WVB_STATUS_RUNTIME_ERROR};
  return forward(WVB_UNIX_CLIENT_HANDLE_CLOSE, &args) ? args.status
                                                    : WVB_STATUS_RUNTIME_ERROR;
}
