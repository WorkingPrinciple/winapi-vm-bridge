#include "wvb_client_unix.h"
#include "wvb_unix_runtime.h"

enum {
  STATUS_SUCCESS = 0,
  STATUS_INVALID_PARAMETER = (int32_t)0xc000000d,
  STATUS_NOT_SUPPORTED = (int32_t)0xc00000bb
};

static int32_t load_config(void *value) {
  return wvb_unix_load_runtime_config(value);
}

static int32_t configure(void *value) {
  WvbUnixClientConfigure *args = value;
  if (!args) return STATUS_INVALID_PARAMETER;
  args->status = wvb_client_configure(args->config);
  return STATUS_SUCCESS;
}

static int32_t bind_operation(void *value) {
  WvbUnixClientBind *args = value;
  if (!args) return STATUS_INVALID_PARAMETER;
  args->status = wvb_client_bind_operation(
      args->adapter_hash, args->operation_id, args->request_schema_id,
      args->response_schema_id);
  return STATUS_SUCCESS;
}

static int32_t call(void *value) {
  WvbUnixClientCall *args = value;
  if (!args) return STATUS_INVALID_PARAMETER;
  args->status = wvb_client_call(
      args->adapter_hash, args->operation_id, args->request, args->request_len,
      args->response, args->response_cap, args->response_len);
  return STATUS_SUCCESS;
}

static int32_t call_ex(void *value) {
  WvbUnixClientCall *args = value;
  if (!args) return STATUS_INVALID_PARAMETER;
  args->status = wvb_client_call_ex(
      args->adapter_hash, args->operation_id, args->request, args->request_len,
      args->response, args->response_cap, args->response_len,
      args->dispatch_status);
  return STATUS_SUCCESS;
}

static int32_t reset(void *value) {
  WvbUnixClientReset *args = value;
  if (!args) return STATUS_INVALID_PARAMETER;
  args->status = wvb_client_reset();
  return STATUS_SUCCESS;
}

static int32_t unsupported(void *value) {
  (void)value;
  return STATUS_NOT_SUPPORTED;
}

__attribute__((visibility("default"))) const WvbUnixClientEntry
    __wine_unix_call_funcs[WVB_UNIX_ENTRY_COUNT] = {
        load_config, configure, bind_operation, call, call_ex, reset};

/* Pointer-bearing client arguments must never be interpreted as WOW64 data. */
__attribute__((visibility("default"))) const WvbUnixClientEntry
    __wine_unix_call_wow64_funcs[WVB_UNIX_ENTRY_COUNT] = {
        load_config, unsupported, unsupported, unsupported, unsupported,
        unsupported};
