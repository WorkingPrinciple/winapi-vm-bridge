#include <windows.h>
#include <wine/unixlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "wvb_client_unix.h"
#include "wvb_unix_runtime.h"

WvbStatus wvb_test_pe_configure(const WvbClientConfig *);
WvbStatus wvb_test_pe_bind(const uint8_t[32], uint32_t, uint32_t, uint32_t);
WvbStatus wvb_test_pe_call(const uint8_t[32], uint32_t, const uint8_t *,
                          size_t, uint8_t *, size_t, size_t *);
WvbStatus wvb_test_pe_call_ex(const uint8_t[32], uint32_t, const uint8_t *,
                             size_t, uint8_t *, size_t, size_t *, int32_t *);
WvbStatus wvb_test_pe_reset(void);
WvbStatus wvb_test_pe_handle_close(const uint8_t[28], int32_t *);

uint64_t __wine_unixlib_handle = 42;
static DWORD last_error;
static int32_t transport_error;
static WvbStatus host_status;
static unsigned int host_calls[WVB_UNIX_ENTRY_COUNT], unix_calls;
static unsigned int config_reads;
static const WvbClientConfig *expected_config;
static const uint8_t *expected_hash, *expected_request;
static uint8_t *expected_response;
static size_t expected_request_len, expected_cap;
static uint32_t expected_operation = 7;
static const uint8_t native_error_body[] = {5, 0, 7, 128, 122, 0, 0, 0};

void SetLastError(DWORD value) { last_error = value; }

NTSTATUS wvb_test_unix_call(unsigned int code, void *args) {
  assert(__wine_unixlib_handle == 42);
  assert(code > WVB_UNIX_LOAD_CONFIG && code < WVB_UNIX_ENTRY_COUNT);
  ++unix_calls;
  if (transport_error &&
      (code == WVB_UNIX_CLIENT_CALL || code == WVB_UNIX_CLIENT_CALL_EX)) {
    WvbUnixClientCall *call = args;
    *call->response_len = 123;
    if (call->dispatch_status) *call->dispatch_status = 456;
  }
  return transport_error ? transport_error : __wine_unix_call_funcs[code](args);
}

int32_t wvb_unix_load_runtime_config(WvbUnixLoadArgs *args) {
  (void)args;
  ++config_reads;
  return (int32_t)0xc0000225;
}

WvbStatus wvb_client_configure(const WvbClientConfig *config) {
  assert(config == expected_config);
  ++host_calls[WVB_UNIX_CLIENT_CONFIGURE];
  return host_status;
}

WvbStatus wvb_client_bind_operation(const uint8_t hash[32], uint32_t operation,
                                    uint32_t request_schema,
                                    uint32_t response_schema) {
  assert(hash == expected_hash && operation == expected_operation);
  assert(request_schema == 11 && response_schema == 13);
  ++host_calls[WVB_UNIX_CLIENT_BIND];
  return host_status;
}

static WvbStatus host_call(const uint8_t *hash, uint32_t operation,
                            const uint8_t *request, size_t request_len,
                            uint8_t *response, size_t cap, size_t *length,
                            int32_t *dispatch) {
  assert(hash == expected_hash && operation == expected_operation);
  assert(request == expected_request && request_len == expected_request_len);
  assert(response == expected_response && cap == expected_cap);
  assert(length && *length == 0);
  assert(dispatch && *dispatch == 0);
  if (host_status == WVB_STATUS_DISPATCH_ERROR) *dispatch = 37;
  if (host_status == WVB_STATUS_INSUFFICIENT_BUFFER) {
    *length = sizeof(native_error_body);
  }
  if (host_status == WVB_STATUS_OK) {
    assert(cap >= sizeof(native_error_body));
    *length = sizeof(native_error_body);
    memcpy(response, native_error_body, sizeof(native_error_body));
  }
  return host_status;
}

WvbStatus wvb_client_call(const uint8_t hash[32], uint32_t operation,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t cap, size_t *length) {
  ++host_calls[WVB_UNIX_CLIENT_CALL];
  int32_t dispatch = 0;
  return host_call(hash, operation, request, request_len, response, cap, length,
                   &dispatch);
}

WvbStatus wvb_client_call_ex(const uint8_t hash[32], uint32_t operation,
                             const uint8_t *request, size_t request_len,
                             uint8_t *response, size_t cap, size_t *length,
                             int32_t *dispatch) {
  ++host_calls[WVB_UNIX_CLIENT_CALL_EX];
  return host_call(hash, operation, request, request_len, response, cap, length,
                   dispatch);
}

WvbStatus wvb_client_reset(void) {
  ++host_calls[WVB_UNIX_CLIENT_RESET];
  return host_status;
}

WvbStatus wvb_client_handle_close(const uint8_t token[28], int32_t *native_status) {
  assert(token == expected_hash && native_status && *native_status == 0);
  ++host_calls[WVB_UNIX_CLIENT_HANDLE_CLOSE];
  *native_status = 17;
  return host_status;
}

int main(void) {
  WvbClientConfig config = {.struct_size = sizeof(config)};
  uint8_t hash[32] = {1}, request[] = {2, 3}, response[16];
  expected_config = &config;
  expected_hash = hash;
  expected_request = request;
  expected_request_len = sizeof(request);
  expected_response = response;
  expected_cap = sizeof(response);

  for (host_status = WVB_STATUS_OK; host_status >= WVB_STATUS_OPERATION_NOT_BOUND;
       --host_status) {
    assert(wvb_test_pe_configure(&config) == host_status);
    assert(wvb_test_pe_bind(hash, 7, 11, 13) == host_status);
    assert(wvb_test_pe_reset() == host_status);
    int32_t close_status = 123;
    assert(wvb_test_pe_handle_close(hash, &close_status) == host_status);
    assert(close_status == 17);
    for (unsigned int extended = 0; extended < 2; ++extended) {
      memset(response, 0xa5, sizeof(response));
      size_t length = 999;
      int32_t dispatch = 999;
      const unsigned int code = extended ? WVB_UNIX_CLIENT_CALL_EX : WVB_UNIX_CLIENT_CALL;
      const unsigned int before = host_calls[code];
      const WvbStatus status =
          extended ? wvb_test_pe_call_ex(hash, 7, request, sizeof(request),
                                         response, sizeof(response), &length,
                                         &dispatch)
                   : wvb_test_pe_call(hash, 7, request, sizeof(request),
                                      response, sizeof(response), &length);
      assert(status == host_status && host_calls[code] == before + 1);
      assert(length == (host_status == WVB_STATUS_OK ||
                        host_status == WVB_STATUS_INSUFFICIENT_BUFFER
                            ? sizeof(native_error_body) : 0));
      if (extended) {
        assert(dispatch == (host_status == WVB_STATUS_DISPATCH_ERROR ? 37 : 0));
      }
      if (host_status == WVB_STATUS_OK) {
        assert(memcmp(response, native_error_body, sizeof(native_error_body)) == 0);
      } else {
        for (size_t index = 0; index < sizeof(response); ++index)
          assert(response[index] == 0xa5);
      }
    }
  }
  assert(!config_reads);

  host_status = WVB_STATUS_INVALID_ARGUMENT;
  expected_config = NULL;
  assert(wvb_test_pe_configure(NULL) == WVB_STATUS_INVALID_ARGUMENT);
  expected_config = &config;

  size_t length = 999;
  int32_t dispatch = 999;
  unsigned int before = unix_calls;
  assert(wvb_test_pe_call_ex(NULL, 7, request, 2, response, 16, &length,
                             &dispatch) == WVB_STATUS_INVALID_ARGUMENT);
  assert(wvb_test_pe_call_ex(hash, 7, NULL, 2, response, 16, &length,
                             &dispatch) == WVB_STATUS_INVALID_ARGUMENT);
  assert(wvb_test_pe_call_ex(hash, 7, request, 2, NULL, 16, &length,
                             &dispatch) == WVB_STATUS_INVALID_ARGUMENT);
  assert(wvb_test_pe_call_ex(hash, 7, request, 2, response, 16, NULL,
                             &dispatch) == WVB_STATUS_INVALID_ARGUMENT);
  assert(wvb_test_pe_call_ex(hash, 7, request, 2, response, 16, &length,
                             NULL) == WVB_STATUS_INVALID_ARGUMENT);
  assert(wvb_test_pe_call(hash, 7, request, 2, response, 16, NULL) ==
         WVB_STATUS_INVALID_ARGUMENT);
  assert(unix_calls == before && length == 999 && dispatch == 999);

  host_status = WVB_STATUS_INSUFFICIENT_BUFFER;
  expected_request = NULL;
  expected_request_len = 0;
  expected_response = NULL;
  expected_cap = 0;
  assert(wvb_test_pe_call_ex(hash, 7, NULL, 0, NULL, 0, &length, &dispatch) ==
         WVB_STATUS_INSUFFICIENT_BUFFER);
  assert(length == sizeof(native_error_body) && dispatch == 0);

  host_status = WVB_STATUS_RUNTIME_ERROR;
  expected_request = request;
  expected_request_len = (size_t)1 << 33;
  expected_response = response;
  expected_cap = (size_t)1 << 34;
  expected_operation = UINT32_MAX;
  assert(wvb_test_pe_call_ex(hash, UINT32_MAX, request, expected_request_len,
                             response, expected_cap, &length, &dispatch) ==
         WVB_STATUS_RUNTIME_ERROR);

  for (unsigned int missing_handle = 0; missing_handle < 2; ++missing_handle) {
    __wine_unixlib_handle = missing_handle ? 0 : 42;
    transport_error = (int32_t)0xc00000bb;
    before = host_calls[WVB_UNIX_CLIENT_CALL_EX];
    memset(response, 0xa5, sizeof(response));
    length = 999;
    dispatch = 999;
    assert(wvb_test_pe_call_ex(hash, 7, request, 2, response, 16, &length,
                               &dispatch) == WVB_STATUS_RUNTIME_ERROR);
    assert(length == 0 && dispatch == 0 && response[0] == 0xa5);
    assert(host_calls[WVB_UNIX_CLIENT_CALL_EX] == before);
    assert(last_error == (missing_handle ? ERROR_DLL_INIT_FAILED :
                         (DWORD)transport_error));
    assert(wvb_test_pe_configure(&config) == WVB_STATUS_RUNTIME_ERROR);
    assert(wvb_test_pe_bind(hash, 7, 11, 13) == WVB_STATUS_RUNTIME_ERROR);
    assert(wvb_test_pe_reset() == WVB_STATUS_RUNTIME_ERROR);
    int32_t close_status = 123;
    assert(wvb_test_pe_handle_close(hash, &close_status) == WVB_STATUS_RUNTIME_ERROR);
    assert(close_status == 0);
    length = 999;
    assert(wvb_test_pe_call(hash, 7, request, 2, response, 16, &length) ==
           WVB_STATUS_RUNTIME_ERROR);
    assert(length == 0 && response[0] == 0xa5);
  }
  __wine_unixlib_handle = 42;
  transport_error = 0;
  for (unsigned int code = 1; code < WVB_UNIX_ENTRY_COUNT; ++code) {
    assert(__wine_unix_call_funcs[code](NULL) == (int32_t)0xc000000d);
    assert(__wine_unix_call_wow64_funcs[code]((void *)(uintptr_t)1) ==
           (int32_t)0xc00000bb);
  }
  assert(!config_reads);
  WvbUnixLoadArgs unused = {0};
  assert(__wine_unix_call_funcs[0](&unused) == (int32_t)0xc0000225);
  assert(__wine_unix_call_wow64_funcs[0](&unused) == (int32_t)0xc0000225);
  assert(config_reads == 2);
  puts("client builtin -> Unix table -> host C ABI mock forwarding passed");
  return 0;
}
