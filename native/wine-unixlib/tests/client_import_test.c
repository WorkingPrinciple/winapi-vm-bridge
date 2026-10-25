#include "wvb_client.h"

/* Link-only consumer: this DLL is never loaded or executed by source checks. */
__declspec(dllexport) WvbStatus wvb_client_import_link_check(
    const WvbClientConfig *config, const uint8_t hash[32],
    const uint8_t *request, size_t request_len, uint8_t *response,
    size_t response_cap, size_t *response_len, int32_t *dispatch_status) {
  WvbStatus status = wvb_client_configure(config);
  status += wvb_client_bind_operation(hash, 7, 11, 13);
  status += wvb_client_call(hash, 7, request, request_len, response, response_cap,
                             response_len);
  status += wvb_client_call_ex(hash, 7, request, request_len, response,
                                response_cap, response_len, dispatch_status);
  status += wvb_client_reset();
  int32_t native_status;
  status += wvb_client_handle_close(hash, &native_status);
  return status;
}
