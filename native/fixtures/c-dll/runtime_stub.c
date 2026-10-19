#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "wvb_client.h"

typedef int32_t (__stdcall *Dispatch)(uint32_t, const uint8_t *, size_t,
                                      uint8_t *, size_t, size_t *);

WvbStatus wvb_client_call(const uint8_t adapter_hash[32], uint32_t operation_id,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t response_cap,
                          size_t *response_len) {
    (void)adapter_hash;
    static HMODULE module;
    static Dispatch dispatch;
    if (!dispatch) {
        module = LoadLibraryW(L"example_math_dispatch.dll");
        if (!module) return 1;
        dispatch = (Dispatch)GetProcAddress(module, "wvb_dispatch");
        if (!dispatch) return 2;
    }
    return dispatch(operation_id, request, request_len, response,
                    response_cap, response_len);
}
