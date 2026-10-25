#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "wvb_client.h"

static const IID IID_IWvbScalarObject =
    {0xba9a4da2, 0x79fe, 0x4b31, {0x8d, 0xb4, 0x20, 0x1a, 0xf0, 0x26, 0x6c, 0x12}};
static const IID IID_Unsupported =
    {0xba9a4da2, 0x79fe, 0x4b31, {0x8d, 0xb4, 0x20, 0x1a, 0xf0, 0x26, 0x6c, 0x14}};
struct IWvbScalarObject : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE Transform(UINT32, UINT32 *) = 0;
};
typedef HRESULT (WINAPI *CreateObject)(REFIID, void **);
typedef HRESULT (WINAPI *CanUnload)();
typedef int (*TraceStart)(const wchar_t *, const char *, const char *, uint64_t);
typedef int (*TraceFinish)();

static bool hex(const wchar_t *input, uint8_t *output, size_t length) {
  static const wchar_t alphabet[] = L"0123456789abcdef";
  if (wcslen(input) != length * 2) return false;
  for (size_t i = 0; i < length; ++i) {
    const wchar_t *high = wcschr(alphabet, input[2 * i]);
    const wchar_t *low = wcschr(alphabet, input[2 * i + 1]);
    if (!high || !low) return false;
    output[i] = static_cast<uint8_t>((high - alphabet) * 16 + (low - alphabet));
  }
  return true;
}

static bool symbol(HMODULE module, const char *name, void *out, size_t length) {
  FARPROC entry = GetProcAddress(module, name);
  if (!entry || length != sizeof(entry)) {
    fprintf(stderr, "com-proxy: missing export %s\n", name);
    return false;
  }
  memcpy(out, &entry, length);
  return true;
}

static bool typed_call(const uint8_t adapter[32], uint32_t operation,
                       uint32_t request_schema, uint32_t response_schema,
                       const uint8_t *input, size_t input_len,
                       uint8_t *output, size_t output_len) {
  size_t written = 0;
  int32_t dispatch = -1;
  WvbStatus status = wvb_client_bind_operation(adapter, operation, request_schema, response_schema);
  if (status == WVB_STATUS_OK)
    status = wvb_client_call_ex(adapter, operation, input, input_len, output,
                                output_len, &written, &dispatch);
  if (status == WVB_STATUS_OK && dispatch == 0 && written == output_len) return true;
  fprintf(stderr, "com-proxy: control probe operation=%u status=%ld dispatch=%ld bytes=%zu; no retry\n",
          operation, static_cast<long>(status), static_cast<long>(dispatch), written);
  return false;
}

static bool close_as_expected(const uint8_t token[28], bool rejected) {
  int32_t native = 0;
  WvbStatus status = wvb_client_handle_close(token, &native);
  if (status == (rejected ? WVB_STATUS_DISPATCH_ERROR : WVB_STATUS_OK) &&
      native == (rejected ? static_cast<int32_t>(0x80070006u) : 0)) return true;
  fprintf(stderr, "com-proxy: close probe rejected=%d status=%ld native=0x%08lx; no retry\n",
          rejected, static_cast<long>(status), static_cast<unsigned long>(native));
  return false;
}

static bool control_negatives(const uint8_t adapter[32], const uint8_t token[28]) {
  const size_t offsets[] = {15, 20, 24};
  for (size_t offset : offsets) {
    uint8_t wrong[28];
    memcpy(wrong, token, sizeof(wrong));
    wrong[offset] ^= 1;
    if (!close_as_expected(wrong, true)) return false;
  }
  uint8_t request[32], response[8] = {};
  memcpy(request, token, 28);
  request[28] = 41; request[29] = request[30] = request[31] = 0;
  if (!typed_call(adapter, 2, 1073741843u, 1073741844u,
                  request, sizeof(request), response, sizeof(response))) return false;
  const uint8_t expected[8] = {0, 0, 0, 0, 42, 0, 0, 0};
  if (memcmp(response, expected, sizeof(expected))) {
    fputs("com-proxy: valid lease did not survive rejected closes\n", stderr);
    return false;
  }
  if (!close_as_expected(token, false) || !close_as_expected(token, true)) return false;
  puts("{\"event\":\"control-negatives\",\"wrong_epoch\":true,\"wrong_generation\":true,"
       "\"wrong_type\":true,\"lease_survived\":true,\"closed\":true,\"stale\":true}");
  return true;
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 11) {
    fputs("usage: proxy_call.exe PROXY KEY_FILE ADDRESS BROKER_HEX ACTOR_HEX INSTANCE_HEX BUILD_HEX TRACE PROXY_SHA CONTRACT_SHA\n", stderr);
    return 2;
  }
  WvbClientConfig config = {};
  config.struct_size = sizeof(config);
  char address[128], proxy_hash[65];
  uint8_t hash[32], adapter[32];
  if (!hex(argv[4], config.broker_public_key, 32) ||
      !hex(argv[5], config.actor_id, 16) ||
      !hex(argv[6], config.client_instance, 16) ||
      !hex(argv[7], config.build_fingerprint, 32) ||
      !hex(argv[9], hash, 32) ||
      !hex(argv[10], adapter, 32) ||
      !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[3], -1, address, sizeof(address), nullptr, nullptr) ||
      !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[9], -1, proxy_hash, sizeof(proxy_hash), nullptr, nullptr))
    return 2;
  FILE *key = _wfopen(argv[2], L"rb");
  if (!key) { fputs("com-proxy: private key open failed\n", stderr); return 2; }
  bool valid = fread(config.client_private_key, 1, 32, key) == 32 &&
               fgetc(key) == EOF && !ferror(key);
  valid = fclose(key) == 0 && valid;
  if (!valid) {
    SecureZeroMemory(config.client_private_key, 32);
    fputs("com-proxy: private key read failed\n", stderr);
    return 2;
  }
  config.broker_address = reinterpret_cast<const uint8_t *>(address);
  config.broker_address_len = strlen(address);
  config.connect_timeout_ms = 5000;
  config.call_timeout_ms = 10000;
  WvbStatus status = wvb_client_configure(&config);
  SecureZeroMemory(config.client_private_key, 32);
  if (status != WVB_STATUS_OK) {
    fprintf(stderr, "com-proxy: configure=%ld; no call; no retry\n", static_cast<long>(status));
    return 2;
  }
  int code = 2;
  HMODULE proxy = LoadLibraryExW(argv[1], nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  if (proxy) {
    CreateObject create = nullptr;
    CanUnload can_unload = nullptr;
    TraceStart trace_start = nullptr;
    TraceFinish trace_finish = nullptr;
    bool recording = false;
    if (symbol(proxy, "whiny_object_create_v1", &create, sizeof(create)) &&
        symbol(proxy, "DllCanUnloadNow", &can_unload, sizeof(can_unload))) {
      FARPROC start = GetProcAddress(proxy, "whiny_trace_start_v1");
      FARPROC finish = GetProcAddress(proxy, "whiny_trace_finish_v1");
      if (start && finish) {
        memcpy(&trace_start, &start, sizeof(start));
        memcpy(&trace_finish, &finish, sizeof(finish));
        recording = trace_start(argv[8], "wvb-com-scalar", proxy_hash, 128) == 0;
      }
      if ((!start && !finish) || recording) {
        uint8_t probe[32] = {};
        bool probe_ready = typed_call(adapter, 1, 1073741841u, 1073741842u,
                                      nullptr, 0, probe, sizeof(probe));
        const uint8_t zero[4] = {};
        probe_ready = probe_ready && !memcmp(probe, zero, 4) && probe[28] == 7 &&
                      probe[29] == 0 && probe[30] == 0 && probe[31] == 0;
        IWvbScalarObject *object = nullptr;
        HRESULT activation = probe_ready
            ? create(IID_IWvbScalarObject, reinterpret_cast<void **>(&object)) : E_UNEXPECTED;
        if (SUCCEEDED(activation) && object) {
          IUnknown *identity = nullptr;
          IWvbScalarObject *again = nullptr;
          void *unsupported = reinterpret_cast<void *>(static_cast<uintptr_t>(1));
          bool correct = object->QueryInterface(IID_IUnknown, reinterpret_cast<void **>(&identity)) == S_OK &&
              object->QueryInterface(IID_IWvbScalarObject, reinterpret_cast<void **>(&again)) == S_OK &&
              identity == static_cast<IUnknown *>(object) && again == object &&
              object->QueryInterface(IID_Unsupported, &unsupported) == E_NOINTERFACE && !unsupported;
          if (identity) identity->Release();
          if (again) again->Release();
          correct = correct && object->Transform(41, nullptr) == E_POINTER;
          UINT32 output = 0xa5a5a5a5;
          HRESULT hr = object->Transform(41, &output);
          printf("{\"event\":\"result\",\"activation_hresult\":%ld,\"hresult\":%ld,\"output\":%u,\"caller_pid\":%lu}\n",
                 static_cast<long>(activation), static_cast<long>(hr), output, GetCurrentProcessId());
          correct = correct && hr == S_OK && output == 42;
          output = 0xa5a5a5a5;
          hr = object->Transform(UINT32_MAX, &output);
          printf("{\"event\":\"native-error\",\"hresult\":%ld,\"output\":%u}\n",
                 static_cast<long>(hr), output);
          correct = correct && hr == E_INVALIDARG && output == 0;
          ULONG references = object->Release();
          HRESULT unload = can_unload();
          printf("{\"event\":\"release\",\"references\":%lu,\"can_unload_hresult\":%ld,\"recording\":%s}\n",
                 references, static_cast<long>(unload), recording ? "true" : "false");
          code = correct && !references && unload == S_OK ? 0 : 2;
        } else {
          fprintf(stderr, "com-proxy: activation HRESULT=0x%08lx; no retry\n",
                  static_cast<unsigned long>(activation));
          if (object) object->Release();
        }
        if (probe_ready && code == 0) {
          bool negatives = control_negatives(adapter, probe + 4);
          if (!negatives) code = 2;
        } else {
          fputs("com-proxy: facade/probe failed; disconnect owns cleanup\n", stderr);
        }
      } else { fputs("com-proxy: recorder initialization failed\n", stderr); }
      if (recording && trace_finish()) { fputs("com-proxy: recorder finish failed\n", stderr); code = 2; }
      if (!start && !finish) fputs("com-proxy: generated recorder unavailable; not A04\n", stderr);
    }
    if (!FreeLibrary(proxy)) { fputs("com-proxy: unload failed\n", stderr); code = 2; }
  } else { fprintf(stderr, "com-proxy: LoadLibrary error=%lu\n", GetLastError()); }
  if (wvb_client_reset() != WVB_STATUS_OK) { fputs("com-proxy: reset failed\n", stderr); code = 2; }
  return code;
}
