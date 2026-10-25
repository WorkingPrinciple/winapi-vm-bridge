#include <initguid.h>
#include "interfaces.hpp"
#include <roapi.h>
#include <winstring.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "wvb_client.h"

using GetFactory = HRESULT (WINAPI *)(HSTRING, REFIID, void **);
using CanUnload = HRESULT (WINAPI *)();
using TraceStart = int (*)(const wchar_t *, const char *, const char *, uint64_t);
using TraceFinish = int (*)();

static bool hex(const wchar_t *text, uint8_t *out, size_t length) {
  static const wchar_t alphabet[] = L"0123456789abcdef";
  if (wcslen(text) != length * 2) return false;
  for (size_t i = 0; i < length; ++i) {
    const wchar_t *high = wcschr(alphabet, text[i * 2]), *low = wcschr(alphabet, text[i * 2 + 1]);
    if (!high || !low) return false;
    out[i] = static_cast<uint8_t>((high - alphabet) * 16 + (low - alphabet));
  }
  return true;
}

template <typename Function>
static bool symbol(HMODULE module, const char *name, Function *function) {
  FARPROC entry = GetProcAddress(module, name);
  static_assert(sizeof(entry) == sizeof(*function), "function pointer size");
  if (!entry) { fprintf(stderr, "winrt-proxy: missing export %s\n", name); return false; }
  memcpy(function, &entry, sizeof(entry));
  return true;
}

static bool inspect(IInspectable *object, REFIID iid, REFIID other) {
  IUnknown *identity = nullptr;
  IInspectable *inspectable = nullptr;
  void *again = nullptr, *unsupported = reinterpret_cast<void *>(static_cast<uintptr_t>(1));
  bool ok = object->QueryInterface(IID_IUnknown, reinterpret_cast<void **>(&identity)) == S_OK;
  ok = object->QueryInterface(IID_IInspectable, reinterpret_cast<void **>(&inspectable)) == S_OK && ok;
  ok = object->QueryInterface(iid, &again) == S_OK && ok;
  ok = identity == static_cast<IUnknown *>(object) && inspectable == object && again == object && ok;
  ok = object->QueryInterface(other, &unsupported) == E_NOINTERFACE && !unsupported && ok;
  if (identity) identity->Release();
  if (inspectable) inspectable->Release();
  if (again) static_cast<IUnknown *>(again)->Release();
  ULONG count = 0;
  IID *values = nullptr;
  HRESULT hr = object->GetIids(&count, &values);
  ok = hr == S_OK && count == 1 && values && values[0] == iid && ok;
  CoTaskMemFree(values);
  HSTRING name = nullptr;
  TrustLevel level = BaseTrust;
  ok = object->GetRuntimeClassName(&name) == E_NOTIMPL && !name && ok;
  if (name) WindowsDeleteString(name);
  ok = object->GetTrustLevel(&level) == E_NOTIMPL && ok;
  return ok;
}

static bool call(const uint8_t adapter[32], uint32_t operation,
                 const uint8_t *input, size_t size, uint8_t *output, size_t capacity) {
  size_t written = 0;
  int32_t dispatch = -1;
  WvbStatus status = wvb_client_bind_operation(adapter, operation,
      1073741887u + operation * 2, 1073741888u + operation * 2);
  if (status == WVB_STATUS_OK)
    status = wvb_client_call_ex(adapter, operation, input, size, output, capacity, &written, &dispatch);
  bool ok = status == WVB_STATUS_OK && dispatch == 0 && written == capacity;
  if (!ok) fprintf(stderr, "winrt-proxy: control op=%u status=%ld dispatch=%ld bytes=%zu; no retry\n",
                   operation, static_cast<long>(status), static_cast<long>(dispatch), written);
  return ok;
}

static bool close(const uint8_t token[28], bool rejected) {
  int32_t native = 0;
  WvbStatus status = wvb_client_handle_close(token, &native);
  bool ok = status == (rejected ? WVB_STATUS_DISPATCH_ERROR : WVB_STATUS_OK) &&
      native == (rejected ? static_cast<int32_t>(0x80070006u) : 0);
  if (!ok) fputs("winrt-proxy: unexpected close outcome; no retry\n", stderr);
  return ok;
}

static bool control_negatives(const uint8_t adapter[32], const uint8_t factory[28]) {
  const size_t offsets[] = {15, 20, 24};
  for (size_t offset : offsets) {
    uint8_t wrong[28];
    memcpy(wrong, factory, sizeof(wrong)); wrong[offset] ^= 1;
    if (!close(wrong, true)) return false;
  }
  uint8_t created[32] = {}, request[32] = {}, response[8] = {};
  request[28] = 41;
  if (!call(adapter, 2, factory, 28, created, sizeof(created))) return false;
  const uint8_t success[4] = {};
  if (memcmp(created, success, 4) || created[28] != 9 || created[29] || created[30] || created[31])
    return false;
  uint8_t wrong_role[28];
  memcpy(wrong_role, created + 4, sizeof(wrong_role));
  wrong_role[24] = 8;
  if (!close(wrong_role, true) || !close(factory, false) || !close(factory, true)) return false;
  memcpy(request, created + 4, 28);
  if (!call(adapter, 3, request, sizeof(request), response, sizeof(response))) return false;
  const uint8_t expected[8] = {0, 0, 0, 0, 42, 0, 0, 0};
  if (memcmp(response, expected, sizeof(expected)) ||
      !close(created + 4, false) || !close(created + 4, true)) return false;
  puts("{\"event\":\"control-negatives\",\"wrong_epoch\":true,\"wrong_generation\":true,"
       "\"wrong_type\":true,\"role_swapped_close\":true,\"factory_closed\":true,"
       "\"instance_survived\":true,\"lease_survived\":true,\"closed\":true,\"stale\":true}");
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
  if (!hex(argv[4], config.broker_public_key, 32) || !hex(argv[5], config.actor_id, 16) ||
      !hex(argv[6], config.client_instance, 16) || !hex(argv[7], config.build_fingerprint, 32) ||
      !hex(argv[9], hash, 32) || !hex(argv[10], adapter, 32) ||
      !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[3], -1,
                          address, sizeof(address), nullptr, nullptr) ||
      !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[9], -1,
                          proxy_hash, sizeof(proxy_hash), nullptr, nullptr)) return 2;
  FILE *key = _wfopen(argv[2], L"rb");
  if (!key) { fputs("winrt-proxy: key open failed\n", stderr); return 2; }
  bool valid = fread(config.client_private_key, 1, 32, key) == 32 && fgetc(key) == EOF && !ferror(key);
  valid = fclose(key) == 0 && valid;
  if (!valid) {
    SecureZeroMemory(config.client_private_key, 32);
    fputs("winrt-proxy: key read failed\n", stderr); return 2;
  }
  config.broker_address = reinterpret_cast<const uint8_t *>(address);
  config.broker_address_len = strlen(address);
  config.connect_timeout_ms = 5000; config.call_timeout_ms = 10000;
  WvbStatus status = wvb_client_configure(&config);
  SecureZeroMemory(config.client_private_key, 32);
  if (status != WVB_STATUS_OK) {
    fprintf(stderr, "winrt-proxy: configure=%ld; no call; no retry\n", static_cast<long>(status));
    return 2;
  }
  int code = 2;
  HMODULE proxy = LoadLibraryExW(argv[1], nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  if (proxy) {
    GetFactory get = nullptr;
    CanUnload can_unload = nullptr;
    TraceStart start = nullptr;
    TraceFinish finish = nullptr;
    if (symbol(proxy, "whiny_winrt_get_activation_factory_v1", &get) &&
        symbol(proxy, "DllCanUnloadNow", &can_unload) &&
        symbol(proxy, "whiny_trace_start_v1", &start) && symbol(proxy, "whiny_trace_finish_v1", &finish)) {
      bool recording = start(argv[8], "wvb-winrt-scalar", proxy_hash, 128) == 0;
      if (recording) {
        uint8_t probe[32] = {};
        bool probe_ready = call(adapter, 1, nullptr, 0, probe, sizeof(probe));
        const uint8_t success[4] = {};
        probe_ready = probe_ready && !memcmp(probe, success, 4) && probe[28] == 8 &&
            !probe[29] && !probe[30] && !probe[31];
        HSTRING name = nullptr;
        HRESULT activation = WindowsCreateString(WVB_RUNTIME_CLASS, ARRAYSIZE(WVB_RUNTIME_CLASS) - 1, &name);
        if (!probe_ready) {
          fputs("winrt-proxy: invalid control activation; facade factory not called\n", stderr);
          activation = E_UNEXPECTED;
        }
        IWvbScalarFactory *factory = nullptr;
        if (SUCCEEDED(activation) && probe_ready)
          activation = get(name, IID_IWvbScalarFactory, reinterpret_cast<void **>(&factory));
        WindowsDeleteString(name);
        if (SUCCEEDED(activation) && factory) {
          bool ok = inspect(factory, IID_IWvbScalarFactory, IID_IWvbScalarInstance) &&
              factory->ReservedFactory() == E_NOTIMPL;
          IWvbScalarInstance *instance = nullptr;
          HRESULT created = factory->Create(&instance);
          ULONG factory_refs = factory->Release();
          HRESULT alive = can_unload();
          if (SUCCEEDED(created) && instance) {
            ok = inspect(instance, IID_IWvbScalarInstance, IID_IWvbScalarFactory) && ok;
            ok = instance->Reserved0() == E_NOTIMPL && instance->Reserved1() == E_NOTIMPL && ok;
            ok = instance->Transform(41, nullptr) == E_POINTER && ok;
            UINT32 output = 0xa5a5a5a5;
            HRESULT hr = instance->Transform(41, &output);
            printf("{\"event\":\"result\",\"activation_hresult\":%ld,\"create_hresult\":%ld,"
                   "\"factory_references\":%lu,\"instance_alive_unload_hresult\":%ld,"
                   "\"hresult\":%ld,\"output\":%u,\"caller_pid\":%lu}\n",
                   static_cast<long>(activation), static_cast<long>(created), factory_refs,
                   static_cast<long>(alive), static_cast<long>(hr), output, GetCurrentProcessId());
            ok = activation == S_OK && created == S_OK && !factory_refs &&
                alive == S_FALSE && hr == S_OK && output == 42 && ok;
            output = 0xa5a5a5a5;
            hr = instance->Transform(UINT32_MAX, &output);
            printf("{\"event\":\"native-error\",\"hresult\":%ld,\"output\":%u}\n",
                   static_cast<long>(hr), output);
            ok = hr == E_INVALIDARG && output == 0xa5a5a5a5 && ok;
            ULONG refs = instance->Release();
            HRESULT unload = can_unload();
            printf("{\"event\":\"release\",\"references\":%lu,\"can_unload_hresult\":%ld,\"recording\":true}\n",
                   refs, static_cast<long>(unload));
            code = ok && !refs && unload == S_OK ? 0 : 2;
          } else {
            fprintf(stderr, "winrt-proxy: Create HRESULT=0x%08lx; no retry\n", static_cast<unsigned long>(created));
            if (instance) instance->Release();
          }
        } else {
          fprintf(stderr, "winrt-proxy: factory HRESULT=0x%08lx; no retry\n", static_cast<unsigned long>(activation));
          if (factory) factory->Release();
        }
        if (probe_ready && code == 0 && !control_negatives(adapter, probe + 4)) code = 2;
        if (finish()) { fputs("winrt-proxy: recorder finish failed\n", stderr); code = 2; }
      } else fputs("winrt-proxy: recorder start failed; no call\n", stderr);
    }
    if (!FreeLibrary(proxy)) { fputs("winrt-proxy: unload failed\n", stderr); code = 2; }
  } else fprintf(stderr, "winrt-proxy: load error=%lu\n", GetLastError());
  if (wvb_client_reset() != WVB_STATUS_OK) { fputs("winrt-proxy: reset failed\n", stderr); code = 2; }
  return code;
}
