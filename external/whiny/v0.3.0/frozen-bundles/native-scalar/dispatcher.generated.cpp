#define WHINY_TARGET_RELATIVE L"target/native_math.dll"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
enum { WHINY_DISPATCH_OK=0, WHINY_DISPATCH_INVALID_BUFFER=1, WHINY_DISPATCH_EXPORT_NOT_FOUND=2, WHINY_DISPATCH_OPERATION_UNKNOWN=3, WHINY_DISPATCH_LOAD_FAILED=4, WHINY_DISPATCH_TARGET_FAILURE=5 };
static HMODULE WHINY_TARGET = NULL;
static HMODULE WHINY_SELF = NULL;
static void wvb_store_le(uint8_t *out, const void *value, size_t size) { memcpy(out, value, size); }
static void wvb_load_le(void *out, const uint8_t *value, size_t size) { memcpy(out, value, size); }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) WHINY_SELF = instance;
  return TRUE;
}
static HMODULE whiny_load_target(void) {
  if (!WHINY_TARGET) {
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(WHINY_SELF, path, 32768);
    if (!length || length >= 32768) return NULL;
    while (length && path[length - 1] != L'\\' && path[length - 1] != L'/') --length;
    if (!length || wcslen(WHINY_TARGET_RELATIVE) >= 32768 - length) return NULL;
    wcscpy(path + length, WHINY_TARGET_RELATIVE);
    WHINY_TARGET = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  }
  return WHINY_TARGET;
}
[[maybe_unused]] static FARPROC whiny_resolve_name(const char *name) {
  HMODULE target = whiny_load_target();
  return target ? GetProcAddress(target, name) : NULL;
}
[[maybe_unused]] static FARPROC whiny_resolve_ordinal(uint16_t ordinal) {
  HMODULE target = whiny_load_target();
  return target ? GetProcAddress(target, MAKEINTRESOURCEA(ordinal)) : NULL;
}
template <typename Function>
static Function whiny_function_cast(FARPROC procedure) {
  static_assert(sizeof(Function) == sizeof(procedure), "function pointer size");
  Function function = nullptr;
  memcpy(&function, &procedure, sizeof(function));
  return function;
}
extern "C" __declspec(dllexport) int32_t __stdcall whiny_dispatch_v1(uint32_t operation_id, const uint8_t *request, size_t request_len, uint8_t *response, size_t response_cap, size_t *response_len) {
  if ((!request && request_len) || !response || !response_len) return WHINY_DISPATCH_INVALID_BUFFER;
  switch (operation_id) {


    case 1: {
      if (request_len != 8 || response_cap < 4) return WHINY_DISPATCH_INVALID_BUFFER;
      int32_t arg0 = (int32_t)0; wvb_load_le(&arg0, request + 0, 4);
      int32_t arg1 = (int32_t)0; wvb_load_le(&arg1, request + 4, 4);
      using Function = int32_t (WINAPI*)(int32_t, int32_t);
      Function function = whiny_function_cast<Function>(whiny_resolve_name("add"));
      if (!function) return WHINY_DISPATCH_EXPORT_NOT_FOUND;
      int32_t result = function(arg0, arg1);
      wvb_store_le(response, &result, sizeof(result));
      *response_len = sizeof(result);
      return WHINY_DISPATCH_OK;
    }

    default: return WHINY_DISPATCH_OPERATION_UNKNOWN;
  }
}
