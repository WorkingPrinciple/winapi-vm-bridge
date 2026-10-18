#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

using Dispatch = int32_t(__stdcall *)(uint32_t, const uint8_t *, size_t,
                                      uint8_t *, size_t, size_t *);

int main() {
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
                           LOAD_LIBRARY_SEARCH_USER_DIRS);
  wchar_t dispatcher_path[32768];
  DWORD path_length =
      GetModuleFileNameW(nullptr, dispatcher_path, 32768);
  if (!path_length || path_length >= 32768) {
    return 9;
  }
  while (path_length && dispatcher_path[path_length - 1] != L'\\' &&
         dispatcher_path[path_length - 1] != L'/') {
    --path_length;
  }
  constexpr wchar_t dispatcher_name[] = L"dispatcher.dll";
  if (!path_length ||
      path_length + (sizeof(dispatcher_name) / sizeof(wchar_t)) >= 32768) {
    return 9;
  }
  std::memcpy(dispatcher_path + path_length, dispatcher_name,
              sizeof(dispatcher_name));
  HMODULE module = LoadLibraryExW(
      dispatcher_path, nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  if (!module) {
    return 10;
  }
  const FARPROC symbol = GetProcAddress(module, "whiny_dispatch_v1");
  Dispatch dispatch = nullptr;
  static_assert(sizeof(dispatch) == sizeof(symbol));
  std::memcpy(&dispatch, &symbol, sizeof(dispatch));
  if (!dispatch) {
    FreeLibrary(module);
    return 11;
  }
  uint8_t request[8];
  int32_t left = 20;
  int32_t right = 22;
  std::memcpy(request, &left, sizeof(left));
  std::memcpy(request + 4, &right, sizeof(right));
  uint8_t response[4] = {};
  size_t response_length = 0;
  const int32_t status =
      dispatch(1, request, sizeof(request), response, sizeof(response),
               &response_length);
  int32_t result = 0;
  std::memcpy(&result, response, sizeof(result));
  const int32_t unknown =
      dispatch(999, request, sizeof(request), response, sizeof(response),
               &response_length);
  const int32_t short_request =
      dispatch(1, request, 7, response, sizeof(response), &response_length);
  FreeLibrary(module);
  if (status != 0 || response_length != 4 || result != 42 || unknown != 3 ||
      short_request != 1) {
    return 12;
  }
  std::puts("whiny-native-scalar-runtime=ok result=42");
  return 0;
}
