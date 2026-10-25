#include "interfaces.hpp"
#include <roapi.h>
#include <winstring.h>
#include <stdint.h>
#include <stdio.h>
#include <string>

static bool module_identity(void *object, const wchar_t *directory, const char *role) {
  void *address = *static_cast<void ***>(object)[0];
  HMODULE module = nullptr;
  wchar_t path[32768], expected[32768];
  std::wstring target = directory;
  target += L"\\Wvb.Test.WvbScalarRuntimeClass.dll";
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCWSTR>(address), &module)) {
    fprintf(stderr, "oracle: module lookup error=%lu\n", GetLastError());
    return false;
  }
  DWORD length = GetModuleFileNameW(module, path, ARRAYSIZE(path));
  DWORD full = GetFullPathNameW(target.c_str(), ARRAYSIZE(expected), expected, nullptr);
  if (!length || length >= ARRAYSIZE(path) || !full || full >= ARRAYSIZE(expected) ||
      _wcsicmp(path, expected)) {
    fputs("oracle: actual object module does not match owned target\n", stderr);
    return false;
  }
  char utf8[131072];
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1,
                          utf8, sizeof(utf8), nullptr, nullptr)) {
    fprintf(stderr, "oracle: module path conversion error=%lu\n", GetLastError());
    return false;
  }
  printf("{\"event\":\"module\",\"role\":\"%s\",\"path\":\"", role);
  for (const unsigned char *byte = reinterpret_cast<unsigned char *>(utf8); *byte; ++byte) {
    if (*byte == '\\' || *byte == '"') putchar('\\');
    if (*byte < 32) printf("\\u%04x", *byte);
    else putchar(*byte);
  }
  puts("\"}");
  return true;
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 4) {
    fputs("usage: winrt_oracle.exe MANIFEST ASSEMBLY_DIRECTORY LOG_FILE\n", stderr);
    return 2;
  }
  if (!SetEnvironmentVariableW(L"WVB_WINRT_FIXTURE_LOG", argv[3])) {
    fprintf(stderr, "oracle: log environment error=%lu\n", GetLastError());
    return 2;
  }
  HRESULT hr = RoInitialize(RO_INIT_MULTITHREADED);
  if (FAILED(hr)) {
    fprintf(stderr, "oracle: RoInitialize HRESULT=0x%08lx\n", static_cast<unsigned long>(hr));
    return 2;
  }
  ACTCTXW definition = {};
  definition.cbSize = sizeof(definition);
  definition.dwFlags = ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID;
  definition.lpSource = argv[1];
  definition.lpAssemblyDirectory = argv[2];
  HANDLE context = CreateActCtxW(&definition);
  ULONG_PTR cookie = 0;
  int code = 2;
  bool active = context != INVALID_HANDLE_VALUE && ActivateActCtx(context, &cookie);
  if (active) {
    HSTRING name = nullptr;
    hr = WindowsCreateString(WVB_RUNTIME_CLASS, ARRAYSIZE(WVB_RUNTIME_CLASS) - 1, &name);
    IWvbScalarFactory *factory = nullptr;
    if (SUCCEEDED(hr)) {
      hr = RoGetActivationFactory(name, IID_IWvbScalarFactory, reinterpret_cast<void **>(&factory));
      WindowsDeleteString(name);
    }
    printf("{\"event\":\"factory\",\"hresult\":%ld,\"caller_pid\":%lu,\"thread\":%lu}\n",
           static_cast<long>(hr), GetCurrentProcessId(), GetCurrentThreadId());
    if (SUCCEEDED(hr) && factory) {
      bool identity = module_identity(factory, argv[2], "factory");
      IWvbScalarInstance *instance = nullptr;
      hr = factory->Create(&instance);
      factory->Release();
      printf("{\"event\":\"create\",\"hresult\":%ld}\n", static_cast<long>(hr));
      if (SUCCEEDED(hr) && instance) {
        bool ok = identity && module_identity(instance, argv[2], "instance");
        ok = (instance->Transform(41, nullptr) == E_POINTER) && ok;
        UINT32 output = 0xa5a5a5a5;
        hr = instance->Transform(41, &output);
        printf("{\"event\":\"oracle\",\"hresult\":%ld,\"output\":%u}\n", static_cast<long>(hr), output);
        ok = ok && hr == S_OK && output == 42;
        output = 0xa5a5a5a5;
        hr = instance->Transform(UINT32_MAX, &output);
        printf("{\"event\":\"oracle-error\",\"hresult\":%ld,\"output\":%u}\n", static_cast<long>(hr), output);
        ok = ok && hr == E_INVALIDARG && output == 0xa5a5a5a5;
        instance->Release();
        code = ok ? 0 : 2;
      } else if (instance) instance->Release();
    } else if (factory) factory->Release();
  } else {
    fprintf(stderr, "oracle: activation context error=%lu\n", GetLastError());
  }
  RoUninitialize();
  if (active && !DeactivateActCtx(0, cookie)) {
    fprintf(stderr, "oracle: DeactivateActCtx error=%lu\n", GetLastError());
    code = 2;
  }
  if (context != INVALID_HANDLE_VALUE) ReleaseActCtx(context);
  return code;
}
