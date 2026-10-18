#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <type_traits>
#include <vector>

#include "wvb_managed_host.h"

namespace {

using hostfxr_handle = void *;

struct get_hostfxr_parameters {
  size_t size;
  const wchar_t *assembly_path;
  const wchar_t *dotnet_root;
};

struct hostfxr_initialize_parameters {
  size_t size;
  const wchar_t *host_path;
  const wchar_t *dotnet_root;
};

enum hostfxr_delegate_type {
  hdt_com_activation,
  hdt_load_in_memory_assembly,
  hdt_winrt_activation,
  hdt_com_register,
  hdt_com_unregister,
  hdt_load_assembly_and_get_function_pointer
};

using get_hostfxr_path_fn =
    int32_t(__cdecl *)(wchar_t *, size_t *,
                       const get_hostfxr_parameters *);
using hostfxr_initialize_for_runtime_config_fn =
    int32_t(__cdecl *)(const wchar_t *,
                       const hostfxr_initialize_parameters *,
                       hostfxr_handle *);
using hostfxr_get_runtime_delegate_fn =
    int32_t(__cdecl *)(hostfxr_handle, hostfxr_delegate_type, void **);
using hostfxr_close_fn = int32_t(__cdecl *)(hostfxr_handle);
using load_assembly_and_get_function_pointer_fn =
    int32_t(__stdcall *)(const wchar_t *, const wchar_t *, const wchar_t *,
                         const wchar_t *, void *, void **);
using managed_dispatch_fn =
    int32_t(__cdecl *)(uint32_t, const uint8_t *, size_t, uint8_t *, size_t,
                       size_t *);

struct ModuleCloser {
  void operator()(HINSTANCE module) const noexcept {
    if (module != nullptr) {
      FreeLibrary(module);
    }
  }
};

using UniqueModule =
    std::unique_ptr<std::remove_pointer_t<HINSTANCE>, ModuleCloser>;

bool nonempty(const wchar_t *value) {
  return value != nullptr && value[0] != L'\0';
}

bool absolute_path(const wchar_t *value) {
  if (!nonempty(value)) {
    return false;
  }
  return (value[0] == L'\\' && value[1] == L'\\') ||
         (((value[0] >= L'A' && value[0] <= L'Z') ||
           (value[0] >= L'a' && value[0] <= L'z')) &&
          value[1] == L':' &&
          (value[2] == L'\\' || value[2] == L'/'));
}

bool same_directory(const wchar_t *left, const wchar_t *right) {
  std::wstring first(left);
  std::wstring second(right);
  const auto first_split = first.find_last_of(L"\\/");
  const auto second_split = second.find_last_of(L"\\/");
  if (first_split == std::wstring::npos ||
      second_split == std::wstring::npos) {
    return false;
  }
  first.resize(first_split);
  second.resize(second_split);
  return _wcsicmp(first.c_str(), second.c_str()) == 0;
}

bool hash_file(const wchar_t *path, std::array<uint8_t, 32> &digest) {
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD result_size = 0;
  std::vector<uint8_t> object;
  std::array<uint8_t, 64 * 1024> buffer{};
  bool success = false;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size),
                        sizeof(object_size), &result_size, 0) < 0) {
    goto cleanup;
  }
  object.resize(object_size);
  if (BCryptCreateHash(algorithm, &hash, object.data(),
                       static_cast<ULONG>(object.size()), nullptr, 0, 0) < 0) {
    goto cleanup;
  }
  for (;;) {
    DWORD read = 0;
    if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read,
                  nullptr)) {
      goto cleanup;
    }
    if (read == 0) {
      break;
    }
    if (BCryptHashData(hash, buffer.data(), read, 0) < 0) {
      goto cleanup;
    }
  }
  if (BCryptFinishHash(hash, digest.data(),
                       static_cast<ULONG>(digest.size()), 0) < 0) {
    goto cleanup;
  }
  success = true;

cleanup:
  if (hash != nullptr) {
    BCryptDestroyHash(hash);
  }
  if (algorithm != nullptr) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
  }
  CloseHandle(file);
  return success;
}

bool hash_matches(const wchar_t *path, const uint8_t expected[32]) {
  std::array<uint8_t, 32> observed{};
  if (!hash_file(path, observed)) {
    return false;
  }
  uint8_t difference = 0;
  for (size_t index = 0; index < observed.size(); ++index) {
    difference |= static_cast<uint8_t>(observed[index] ^ expected[index]);
  }
  return difference == 0;
}

template <typename Function>
Function symbol(HINSTANCE module, const char *name) {
  const FARPROC procedure = GetProcAddress(module, name);
  static_assert(sizeof(Function) == sizeof(procedure));
  Function function = nullptr;
  std::memcpy(&function, &procedure, sizeof(function));
  return function;
}

} // namespace

struct WvbManagedHost {
  UniqueModule nethost;
  UniqueModule hostfxr;
  managed_dispatch_fn dispatch;
};

extern "C" int32_t
wvb_managed_host_create(const WvbManagedHostConfig *config,
                        WvbManagedHost **host) {
  if (config == nullptr || host == nullptr ||
      config->struct_size != sizeof(WvbManagedHostConfig) ||
      !absolute_path(config->dotnet_root) ||
      !absolute_path(config->nethost_path) ||
      !absolute_path(config->runtime_config_path) ||
      !absolute_path(config->dispatcher_assembly_path) ||
      !absolute_path(config->target_assembly_path) ||
      !nonempty(config->dispatcher_type_name) ||
      !nonempty(config->dispatcher_method_name) ||
      !same_directory(config->dispatcher_assembly_path,
                      config->target_assembly_path)) {
    return WVB_MANAGED_HOST_INVALID_ARGUMENT;
  }
  *host = nullptr;
  if (!hash_matches(config->nethost_path, config->nethost_sha256)) {
    return WVB_MANAGED_HOST_NETHOST_HASH_MISMATCH;
  }
  if (!hash_matches(config->runtime_config_path,
                    config->runtime_config_sha256)) {
    return WVB_MANAGED_HOST_RUNTIME_CONFIG_HASH_MISMATCH;
  }
  if (!hash_matches(config->dispatcher_assembly_path,
                    config->dispatcher_assembly_sha256)) {
    return WVB_MANAGED_HOST_DISPATCHER_HASH_MISMATCH;
  }
  if (!hash_matches(config->target_assembly_path,
                    config->target_assembly_sha256)) {
    return WVB_MANAGED_HOST_TARGET_HASH_MISMATCH;
  }

  UniqueModule nethost(LoadLibraryExW(
      config->nethost_path, nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS));
  if (!nethost) {
    return WVB_MANAGED_HOST_LOAD_FAILED;
  }
  const auto get_hostfxr_path =
      symbol<get_hostfxr_path_fn>(nethost.get(), "get_hostfxr_path");
  if (get_hostfxr_path == nullptr) {
    return WVB_MANAGED_HOST_LOAD_FAILED;
  }
  std::vector<wchar_t> hostfxr_path(32768);
  size_t hostfxr_path_size = hostfxr_path.size();
  const get_hostfxr_parameters path_parameters{
      sizeof(get_hostfxr_parameters), config->dispatcher_assembly_path,
      config->dotnet_root};
  if (get_hostfxr_path(hostfxr_path.data(), &hostfxr_path_size,
                       &path_parameters) != 0 ||
      hostfxr_path_size == 0 ||
      !hash_matches(hostfxr_path.data(), config->hostfxr_sha256)) {
    return WVB_MANAGED_HOST_HOSTFXR_HASH_MISMATCH;
  }

  UniqueModule hostfxr(LoadLibraryExW(
      hostfxr_path.data(), nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS));
  if (!hostfxr) {
    return WVB_MANAGED_HOST_LOAD_FAILED;
  }
  const auto initialize = symbol<hostfxr_initialize_for_runtime_config_fn>(
      hostfxr.get(), "hostfxr_initialize_for_runtime_config");
  const auto get_delegate = symbol<hostfxr_get_runtime_delegate_fn>(
      hostfxr.get(), "hostfxr_get_runtime_delegate");
  const auto close =
      symbol<hostfxr_close_fn>(hostfxr.get(), "hostfxr_close");
  if (initialize == nullptr || get_delegate == nullptr || close == nullptr) {
    return WVB_MANAGED_HOST_LOAD_FAILED;
  }

  hostfxr_handle context = nullptr;
  const hostfxr_initialize_parameters initialize_parameters{
      sizeof(hostfxr_initialize_parameters), nullptr, config->dotnet_root};
  const int32_t initialize_status =
      initialize(config->runtime_config_path, &initialize_parameters, &context);
  if (initialize_status < 0 || context == nullptr) {
    return WVB_MANAGED_HOST_RUNTIME_FAILED;
  }
  void *load_function = nullptr;
  const int32_t delegate_status = get_delegate(
      context, hdt_load_assembly_and_get_function_pointer, &load_function);
  close(context);
  if (delegate_status < 0 || load_function == nullptr) {
    return WVB_MANAGED_HOST_RUNTIME_FAILED;
  }

  void *dispatch = nullptr;
  const auto load_assembly =
      reinterpret_cast<load_assembly_and_get_function_pointer_fn>(
          load_function);
  if (load_assembly(config->dispatcher_assembly_path,
                    config->dispatcher_type_name,
                    config->dispatcher_method_name,
                    reinterpret_cast<const wchar_t *>(-1), nullptr,
                    &dispatch) != 0 ||
      dispatch == nullptr) {
    return WVB_MANAGED_HOST_RUNTIME_FAILED;
  }

  auto created = std::unique_ptr<WvbManagedHost>(
      new (std::nothrow) WvbManagedHost{
          std::move(nethost), std::move(hostfxr),
          reinterpret_cast<managed_dispatch_fn>(dispatch)});
  if (!created) {
    return WVB_MANAGED_HOST_RUNTIME_FAILED;
  }
  *host = created.release();
  return WVB_MANAGED_HOST_OK;
}

extern "C" int32_t
wvb_managed_host_dispatch(WvbManagedHost *host, uint32_t operation_id,
                          const uint8_t *request, size_t request_length,
                          uint8_t *response, size_t response_capacity,
                          size_t *response_length) {
  if (host == nullptr || host->dispatch == nullptr ||
      (request == nullptr && request_length != 0) || response == nullptr ||
      response_length == nullptr) {
    return WVB_MANAGED_HOST_INVALID_ARGUMENT;
  }
  *response_length = 0;
  const int32_t status =
      host->dispatch(operation_id, request, request_length, response,
                     response_capacity, response_length);
  if (*response_length > response_capacity) {
    *response_length = 0;
    return WVB_MANAGED_HOST_DISPATCH_FAILED;
  }
  return status;
}

extern "C" void wvb_managed_host_destroy(WvbManagedHost *host) {
  delete host;
}
