#include <array>
#include <cstdint>
#include <cstring>
#include <cwchar>

#include "wvb_managed_host.h"

namespace {

bool decode_hash(const wchar_t *text, uint8_t output[32]) {
  if (text == nullptr || std::wcslen(text) != 64) {
    return false;
  }
  for (size_t index = 0; index < 32; ++index) {
    const wchar_t pair[3] = {text[index * 2], text[index * 2 + 1], L'\0'};
    wchar_t *end = nullptr;
    const unsigned long value = std::wcstoul(pair, &end, 16);
    if (end == nullptr || *end != L'\0' || value > 0xff) {
      return false;
    }
    output[index] = static_cast<uint8_t>(value);
  }
  return true;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  if (argc != 11) {
    return 64;
  }
  WvbManagedHostConfig config{};
  config.struct_size = sizeof(config);
  config.dotnet_root = argv[1];
  config.nethost_path = argv[2];
  config.runtime_config_path = argv[5];
  config.dispatcher_assembly_path = argv[7];
  config.target_assembly_path = argv[9];
  config.dispatcher_type_name =
      L"Whiny.Generated.ManagedDispatcher, ExampleManagedMath.WhinyDispatcher";
  config.dispatcher_method_name = L"DispatchUnmanaged";
  if (!decode_hash(argv[3], config.nethost_sha256) ||
      !decode_hash(argv[4], config.hostfxr_sha256) ||
      !decode_hash(argv[6], config.runtime_config_sha256) ||
      !decode_hash(argv[8], config.dispatcher_assembly_sha256) ||
      !decode_hash(argv[10], config.target_assembly_sha256)) {
    return 65;
  }

  WvbManagedHost *host = nullptr;
  const int32_t create_status = wvb_managed_host_create(&config, &host);
  if (create_status != WVB_MANAGED_HOST_OK || host == nullptr) {
    return 70;
  }
  std::array<uint8_t, 8> request{};
  const int32_t left = 20;
  const int32_t right = 22;
  std::memcpy(request.data(), &left, sizeof(left));
  std::memcpy(request.data() + sizeof(left), &right, sizeof(right));
  std::array<uint8_t, 8> response{};
  size_t response_length = 0;
  const int32_t dispatch_status = wvb_managed_host_dispatch(
      host, 1, request.data(), request.size(), response.data(), response.size(),
      &response_length);
  int32_t result = 0;
  if (response_length == sizeof(result)) {
    std::memcpy(&result, response.data(), sizeof(result));
  }
  wvb_managed_host_destroy(host);
  return dispatch_status == WVB_MANAGED_HOST_OK &&
                 response_length == sizeof(result) && result == 42
             ? 0
             : 71;
}
