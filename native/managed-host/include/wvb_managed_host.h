#ifndef WVB_MANAGED_HOST_H
#define WVB_MANAGED_HOST_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define WVB_MANAGED_HOST_EXPORT __declspec(dllexport)
#else
#define WVB_MANAGED_HOST_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
  WVB_MANAGED_HOST_OK = 0,
  WVB_MANAGED_HOST_INVALID_ARGUMENT = -1,
  WVB_MANAGED_HOST_HASH_MISMATCH = -2,
  WVB_MANAGED_HOST_LOAD_FAILED = -3,
  WVB_MANAGED_HOST_RUNTIME_FAILED = -4,
  WVB_MANAGED_HOST_DISPATCH_FAILED = -5,
  WVB_MANAGED_HOST_INSUFFICIENT_BUFFER = -6
};

typedef struct WvbManagedHostConfig {
  uint32_t struct_size;
  const wchar_t *dotnet_root;
  const wchar_t *nethost_path;
  uint8_t nethost_sha256[32];
  uint8_t hostfxr_sha256[32];
  const wchar_t *runtime_config_path;
  uint8_t runtime_config_sha256[32];
  const wchar_t *dispatcher_assembly_path;
  uint8_t dispatcher_assembly_sha256[32];
  const wchar_t *target_assembly_path;
  uint8_t target_assembly_sha256[32];
  const wchar_t *dispatcher_type_name;
  const wchar_t *dispatcher_method_name;
} WvbManagedHostConfig;

typedef struct WvbManagedHost WvbManagedHost;

WVB_MANAGED_HOST_EXPORT int32_t
wvb_managed_host_create(const WvbManagedHostConfig *config,
                        WvbManagedHost **host);

WVB_MANAGED_HOST_EXPORT int32_t
wvb_managed_host_dispatch(WvbManagedHost *host, uint32_t operation_id,
                          const uint8_t *request, size_t request_length,
                          uint8_t *response, size_t response_capacity,
                          size_t *response_length);

WVB_MANAGED_HOST_EXPORT void
wvb_managed_host_destroy(WvbManagedHost *host);

#ifdef __cplusplus
}
#endif

#endif
