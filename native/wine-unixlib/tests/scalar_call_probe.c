#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "wvb_client.h"

typedef int32_t (*Add)(int32_t, int32_t);
typedef int (*TraceStart)(const wchar_t *, const char *, const char *, uint64_t);
typedef int (*TraceFinish)(void);

static int ascii(const wchar_t *input, char *output, size_t capacity) {
  const size_t length = wcslen(input);
  if (length >= capacity) return 0;
  for (size_t index = 0; index <= length; ++index) {
    if (input[index] > 127) return 0;
    output[index] = (char)input[index];
  }
  return 1;
}

static int hex_byte(wchar_t high, wchar_t low) {
  const wchar_t *alphabet = L"0123456789abcdef";
  const wchar_t *a = wcschr(alphabet, high);
  const wchar_t *b = wcschr(alphabet, low);
  if (!high || !low || !a || !b) return -1;
  return (int)((a - alphabet) * 16 + (b - alphabet));
}

static int absolute(const wchar_t *path) {
  return wcslen(path) >= 3 &&
         ((path[0] >= L'A' && path[0] <= L'Z') ||
          (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' &&
         (path[2] == L'\\' || path[2] == L'/');
}

static int loopback(const char *address) {
  if (strncmp(address, "127.0.0.1:", 10) != 0) return 0;
  unsigned int port = 0;
  size_t index = 10;
  if (!address[index]) return 0;
  for (; address[index]; ++index) {
    if (index >= 15 || address[index] < '0' || address[index] > '9') return 0;
    port = port * 10 + (unsigned int)(address[index] - '0');
  }
  return port >= 1 && port <= 65535;
}

static int symbol(HMODULE module, const char *name, void *target, size_t size) {
  FARPROC entry = GetProcAddress(module, name);
  if (!entry || size != sizeof(entry)) {
    fprintf(stderr, "a08-scalar failed export=%s error=%lu\n",
            name, (unsigned long)GetLastError());
    return 0;
  }
  memcpy(target, &entry, size);
  return 1;
}

int wmain(int argc, wchar_t **argv) {
  char address[32], proxy_hash[65];
  WvbClientConfig config = {.struct_size = sizeof(config)};
  HMODULE proxy = NULL;
  Add add = NULL;
  TraceStart trace_start = NULL;
  TraceFinish trace_finish = NULL;
  int code = 1, configured = 0, recording = 0;
  if (argc != 6 || !absolute(argv[1]) || !absolute(argv[4]) ||
      !ascii(argv[2], address, sizeof(address)) ||
      !ascii(argv[5], proxy_hash, sizeof(proxy_hash)) ||
      strlen(proxy_hash) != 64 || wcslen(argv[3]) != 64 ||
      !loopback(address)) {
    fputs("a08-scalar invalid explicit synthetic arguments\n", stderr);
    return 2;
  }
  for (size_t index = 0; index < 32; ++index) {
    const int value = hex_byte(argv[3][index * 2], argv[3][index * 2 + 1]);
    if (value < 0 || hex_byte(argv[5][index * 2], argv[5][index * 2 + 1]) < 0) {
      fputs("a08-scalar invalid public-key/artifact hex\n", stderr);
      return 2;
    }
    config.broker_public_key[index] = (uint8_t)value;
  }
  config.broker_address = (const uint8_t *)address;
  config.broker_address_len = strlen(address);
  memset(config.client_private_key, 3, sizeof(config.client_private_key));
  memset(config.actor_id, 8, sizeof(config.actor_id));
  memset(config.client_instance, 4, sizeof(config.client_instance));
  memset(config.build_fingerprint, 5, sizeof(config.build_fingerprint));
  config.connect_timeout_ms = 2000;
  config.call_timeout_ms = 2000;
  const WvbStatus configured_status = wvb_client_configure(&config);
  memset(config.client_private_key, 0, sizeof(config.client_private_key));
  if (configured_status != WVB_STATUS_OK) {
    fprintf(stderr, "a08-scalar configure failed status=%ld\n", (long)configured_status);
    goto cleanup;
  }
  configured = 1;
  proxy = LoadLibraryExW(argv[1], NULL, 0);
  if (!proxy) {
    fprintf(stderr, "a08-scalar proxy load failed error=%lu\n",
            (unsigned long)GetLastError());
    goto cleanup;
  }
  if (!symbol(proxy, "add", &add, sizeof(add)) ||
      !symbol(proxy, "whiny_trace_start_v1", &trace_start, sizeof(trace_start)) ||
      !symbol(proxy, "whiny_trace_finish_v1", &trace_finish, sizeof(trace_finish)))
    goto cleanup;
  if (trace_start(argv[4], "a08-local-builtin-l02", proxy_hash, 64) != 0) {
    fputs("a08-scalar recorder start failed\n", stderr);
    goto cleanup;
  }
  recording = 1;
  SetLastError(0);
  const int32_t value = add(20, 22);
  const DWORD native_error = GetLastError();
  if (trace_finish() != 0) {
    recording = 0;
    fputs("a08-scalar recorder finish failed\n", stderr);
    goto cleanup;
  }
  recording = 0;
  if (value != 42) {
    fprintf(stderr, "a08-scalar unexpected result=%ld last-error=%lu\n",
            (long)value, (unsigned long)native_error);
    goto cleanup;
  }
  printf("a08-scalar=called result=42 windows-pid=%lu last-error=%lu\n",
         (unsigned long)GetCurrentProcessId(), (unsigned long)native_error);
  fflush(stdout);
  Sleep(10000);
  code = 0;

cleanup:
  if (recording && trace_finish() != 0) {
    fputs("a08-scalar cleanup recorder failed\n", stderr);
    code = 1;
  }
  if (configured && wvb_client_reset() != WVB_STATUS_OK) {
    fputs("a08-scalar cleanup reset failed\n", stderr);
    code = 1;
  }
  if (proxy && !FreeLibrary(proxy)) {
    fprintf(stderr, "a08-scalar cleanup unload failed error=%lu\n",
            (unsigned long)GetLastError());
    code = 1;
  }
  if (!code) puts("a08-scalar=unloaded");
  return code;
}
