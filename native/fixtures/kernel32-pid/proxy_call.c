#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "wvb_client.h"

typedef uint32_t (WINAPI *GetPid)(void);
typedef int (*TraceStart)(const wchar_t *, const char *, const char *, uint64_t);
typedef int (*TraceFinish)(void);

static int ascii(const wchar_t *input, char *output, size_t capacity) {
  const size_t length = wcslen(input);
  if (length >= capacity) return 0;
  for (size_t i = 0; i <= length; ++i) {
    if (input[i] > 127) return 0;
    output[i] = (char)input[i];
  }
  return 1;
}

static int hex(const wchar_t *input, uint8_t *output, size_t size) {
  const wchar_t *alphabet = L"0123456789abcdef";
  if (wcslen(input) != size * 2) return 0;
  for (size_t i = 0; i < size; ++i) {
    const wchar_t *high = wcschr(alphabet, input[i * 2]);
    const wchar_t *low = wcschr(alphabet, input[i * 2 + 1]);
    if (!high || !low) return 0;
    output[i] = (uint8_t)((high - alphabet) * 16 + (low - alphabet));
  }
  return 1;
}

static int symbol(HMODULE module, const char *name, void *target, size_t size) {
  FARPROC entry = GetProcAddress(module, name);
  if (!entry || size != sizeof(entry)) {
    fprintf(stderr, "pid-proxy missing export=%s error=%lu\n",
            name, (unsigned long)GetLastError());
    return 0;
  }
  memcpy(target, &entry, size);
  return 1;
}

int wmain(int argc, wchar_t **argv) {
  WvbClientConfig config = {.struct_size = sizeof(config)};
  char address[64], proxy_hash[65];
  uint8_t artifact_hash[32];
  wchar_t *end = NULL;
  HMODULE proxy = NULL;
  GetPid get_pid = NULL;
  TraceStart trace_start = NULL;
  TraceFinish trace_finish = NULL;
  int configured = 0, recording = 0, code = 1;
  FILE *key = NULL;
  if (argc != 11 || !ascii(argv[3], address, sizeof(address)) ||
      !hex(argv[4], config.broker_public_key, sizeof(config.broker_public_key)) ||
      !hex(argv[5], config.actor_id, sizeof(config.actor_id)) ||
      !hex(argv[6], config.client_instance, sizeof(config.client_instance)) ||
      !hex(argv[7], config.build_fingerprint, sizeof(config.build_fingerprint)) ||
      !ascii(argv[10], proxy_hash, sizeof(proxy_hash)) ||
      !hex(argv[10], artifact_hash, sizeof(artifact_hash))) {
    fputs("pid-proxy invalid explicit arguments\n", stderr);
    return 2;
  }
  errno = 0;
  const unsigned long expected = wcstoul(argv[8], &end, 10);
  if (errno || !expected || end == argv[8] || *end) {
    fputs("pid-proxy invalid independently observed PID\n", stderr);
    return 2;
  }
  key = _wfopen(argv[2], L"rb");
  if (!key || fread(config.client_private_key, 1, 32, key) != 32 ||
      fgetc(key) != EOF || ferror(key)) {
    fputs("pid-proxy private key read failed; no call sent\n", stderr);
    goto cleanup;
  }
  if (fclose(key)) {
    key = NULL;
    fputs("pid-proxy private key close failed; no call sent\n", stderr);
    goto cleanup;
  }
  key = NULL;
  config.broker_address = (const uint8_t *)address;
  config.broker_address_len = strlen(address);
  config.connect_timeout_ms = 5000;
  config.call_timeout_ms = 5000;
  const WvbStatus status = wvb_client_configure(&config);
  SecureZeroMemory(config.client_private_key, sizeof(config.client_private_key));
  if (status != WVB_STATUS_OK) {
    fprintf(stderr, "pid-proxy configure failed status=%ld; no call sent\n", (long)status);
    goto cleanup;
  }
  configured = 1;
  proxy = LoadLibraryExW(argv[1], NULL,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  if (!proxy) {
    fprintf(stderr, "pid-proxy load failed error=%lu; no API call sent\n",
            (unsigned long)GetLastError());
    goto cleanup;
  }
  if (!symbol(proxy, "GetCurrentProcessId", &get_pid, sizeof(get_pid)) ||
      !symbol(proxy, "whiny_trace_start_v1", &trace_start, sizeof(trace_start)) ||
      !symbol(proxy, "whiny_trace_finish_v1", &trace_finish, sizeof(trace_finish)))
    goto cleanup;
  if (trace_start(argv[9], "wvb-kernel32-pid", proxy_hash, 64)) {
    fputs("pid-proxy recorder start failed; no API call sent\n", stderr);
    goto cleanup;
  }
  recording = 1;
  SetLastError(0);
  const uint32_t observed = get_pid();
  const DWORD last_error = GetLastError();
  const int trace_status = trace_finish();
  recording = 0;
  if (trace_status || observed != expected) {
    fprintf(stderr, "pid-proxy result=%lu expected=%lu last_error=%lu trace_status=%d; no retry\n",
            (unsigned long)observed, expected, (unsigned long)last_error, trace_status);
    goto cleanup;
  }
  printf("pid-proxy result=%lu expected=%lu caller_pid=%lu\n",
         (unsigned long)observed, expected, (unsigned long)GetCurrentProcessId());
  code = 0;

cleanup:
  SecureZeroMemory(config.client_private_key, sizeof(config.client_private_key));
  if (key && fclose(key)) {
    fputs("pid-proxy cleanup key close failed\n", stderr);
    code = 1;
  }
  if (recording && trace_finish()) {
    fputs("pid-proxy cleanup recorder failed\n", stderr);
    code = 1;
  }
  if (configured && wvb_client_reset() != WVB_STATUS_OK) {
    fputs("pid-proxy cleanup client reset failed\n", stderr);
    code = 1;
  }
  if (proxy && !FreeLibrary(proxy)) {
    fprintf(stderr, "pid-proxy cleanup unload failed error=%lu\n",
            (unsigned long)GetLastError());
    code = 1;
  }
  return code;
}
