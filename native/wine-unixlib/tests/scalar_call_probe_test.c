#include <windows.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wvb_client.h"

int wmain(int argc, wchar_t **argv);
static char module;
static unsigned int scenario, configures, resets, calls, starts, finishes, unloads;
static DWORD error;

WvbStatus wvb_client_configure(const WvbClientConfig *config) {
  ++configures;
  assert(config->struct_size == sizeof(*config));
  assert(config->broker_address_len == 15);
  assert(memcmp(config->broker_address, "127.0.0.1:12345", 15) == 0);
  assert(config->client_private_key[0] == 3 && config->client_private_key[31] == 3);
  assert(config->broker_public_key[0] == 0xab && config->broker_public_key[31] == 0xab);
  assert(config->actor_id[0] == 8 && config->client_instance[0] == 4);
  assert(config->build_fingerprint[0] == 5);
  assert(config->connect_timeout_ms == 2000 && config->call_timeout_ms == 2000);
  return scenario == 1 ? WVB_STATUS_RUNTIME_ERROR : WVB_STATUS_OK;
}

WvbStatus wvb_client_reset(void) {
  ++resets;
  return scenario == 8 ? WVB_STATUS_RUNTIME_ERROR : WVB_STATUS_OK;
}

static int32_t add(int32_t left, int32_t right) {
  assert(left == 20 && right == 22 && starts == 1 && finishes == 0);
  ++calls;
  return scenario == 5 ? 0 : 42;
}

static int trace_start(const wchar_t *path, const char *run,
                       const char *hash, uint64_t limit) {
  ++starts;
  assert(wcscmp(path, L"Z:\\evidence\\trace.jsonl") == 0);
  assert(strcmp(run, "a08-local-builtin-l02") == 0);
  assert(strlen(hash) == 64 && limit == 64);
  return scenario == 4 ? -1 : 0;
}

static int trace_finish(void) {
  ++finishes;
  return scenario == 6 ? -1 : 0;
}

HMODULE LoadLibraryExW(const wchar_t *path, void *file, DWORD flags) {
  assert(wcscmp(path, L"Z:\\packet\\native_math.dll") == 0 && !file && !flags);
  return scenario == 2 ? NULL : &module;
}

FARPROC GetProcAddress(HMODULE instance, const char *name) {
  assert(instance == &module);
  if (scenario == 3) return NULL;
  FARPROC result = NULL;
  if (strcmp(name, "add") == 0) {
    int32_t (*function)(int32_t, int32_t) = add;
    memcpy(&result, &function, sizeof(result));
  } else if (strcmp(name, "whiny_trace_start_v1") == 0) {
    int (*function)(const wchar_t *, const char *, const char *, uint64_t) = trace_start;
    memcpy(&result, &function, sizeof(result));
  } else {
    assert(strcmp(name, "whiny_trace_finish_v1") == 0);
    int (*function)(void) = trace_finish;
    memcpy(&result, &function, sizeof(result));
  }
  return result;
}

BOOL FreeLibrary(HMODULE instance) {
  assert(instance == &module);
  ++unloads;
  return scenario != 7;
}
void SetLastError(DWORD value) { error = value; }
DWORD GetLastError(void) { return error; }
DWORD GetCurrentProcessId(void) { return 123; }
void Sleep(DWORD value) { assert(value == 10000 && calls == 1); }

int main(void) {
  wchar_t *argv[] = {
      L"probe", L"Z:\\packet\\native_math.dll", L"127.0.0.1:12345",
      L"abababababababababababababababababababababababababababababababab",
      L"Z:\\evidence\\trace.jsonl",
      L"0101010101010101010101010101010101010101010101010101010101010101"};
  for (scenario = 0; scenario <= 8; ++scenario) {
    configures = resets = calls = starts = finishes = unloads = 0;
    assert(wmain(6, argv) == (scenario ? 1 : 0));
    assert(configures == 1);
    assert(resets == (scenario == 1 ? 0 : 1));
    assert(calls == (scenario == 0 || scenario >= 5 ? 1 : 0));
    assert(unloads == (scenario == 1 || scenario == 2 ? 0 : 1));
  }
  configures = 0;
  assert(wmain(5, argv) == 2);
  wchar_t *invalid[6];
  memcpy(invalid, argv, sizeof(invalid));
  invalid[2] = L"192.0.2.1:12345";
  assert(wmain(6, invalid) == 2);
  wchar_t *bad_ports[] = {L"127.0.0.1:", L"127.0.0.1:0",
      L"127.0.0.1:65536", L"127.0.0.1:123456", L"127.0.0.1:+12",
      L"127.0.0.1:12x"};
  for (size_t index = 0; index < sizeof(bad_ports) / sizeof(*bad_ports); ++index) {
    invalid[2] = bad_ports[index];
    assert(wmain(6, invalid) == 2);
  }
  invalid[2] = argv[2];
  invalid[1] = L"relative.dll";
  assert(wmain(6, invalid) == 2);
  invalid[1] = argv[1];
  invalid[3] = L"not-hex";
  assert(wmain(6, invalid) == 2);
  invalid[3] = argv[3];
  invalid[5] = L"010101010101010101010101010101010101010101010101010101010101010g";
  assert(wmain(6, invalid) == 2);
  assert(!configures);
  puts("scalar PE caller source mocks passed; no real client/loader/sleep/trace");
  return 0;
}
