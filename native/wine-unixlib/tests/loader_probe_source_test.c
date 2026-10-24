#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

int wmain(int argc, wchar_t **argv);
static char module;
static unsigned int scenario, generated, loads, unloads, invoked, sleeps;

static void forbidden_export(void) { ++invoked; }

HMODULE LoadLibraryExW(const wchar_t *path, void *file, DWORD flags) {
  ++loads;
  assert(wcscmp(path, generated ? L"Z:\\packet\\native_math.dll" : L"wvb_autoconfig.dll") == 0);
  assert(!file && !flags);
  return scenario == 1 ? NULL : &module;
}

FARPROC GetProcAddress(HMODULE instance, const char *name) {
  assert(instance == &module);
  assert(strcmp(name, generated ? "add" : "wvb_builtin_load_config") == 0);
  return scenario == 2 ? NULL : forbidden_export;
}

DWORD GetModuleFileNameW(HMODULE instance, wchar_t *path, DWORD capacity) {
  assert(instance == &module && capacity >= 32);
  if (scenario == 3) return 0;
  if (scenario == 4) return capacity;
  wcscpy(path, L"Z:\\packet\\loaded.dll");
  return (DWORD)wcslen(path);
}

BOOL FreeLibrary(HMODULE instance) {
  assert(instance == &module);
  ++unloads;
  return scenario != 5;
}

DWORD GetCurrentProcessId(void) { return 123; }
DWORD GetLastError(void) { return 127; }
void Sleep(DWORD milliseconds) {
  assert(milliseconds == 10000 && !invoked);
  ++sleeps;
}

int main(void) {
  wchar_t *argv[] = {L"probe", L"Z:\\packet\\native_math.dll"};
  const int expected[] = {0, 70, 71, 72, 72, 73};
  for (generated = 0; generated <= 1; ++generated) {
    for (scenario = 0; scenario <= 5; ++scenario) {
      loads = unloads = invoked = sleeps = 0;
      assert(wmain(generated ? 2 : 1, argv) == expected[scenario]);
      assert(loads == 1 && !invoked);
      assert(unloads == (scenario == 1 ? 0 : 1));
      assert(sleeps == (scenario == 0 || scenario == 5 ? 1 : 0));
    }
  }
  loads = 0;
  argv[1] = L"relative.dll";
  assert(wmain(2, argv) == 74);
  assert(wmain(3, argv) == 74);
  assert(!loads);
  puts("noncalling loader source mocks passed for builtin and explicit generated proxy");
  return 0;
}
