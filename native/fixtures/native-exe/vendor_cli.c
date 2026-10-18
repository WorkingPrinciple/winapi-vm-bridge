#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  DWORD stdin_read = 0;
  char input[1025] = {0};
  ReadFile(GetStdHandle(STD_INPUT_HANDLE), input, 1024, &stdin_read, NULL);
  input[stdin_read] = 0;
  char mode[128] = {0};
  GetEnvironmentVariableA("WVB_MODE", mode, sizeof(mode));
  int exit_code = 0;
  DWORD sleep_ms = 0;
  const char *marker = NULL;
  for (int index = 1; index < argc; ++index) {
    if (!strncmp(argv[index], "--exit=", 7)) {
      exit_code = atoi(argv[index] + 7);
    } else if (!strncmp(argv[index], "--sleep-ms=", 11)) {
      sleep_ms = (DWORD)strtoul(argv[index] + 11, NULL, 10);
    } else if (!strncmp(argv[index], "--child-marker=", 15)) {
      marker = argv[index] + 15;
    }
  }
  if (marker) {
    Sleep(2000);
    FILE *file = fopen(marker, "wb");
    if (file) {
      fputs("unexpected", file);
      fclose(file);
    }
    return 0;
  }
  if (sleep_ms) {
    Sleep(sleep_ms);
  }
  fprintf(stdout, "argc=%d mode=%s stdin=%s", argc, mode, input);
  for (int index = 1; index < argc; ++index) {
    fprintf(stdout, " arg%d=%s", index, argv[index]);
  }
  fputs("\nfixture-stderr\n", stderr);
  return exit_code;
}
