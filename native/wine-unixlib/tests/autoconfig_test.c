#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "wvb_autoconfig.h"

#include <stdio.h>
#include <string.h>

int wmain(int argc, wchar_t **argv) {
  if (argc != 3) {
    return 64;
  }
  char account[128];
  const int account_length =
      WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[2], -1,
                          account, sizeof(account), NULL, NULL);
  if (account_length <= 1) {
    return 65;
  }
  WvbAutoConfig config = {0};
  const int32_t status = wvb_auto_config_load(argv[1], account, &config);
  if (status == WVB_AUTOCONFIG_WINE_API_UNAVAILABLE ||
      status == WVB_AUTOCONFIG_UNIXLIB_LOAD_FAILED) {
    printf("wine-unixlib-runtime=unavailable status=%d last_error=0x%08lx\n",
           status, (unsigned long)GetLastError());
    return 77;
  }
  if (status != WVB_AUTOCONFIG_OK ||
      strcmp(config.broker_address, "127.0.0.1:47802") ||
      config.client_private_key[0] != 1 ||
      config.client_private_key[31] != 32 ||
      config.broker_public_key[0] != 33 ||
      config.connect_timeout_ms != 5000 ||
      config.call_timeout_ms != 5000) {
    printf("wine-unixlib-keychain status=%d last_error=0x%08lx address=%s\n",
           status, (unsigned long)GetLastError(), config.broker_address);
    return 70;
  }
  puts("wine-unixlib-keychain=ok");
  return 0;
}
