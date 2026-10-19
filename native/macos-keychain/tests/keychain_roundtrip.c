#include "wvb_keychain.h"
#include "wvb_unix_runtime.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  char account[128];
  snprintf(account, sizeof(account), "acceptance-%ld", (long)getpid());
  WvbKeychainRecordV1 expected = {
      .magic = WVB_KEYCHAIN_RECORD_MAGIC,
      .version = WVB_KEYCHAIN_RECORD_VERSION,
      .state = WVB_KEYCHAIN_RECORD_ACTIVE,
      .broker_address = "127.0.0.1:47802",
      .connect_timeout_ms = 5000,
      .call_timeout_ms = 5000,
  };
  for (size_t index = 0; index < sizeof(expected.client_private_key); ++index) {
    expected.client_private_key[index] = (uint8_t)(index + 1);
    expected.broker_public_key[index] = (uint8_t)(index + 33);
    expected.build_fingerprint[index] = (uint8_t)(index + 65);
  }
  memset(expected.actor_id, 0x42, sizeof(expected.actor_id));
  memset(expected.client_instance, 0x24, sizeof(expected.client_instance));

  int result = 1;
  if (wvb_keychain_store(account, (const uint8_t *)&expected,
                         sizeof(expected)) != WVB_KEYCHAIN_OK) {
    goto cleanup;
  }
  WvbUnixLoadArgs loaded = {0};
  memcpy(loaded.account, account, strlen(account) + 1);
  if (wvb_unix_load_runtime_config(&loaded) != 0 ||
      memcmp(&loaded.record, &expected, sizeof(expected)) != 0) {
    goto cleanup;
  }
  result = 0;

cleanup:
  memset(&expected, 0, sizeof(expected));
  wvb_keychain_delete(account);
  if (result == 0) {
    puts("macos-keychain-unixlib=ok");
  }
  return result;
}
