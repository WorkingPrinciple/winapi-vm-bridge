#include "wvb_keychain.h"
#include "wvb_unix_runtime.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 3 || !argv[2][0]) {
    return 64;
  }
  if (!strcmp(argv[1], "delete")) {
    const int32_t status = wvb_keychain_delete(argv[2]);
    return status == WVB_KEYCHAIN_OK || status == WVB_KEYCHAIN_NOT_FOUND ? 0
                                                                        : 65;
  }
  if (strcmp(argv[1], "store")) {
    return 64;
  }
  WvbKeychainRecordV1 record = {
      .magic = WVB_KEYCHAIN_RECORD_MAGIC,
      .version = WVB_KEYCHAIN_RECORD_VERSION,
      .state = WVB_KEYCHAIN_RECORD_ACTIVE,
      .broker_address = "127.0.0.1:47802",
      .connect_timeout_ms = 5000,
      .call_timeout_ms = 5000,
  };
  for (size_t index = 0; index < sizeof(record.client_private_key); ++index) {
    record.client_private_key[index] = (uint8_t)(index + 1);
    record.broker_public_key[index] = (uint8_t)(index + 33);
    record.build_fingerprint[index] = (uint8_t)(index + 65);
  }
  memset(record.actor_id, 0x42, sizeof(record.actor_id));
  memset(record.client_instance, 0x24, sizeof(record.client_instance));
  const int32_t status =
      wvb_keychain_store(argv[2], (const uint8_t *)&record, sizeof(record));
  memset(&record, 0, sizeof(record));
  return status == WVB_KEYCHAIN_OK ? 0 : 66;
}
