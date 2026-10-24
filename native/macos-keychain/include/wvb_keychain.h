#ifndef WVB_KEYCHAIN_H
#define WVB_KEYCHAIN_H

#include <stddef.h>
#include <stdint.h>

enum {
  WVB_KEYCHAIN_OK = 0,
  WVB_KEYCHAIN_INVALID_ARGUMENT = -1,
  WVB_KEYCHAIN_NOT_FOUND = -2,
  WVB_KEYCHAIN_INSUFFICIENT_BUFFER = -3,
  WVB_KEYCHAIN_OS_ERROR = -4,
  WVB_KEYCHAIN_ALREADY_EXISTS = -5
};

struct WvbKeychainRecordV1;
/* Create-only, noninteractive. The caller owns and must erase record storage. */
int32_t wvb_keychain_create_runtime(const char *account,
                                    const struct WvbKeychainRecordV1 *record);

int32_t wvb_keychain_store(const char *account, const uint8_t *data,
                           size_t data_length);
int32_t wvb_keychain_load(const char *account, uint8_t *data,
                          size_t data_capacity, size_t *data_length);
int32_t wvb_keychain_delete(const char *account);

#endif
