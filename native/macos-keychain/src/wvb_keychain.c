#include "wvb_keychain.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>

static const char *WVB_SERVICE = "com.dragoshont.winapi-vm-bridge.runtime-v2";

static CFStringRef string(const char *value) {
  if (!value || !value[0]) {
    return NULL;
  }
  return CFStringCreateWithCString(kCFAllocatorDefault, value,
                                   kCFStringEncodingUTF8);
}

static CFMutableDictionaryRef query(CFStringRef account) {
  CFMutableDictionaryRef value = CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  CFStringRef service = string(WVB_SERVICE);
  if (!value || !service) {
    if (value) {
      CFRelease(value);
    }
    if (service) {
      CFRelease(service);
    }
    return NULL;
  }
  CFDictionarySetValue(value, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(value, kSecAttrService, service);
  CFDictionarySetValue(value, kSecAttrAccount, account);
  CFRelease(service);
  return value;
}

int32_t wvb_keychain_store(const char *account_value, const uint8_t *data,
                           size_t data_length) {
  if (!account_value || !account_value[0] || !data || data_length == 0 ||
      data_length > 4096) {
    return WVB_KEYCHAIN_INVALID_ARGUMENT;
  }
  CFStringRef account = string(account_value);
  CFDataRef secret = CFDataCreate(kCFAllocatorDefault, data, data_length);
  CFMutableDictionaryRef match = account ? query(account) : NULL;
  if (!account || !secret || !match) {
    if (account) {
      CFRelease(account);
    }
    if (secret) {
      CFRelease(secret);
    }
    if (match) {
      CFRelease(match);
    }
    return WVB_KEYCHAIN_OS_ERROR;
  }
  const void *update_keys[] = {kSecValueData};
  const void *update_values[] = {secret};
  CFDictionaryRef update = CFDictionaryCreate(
      kCFAllocatorDefault, update_keys, update_values, 1,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  OSStatus status = SecItemUpdate(match, update);
  if (status == errSecItemNotFound) {
    CFDictionarySetValue(match, kSecValueData, secret);
    CFDictionarySetValue(match, kSecAttrSynchronizable, kCFBooleanFalse);
    status = SecItemAdd(match, NULL);
  }
  CFRelease(update);
  CFRelease(match);
  CFRelease(secret);
  CFRelease(account);
  return status == errSecSuccess ? WVB_KEYCHAIN_OK : WVB_KEYCHAIN_OS_ERROR;
}

int32_t wvb_keychain_load(const char *account_value, uint8_t *data,
                          size_t data_capacity, size_t *data_length) {
  if (!account_value || !account_value[0] || !data_length ||
      (data_capacity != 0 && !data)) {
    return WVB_KEYCHAIN_INVALID_ARGUMENT;
  }
  *data_length = 0;
  CFStringRef account = string(account_value);
  CFMutableDictionaryRef match = account ? query(account) : NULL;
  if (!account || !match) {
    if (account) {
      CFRelease(account);
    }
    if (match) {
      CFRelease(match);
    }
    return WVB_KEYCHAIN_OS_ERROR;
  }
  CFDictionarySetValue(match, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(match, kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef result = NULL;
  const OSStatus status = SecItemCopyMatching(match, &result);
  CFRelease(match);
  CFRelease(account);
  if (status == errSecItemNotFound) {
    return WVB_KEYCHAIN_NOT_FOUND;
  }
  if (status != errSecSuccess || !result ||
      CFGetTypeID(result) != CFDataGetTypeID()) {
    if (result) {
      CFRelease(result);
    }
    return WVB_KEYCHAIN_OS_ERROR;
  }
  const CFDataRef secret = (CFDataRef)result;
  const CFIndex length = CFDataGetLength(secret);
  if (length < 0 || (uint64_t)length > SIZE_MAX) {
    CFRelease(result);
    return WVB_KEYCHAIN_OS_ERROR;
  }
  *data_length = (size_t)length;
  if (data_capacity < *data_length) {
    CFRelease(result);
    return WVB_KEYCHAIN_INSUFFICIENT_BUFFER;
  }
  if (*data_length != 0) {
    memcpy(data, CFDataGetBytePtr(secret), *data_length);
  }
  CFRelease(result);
  return WVB_KEYCHAIN_OK;
}

int32_t wvb_keychain_delete(const char *account_value) {
  if (!account_value || !account_value[0]) {
    return WVB_KEYCHAIN_INVALID_ARGUMENT;
  }
  CFStringRef account = string(account_value);
  CFMutableDictionaryRef match = account ? query(account) : NULL;
  if (!account || !match) {
    if (account) {
      CFRelease(account);
    }
    if (match) {
      CFRelease(match);
    }
    return WVB_KEYCHAIN_OS_ERROR;
  }
  const OSStatus status = SecItemDelete(match);
  CFRelease(match);
  CFRelease(account);
  if (status == errSecItemNotFound) {
    return WVB_KEYCHAIN_NOT_FOUND;
  }
  return status == errSecSuccess ? WVB_KEYCHAIN_OK : WVB_KEYCHAIN_OS_ERROR;
}
