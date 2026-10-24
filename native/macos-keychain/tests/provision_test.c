#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "wvb_keychain.h"
#include "wvb_unix_runtime.h"

static unsigned adds, zeros, interaction_calls;
static OSStatus add_status, interaction_status;
static const WvbKeychainRecordV1 *expected;
static int cli_copy, io_mode;
static unsigned polls;
static unsigned clocks;
static unsigned reports;
static int output_failure;

static OSStatus test_add(CFDictionaryRef attributes, CFTypeRef *result) {
  assert(!result);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  assert(CFEqual(CFDictionaryGetValue(attributes, kSecUseAuthenticationUI),
                 kSecUseAuthenticationUIFail));
#pragma clang diagnostic pop
  assert(CFEqual(CFDictionaryGetValue(attributes, kSecAttrSynchronizable),
                 kCFBooleanFalse));
  CFDataRef data = CFDictionaryGetValue(attributes, kSecValueData);
  assert(CFDataGetLength(data) == sizeof(*expected));
  assert(memcmp(CFDataGetBytePtr(data), expected, sizeof(*expected)) == 0);
  if (!cli_copy) assert(CFDataGetBytePtr(data) == (const UInt8 *)expected);
  else assert(interaction_calls);
  assert(CFEqual(CFDictionaryGetValue(attributes, kSecAttrService),
                 CFSTR("com.dragoshont.winapi-vm-bridge.runtime-v2")));
  adds++;
  return add_status;
}

static OSStatus forbidden_update(CFDictionaryRef a, CFDictionaryRef b) {
  (void)a; (void)b; assert(0); return errSecParam;
}
static OSStatus forbidden_load(CFDictionaryRef a, CFTypeRef *b) {
  (void)a; (void)b; assert(0); return errSecParam;
}
static OSStatus forbidden_delete(CFDictionaryRef a) {
  (void)a; assert(0); return errSecParam;
}
static OSStatus test_interaction(Boolean allowed) {
  assert(!allowed);
  interaction_calls++;
  return interaction_status;
}

#define SecItemAdd test_add
#define SecItemUpdate forbidden_update
#define SecItemCopyMatching forbidden_load
#define SecItemDelete forbidden_delete
#include "../src/wvb_keychain.c"
#undef SecItemAdd
#undef SecItemUpdate
#undef SecItemCopyMatching
#undef SecItemDelete

static void observed_zero(void *value, size_t length) {
  wvb_runtime_zero(value, length);
  for (size_t i = 0; i < length; ++i)
    assert(((const unsigned char *)value)[i] == 0);
  zeros++;
}

#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/stat.h>
static int test_fstat(int fd, struct stat *info) {
  if (io_mode == 12) return -1;
  int status = fstat(fd, info);
  if (!status) {
    if (io_mode == 9) info->st_mode = S_IFREG | 0600;
    if (io_mode == 10) info->st_uid = geteuid() + 1;
    if (io_mode == 11) info->st_nlink = 1;
  }
  return status;
}
static int test_poll(struct pollfd *fds, nfds_t count, int timeout) {
  polls++;
  assert(timeout > 0 && timeout <= 5000);
  if (io_mode == 1) return 0;
  if (io_mode == 2) { errno = EBADF; return -1; }
  if (io_mode == 3 && polls == 1) { errno = EINTR; return -1; }
  if (io_mode == 7) { errno = EINTR; return -1; }
  return poll(fds, count, timeout);
}
static ssize_t test_read(int fd, void *data, size_t length) {
  if ((io_mode == 4 || io_mode == 6) && length > 1) length = 1;
  if (io_mode == 5) { errno = EIO; return -1; }
  return read(fd, data, length);
}
static int test_clock(clockid_t id, struct timespec *now) {
  if (io_mode == 8) return -1;
  if (io_mode == 6 || io_mode == 7) {
    now->tv_sec = (time_t)(clocks++ * 3);
    now->tv_nsec = 0;
    return 0;
  }
  return clock_gettime(id, now);
}
static int test_report(FILE *stream, const char *format, const char *message) {
  assert(stream == stdout || stream == stderr);
  assert(strcmp(format, "%s\n") == 0);
  assert(zeros == reports + 1);
  assert(!strcmp(message, "provision: invalid input") ||
         !strcmp(message, "provision: created") ||
         !strcmp(message, "provision: selector exists") ||
         !strcmp(message, "provision: noninteractive policy failed") ||
         !strcmp(message, "provision: create failed"));
  reports++;
  return output_failure ? -1 : (int)strlen(message) + 1;
}

#define wvb_runtime_zero observed_zero
#define SecKeychainSetUserInteractionAllowed test_interaction
#define poll test_poll
#define read test_read
#define clock_gettime test_clock
#define fprintf test_report
#define fstat test_fstat
#define main provision_main
#include "../src/wvb_provision.c"
#undef main
#undef read
#undef poll
#undef clock_gettime
#undef fprintf
#undef fstat
#undef wvb_runtime_zero
#undef SecKeychainSetUserInteractionAllowed

static int invoke(const void *data, size_t length, const char *account) {
  int descriptors[2];
  assert(pipe(descriptors) == 0);
  assert(write(descriptors[1], data, length) == (ssize_t)length);
  close(descriptors[1]);
  int saved = dup(STDIN_FILENO);
  assert(saved >= 0 && dup2(descriptors[0], STDIN_FILENO) >= 0);
  close(descriptors[0]);
  char *args[] = {"wvb-provision", "create", (char *)account, NULL};
  polls = 0;
  clocks = 0;
  cli_copy = 1;
  int result = provision_main(3, args);
  cli_copy = 0;
  assert(dup2(saved, STDIN_FILENO) >= 0);
  close(saved);
  return result;
}

int main(void) {
  WvbKeychainRecordV1 record = {
      .magic = WVB_KEYCHAIN_RECORD_MAGIC,
      .version = WVB_KEYCHAIN_RECORD_VERSION,
      .state = WVB_KEYCHAIN_RECORD_ACTIVE,
      .broker_address = "127.0.0.1:1",
      .connect_timeout_ms = 1, .call_timeout_ms = 1};
  assert(sizeof(record) == 208);
  memset(record.client_private_key, 0xa5, sizeof(record.client_private_key));
  expected = &record;
  assert(wvb_keychain_create_runtime("selector", &record) == 0);
  assert(adds == 1);
  add_status = errSecDuplicateItem;
  assert(wvb_keychain_create_runtime("selector", &record) ==
         WVB_KEYCHAIN_ALREADY_EXISTS);
  add_status = errSecInteractionNotAllowed;
  assert(wvb_keychain_create_runtime("selector", &record) == WVB_KEYCHAIN_OS_ERROR);
  unsigned before = adds;
  assert(wvb_keychain_create_runtime("", &record) == WVB_KEYCHAIN_INVALID_ARGUMENT);
  assert(wvb_keychain_create_runtime("bad selector", &record) ==
         WVB_KEYCHAIN_INVALID_ARGUMENT);
  assert(wvb_keychain_create_runtime("\x80", &record) == WVB_KEYCHAIN_INVALID_ARGUMENT);
  char long_account[129]; memset(long_account, 'a', 128); long_account[128] = 0;
  assert(wvb_keychain_create_runtime(long_account, &record) == WVB_KEYCHAIN_INVALID_ARGUMENT);
  for (unsigned field = 0; field < 7; ++field) {
    WvbKeychainRecordV1 invalid = record;
    switch (field) {
      case 0: invalid.magic = 0; break;
      case 1: invalid.version++; break;
      case 2: invalid.state = 0; break;
      case 3: invalid.broker_address[0] = 0; break;
      case 4: memset(invalid.broker_address, 'a', 64); break;
      case 5: invalid.connect_timeout_ms = 0; break;
      case 6: invalid.call_timeout_ms = 0; break;
    }
    assert(wvb_keychain_create_runtime("selector", &invalid) ==
           WVB_KEYCHAIN_INVALID_ARGUMENT);
    assert(wvb_runtime_record_header_valid(&invalid) ==
           (field == 3 || field == 5 || field == 6));
    assert(invoke(&invalid, sizeof(invalid), "selector") != 0);
  }
  assert(adds == before && interaction_calls == 0);
  assert(wvb_keychain_create_runtime(NULL, &record) == WVB_KEYCHAIN_INVALID_ARGUMENT);
  assert(wvb_keychain_create_runtime("selector", NULL) == WVB_KEYCHAIN_INVALID_ARGUMENT);
  assert(invoke(&record, sizeof(record) - 1, "selector") != 0);
  assert(invoke(&record, 0, "selector") != 0);
  unsigned char excess[sizeof(record) + 1] = {0};
  assert(invoke(excess, sizeof(excess), "selector") != 0);
  assert(invoke(&record, sizeof(record), "bad selector") != 0);
  interaction_status = errSecInteractionNotAllowed;
  assert(invoke(&record, sizeof(record), "selector") != 0);
  assert(adds == before && interaction_calls == 1);
  interaction_status = 0;
  add_status = 0;
  assert(invoke(&record, sizeof(record), "selector") == 0);
  add_status = errSecDuplicateItem;
  assert(invoke(&record, sizeof(record), "selector") == 65);
  add_status = errSecInteractionNotAllowed;
  assert(invoke(&record, sizeof(record), "selector") == 65);
  add_status = 0;
  before = adds;
  for (io_mode = 1; io_mode <= 12; ++io_mode) {
    int result = invoke(&record, sizeof(record), "selector");
    assert(result == ((io_mode == 3 || io_mode == 4) ? 0 : 64));
    if (io_mode == 6 || io_mode == 7) assert(polls == 1);
  }
  io_mode = 0;
  assert(adds == before + 2);
  char *bad_args[] = {"wvb-provision", "overwrite", "selector", NULL};
  assert(provision_main(3, bad_args) == 64);
  assert(provision_main(1, bad_args) == 64);
  char *valid_args[] = {"wvb-provision", "create", "selector", NULL};
  int saved = dup(STDIN_FILENO);
  int regular = open("/dev/null", O_RDONLY);
  assert(saved >= 0 && regular >= 0 && dup2(regular, STDIN_FILENO) >= 0);
  close(regular);
  assert(provision_main(3, valid_args) == 64);
  assert(dup2(saved, STDIN_FILENO) >= 0);
  close(saved);
  char max_account[128]; memset(max_account, 'a', 127); max_account[127] = 0;
  assert(invoke(&record, sizeof(record), max_account) == 0);
  output_failure = 1;
  assert(invoke(&record, sizeof(record), "selector") == 74);
  output_failure = 0;
  puts("provision validation/create-only API doubles passed");
  assert(zeros == 32 && reports == zeros);
  wvb_runtime_zero(&record, sizeof(record));
  return 0;
}
