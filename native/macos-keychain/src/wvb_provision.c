#include "wvb_keychain.h"
#include "wvb_unix_runtime.h"

#include <Security/Security.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int read_record(int fd, unsigned char *bytes, size_t capacity) {
  struct stat info;
  /* Anonymous pipes have no pathname; mode bits do not restrict their descriptors. */
  if (fstat(fd, &info) || !S_ISFIFO(info.st_mode) || info.st_uid != geteuid() ||
      info.st_nlink != 0) return 0;
  int64_t start = monotonic_ms();
  if (start < 0) return 0;
  size_t used = 0;
  for (;;) {
    int64_t now = monotonic_ms();
    if (now < 0 || now - start >= 5000) return 0;
    struct pollfd input = {fd, POLLIN, 0};
    int ready = poll(&input, 1, (int)(5000 - (now - start)));
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0 || (input.revents & (POLLERR | POLLNVAL))) return 0;
    ssize_t count = read(fd, bytes + used, capacity - used);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) return 0;
    if (!count) return used == sizeof(WvbKeychainRecordV1);
    used += (size_t)count;
    if (used == capacity) return 0;
  }
}

int main(int argc, char **argv) {
  union {
    WvbKeychainRecordV1 record;
    unsigned char bytes[sizeof(WvbKeychainRecordV1) + 1];
  } input = {0};
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    wvb_runtime_zero(&input, sizeof(input));
    return 71;
  }
  int result = 64;
  const char *message = "provision: invalid input";
  if (argc != 3 || strcmp(argv[1], "create") ||
      !wvb_runtime_account_valid(argv[2]) ||
      !read_record(STDIN_FILENO, input.bytes, sizeof(input.bytes)) ||
      !wvb_runtime_record_valid(&input.record)) goto finish;
  /* Dedicated CLI process only; existing library store/load defaults are unchanged. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  OSStatus interaction = SecKeychainSetUserInteractionAllowed(false);
#pragma clang diagnostic pop
  if (interaction != errSecSuccess) {
    result = 65;
    message = "provision: noninteractive policy failed";
    goto finish;
  }
  int32_t status = wvb_keychain_create_runtime(argv[2], &input.record);
  result = status == WVB_KEYCHAIN_OK ? 0 : 65;
  message = status == WVB_KEYCHAIN_OK ? "provision: created" :
            status == WVB_KEYCHAIN_ALREADY_EXISTS ? "provision: selector exists" :
            "provision: create failed";
finish:
  wvb_runtime_zero(&input, sizeof(input));
  FILE *output = result ? stderr : stdout;
  if (fprintf(output, "%s\n", message) < 0 || fflush(output)) return 74;
  return result;
}
