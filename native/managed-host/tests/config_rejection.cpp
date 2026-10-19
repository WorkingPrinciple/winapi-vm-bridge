#include "wvb_managed_host.h"

int main() {
  WvbManagedHost *host = nullptr;
  if (wvb_managed_host_create(nullptr, &host) !=
      WVB_MANAGED_HOST_INVALID_ARGUMENT) {
    return 1;
  }
  if (wvb_managed_host_dispatch(nullptr, 1, nullptr, 0, nullptr, 0,
                                nullptr) !=
      WVB_MANAGED_HOST_INVALID_ARGUMENT) {
    return 2;
  }
  wvb_managed_host_destroy(nullptr);
  return 0;
}
