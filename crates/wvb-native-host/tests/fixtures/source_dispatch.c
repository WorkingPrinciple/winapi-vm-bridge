#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#ifdef NO_DISPATCH
int unrelated_export(void) { return 0; }
#else
int32_t whiny_dispatch_v1(uint32_t operation, const uint8_t *request,
                          size_t request_size, uint8_t *response,
                          size_t response_capacity, size_t *response_size) {
  (void)request;
  (void)request_size;
  static atomic_uint_least32_t calls;
  const uint32_t call = atomic_fetch_add_explicit(&calls, 1, memory_order_relaxed) + 1;
  if (response_capacity < sizeof(call)) {
    return -1;
  }
  memcpy(response, &call, sizeof(call));
  *response_size =
      operation == 3 ? response_capacity + 1 : sizeof(call);
  return operation == 2 ? -17 : 0;
}
#endif
