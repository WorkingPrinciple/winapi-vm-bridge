#include "wvb_client_unix.h"
#include "wvb_unix_runtime.h"

const WvbUnixClientEntry *wvb_relocation_native_table(void) {
  return __wine_unix_call_funcs;
}

const WvbUnixClientEntry *wvb_relocation_wow64_table(void) {
  return __wine_unix_call_wow64_funcs;
}

int32_t (*wvb_relocation_config_entry(void))(WvbUnixLoadArgs *) {
  return wvb_unix_load_runtime_config;
}
