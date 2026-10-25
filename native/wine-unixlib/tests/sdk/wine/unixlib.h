#ifndef WVB_TEST_UNIXLIB_H
#define WVB_TEST_UNIXLIB_H
#include <windows.h>
extern uint64_t __wine_unixlib_handle;
NTSTATUS __wine_init_unix_call(void);
NTSTATUS wvb_test_unix_call(unsigned int code, void *args);
#define WINE_UNIX_CALL(code, args) wvb_test_unix_call(code, args)
#endif
