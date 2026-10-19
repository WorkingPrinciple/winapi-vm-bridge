#include <stdint.h>
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#define CALL __stdcall
#else
#define EXPORT
#define CALL
#endif

EXPORT int32_t CALL ExampleAdd(int32_t left, int32_t right) {
    return left + right;
}
