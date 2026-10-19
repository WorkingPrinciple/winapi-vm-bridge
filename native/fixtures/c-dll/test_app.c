#include <stdint.h>
#include <stdio.h>

int32_t __stdcall ExampleAdd(int32_t left, int32_t right);

int main(void) {
    int32_t result = ExampleAdd(19, 23);
    if (result != 42) {
        fprintf(stderr, "expected 42, got %d\n", (int)result);
        return 1;
    }
    puts("generated proxy -> dispatcher -> real DLL passed");
    return 0;
}
