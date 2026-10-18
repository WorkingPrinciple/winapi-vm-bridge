#pragma once

int VendorAdd(int left, int right);
int VendorQuery(const void *request, unsigned int request_bytes,
                void *output, unsigned int *output_bytes);
typedef void (*VendorCallback)(int status, void *context);
int VendorBegin(VendorCallback callback, void *context);

