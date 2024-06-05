#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

int printf(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
int puts(const char* str);
int putchar(char c);
int pread(int fd, void *buf, size_t count, size_t offset);
int pwrite(int fd, void *buf, size_t count, size_t offset);
int compute_hmac(void *buf, void *result, int length);
int usleep(int time);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
