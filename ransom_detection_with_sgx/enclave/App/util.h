#ifndef _RANSOM_APP_UTIL
#define _RANSOM_APP_UTIL

#include "sgx_error.h"       /* sgx_status_t */

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;


void print_error_message(sgx_status_t ret);

#endif // _RANSOM_APP_UTIL
