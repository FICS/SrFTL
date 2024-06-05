#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <detection.h>
#include "sgx_tcrypto.h"

#include <exception>
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

lba_table_t lba_file_tbl;
lba_set_t lba_set;
static bool init = false;
static uint8_t hmac_key[HMAC_KEY_SIZE];

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int puts(const char* str)
{
    return printf("%s\n", str);
}

int putchar(char c)
{
  return printf("%c", c);
}

int pread(int fd, void *buf, size_t count, size_t offset)
{
    int retval = 0;
    sgx_status_t ret = ocall_pread(&retval, fd, buf, count, offset);

    if (ret != SGX_SUCCESS) {
        printf("SGX ERROR: pread\n");
        return -1;
    }

    return retval;
}

int pwrite(int fd, void *buf, size_t count, size_t offset)
{
    int retval = 0;
    sgx_status_t ret = ocall_pwrite(&retval, fd, buf, count, offset);

    if (ret != SGX_SUCCESS) {
        printf("SGX ERROR: pwrite\n");
        return -1;
    }

    return retval;
}

int compute_hmac(void *buf, void *result, int length) {
    sgx_status_t res = sgx_hmac_sha256_msg((unsigned char*)buf, length, (unsigned char*)hmac_key, HMAC_KEY_SIZE, (unsigned char*)result, HMAC_LENGTH);

    if (res != SGX_SUCCESS) {
      printf("SGX ERROR: failed to compute HMAC\n");
      return 0;
    }

    return 1;
}

uint64_t usleep(int time)
{
    uint64_t retval;
    sgx_status_t ret = ocall_usleep(&retval, time);

    if (ret != SGX_SUCCESS) {
        printf("SGX ERROR: usleep\n");
        return -1;
    }

    return retval;
}

uint64_t get_time()
{
    uint64_t retval;
    sgx_status_t ret = ocall_get_time(&retval);

    if (ret != SGX_SUCCESS) {
        printf("SGX ERROR: get_time\n");
        return -1;
    }

    return retval;
}

struct sus_struct *sus_content = NULL;
uint8_t * buf_read = NULL;
uint8_t * buf_hmac = NULL;
uint8_t * buf_write = NULL;
uint8_t * pg_read_buf = NULL;
uint64_t * low_num = NULL;
uint64_t * middle_num = NULL;
uint64_t * high_num = NULL;

int ecall_initialize() {
    if (init) {
        printf("ERROR: SrFTL init twice\n");
        return false;
    }

    memset(hmac_key, 1, HMAC_KEY_SIZE);
    sus_content = (struct sus_struct *) malloc(sizeof(struct sus_struct) * TBL_SIZE);

    // not memaligned in enclave, but this is okay because we copy this to memaligned areas in untrusted app
    buf_read = (uint8_t*)calloc(READ_BUFFER_SZ, 1);
    buf_write = (uint8_t*)calloc(WRITE_BUFFER_SZ, 1);
    pg_read_buf = (uint8_t*)calloc(PG_BUFFER_SZ, 1);
    buf_hmac = (uint8_t*)calloc(HMAC_BUFFER_SZ, 1);
    low_num = (uint64_t*)calloc(sizeof(uint64_t), 1);
    middle_num = (uint64_t*)calloc(sizeof(uint64_t), 1);
    high_num = (uint64_t*)calloc(sizeof(uint64_t), 1);

    if (!sus_content || !buf_read || !buf_write || !pg_read_buf || !buf_hmac) {
        return false;
    }

    printf("SrFTL Enclave init\n");
    init = true;

    return true;
}

int ecall_process_table(int fd) {
    struct ftl_comm comm;

    comm.fd = fd;
    comm.buf_read = buf_read;
    comm.buf_write = buf_write;
    comm.buf_hmac = buf_hmac;
    comm.pg_read_buf = pg_read_buf;
    comm.low_num = low_num;
    comm.high_num = high_num;
    comm.middle_num = middle_num;

    try {
    return process_single_table(&comm, sus_content);
    } catch (std::exception & e) {
        printf("Unhandled exception!\n");
        return -1;
    }
}

void ecall_add_mapping(uint64_t lba, struct file_properties * mapping) {
    //printf("Adding file mapping %lu\n", lba);

	    //printf("%llu, %s\n", lba, mapping->file_type);
    // we need to copy the struct as the lifetime of it ends after this function...
    if(lba_file_tbl.find(lba) == lba_file_tbl.end()) {
        struct file_properties *mid_point = (struct file_properties *) malloc(sizeof(struct file_properties));
	mapping->type_change = 0;
    	memcpy(mid_point, mapping, sizeof(*mid_point));

//	if(strcmp(mid_point->file_type, "data") == 0) // encrypted file will always have data type
//		mid_point->type_change = 1;

	lba_file_tbl[lba] = mid_point;
    }
    else {
	    mapping->type_change=0;
    	if(strcmp(lba_file_tbl[lba]->file_type, mapping->file_type) != 0) {
		//printf("Type change! %s %s\n", lba_file_tbl[lba]->file_type, mapping->file_type);
  	    mapping->type_change=1;
	}

	if(strcmp(lba_file_tbl[lba]->file_name, mapping->file_name) != 0) {
		mapping->	
	}

	if(lba_file_tbl[lba]->type_change == 1)
		mapping->type_change = 1;
	memcpy(lba_file_tbl[lba], mapping, sizeof(struct file_properties));

    }
}
