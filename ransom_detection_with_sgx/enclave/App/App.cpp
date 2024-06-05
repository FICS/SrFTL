#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "util.h"

#include <detection.h>
#include <unistd.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
struct ftl_comm comm;

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    //fprintf(stderr, "ENCLAVE: %s", str);
    fprintf(stderr, "%s", str);
}

int ocall_pread(int fd, void* buf, size_t len, size_t offset) {
  //printf("PR: %d, %p, %zu, %zu\n", fd, buf, len, offset);

  if (len > READ_BUFFER_SZ) {
    printf("ERROR: ocall_pread tried to read more than expected\n");
    return -1;
  }

  int ret = pread(fd, comm.buf_read, len, offset);

  if (ret < 0) {
    perror("pread");
  } else {
    memcpy(buf, comm.buf_read, len);
  }

  return ret;
}

uint64_t ocall_get_time() {
  return (uint64_t)get_time();
}

int ocall_usleep(int time) {
  return (int)usleep(time);
}

int ocall_pwrite(int fd, void* buf, size_t len, size_t offset) {
  //printf("PW: %d, %p, %zu, %zu\n", fd, buf, len, offset);

  if (len > READ_BUFFER_SZ) {
    printf("ERROR: ocall_pwrite tried to read more than expected\n");
    return -1;
  }

  // must copy to memaligned area
  memcpy(comm.buf_read, buf, len);

  int ret = pwrite(fd, comm.buf_read, len, offset);

  if (ret < 0) {
    perror("pwrite");
  }

  return ret;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    printf("SrFTL App init\n");

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        return -1;
    }

    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;

    init_ftl_comm("/dev/nvme0n1", &comm);

    // local copy only before enclave transfer
	
    lba_table_t lba_file_tbl;

    ret = ecall_initialize(global_eid, &retval);

    if (ret != SGX_SUCCESS) {
      print_error_message(ret);
      return -1;
    }

    if (!retval) {
      printf("SrFTL failed to initialize\n");
      sgx_destroy_enclave(global_eid);
      return -1;
    }

    int processed_num = 0;
	
    lba_table_t mid_tbl;

    while (1) {

	if(processed_num == 0) {
	    system("python get_lba.py /home/weidong/femu_dir");
	    mid_tbl.clear();
    	    load_mapping_table("mapping.tbl", mid_tbl, &comm);
	}

	processed_num++;

	if(processed_num == 150) {
	    processed_num = 0;
	}	

    	for (auto it = mid_tbl.begin(); it != mid_tbl.end(); it++) {

	     	sgx_status_t ret = ecall_add_mapping(global_eid, (*it).first, (*it).second);

	  	if (ret != SGX_SUCCESS) {
			print_error_message(ret);
			return -1;
	  	}
    	}


        ret = ecall_process_table(global_eid, &retval, comm.fd);
        //printf("Low: %lld, middle %lld, high: %lld\n", *comm.low_num, *comm.middle_num, *comm.high_num);
        if (retval < 0) {
            // TODO: don't crash on malicious tables, just keep processing
            printf("FATAL: failed to process table\n");
//            break;
        // only sleep if we didnt get any table, otherwise, there may be another table waiting
        } else if (retval == 0) {
            // TODO: make timeout be configurable for more performance during heavy I/O
            sleep(1);
        }
        //sleep(1);
    }

    printf("Exiting...\n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}

