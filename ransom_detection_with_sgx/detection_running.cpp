//
// Created by Weidong Zhu on 12/1/19.
//

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "detection.h"

lba_table_t lba_file_tbl;
lba_set_t lba_set;

int main(void) {
    struct sus_struct *sus_content = (struct sus_struct *) malloc(sizeof(struct sus_struct) * TBL_SIZE);
    struct ftl_comm comm;

#ifndef SGX_ENCLAVE
    printf("WARNING: non-enclave build. not protecting with HMAC\n");
#endif

    init_ftl_comm("/dev/nvme0n1", &comm);
//    load_mapping_table("mapping.tbl", lba_file_tbl, &comm);


    int processed_num = 0;
    while (1) {

        if(processed_num == 0) {
    	    system("python get_lba.py /home/weidong/femu_dir");
	    load_mapping_table("mapping.tbl", lba_file_tbl, &comm);
	}

	processed_num++;
	if(processed_num == 150) {
		processed_num = 0;
	}
							            
//    while (1) {
        int tables_processed = process_single_table(&comm, sus_content);


        if (tables_processed < 0) {
            // TODO: don't crash on malicious tables, just keep processing
            printf("FATAL: failed to process table\n");
            exit(-1);
        // only sleep if we didnt get any table, otherwise, there may be another table waiting
        } else if (tables_processed == 0) {
            // TODO: make timeout be configurable for more performance during heavy I/O
            sleep(1);
        }
    }
}
