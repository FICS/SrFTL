//
// Created by Weidong Zhu on 11/30/19.
//

#ifndef RANSOM_DETECTION_WITH_SGX_DETECTION_H
#define RANSOM_DETECTION_WITH_SGX_DETECTION_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#ifndef SGX_ENCLAVE
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <iostream>
#include <map>
#include <set>

#define TYPE_RANGE 0
#define TYPE_SUSTBL 1
#define TBL_SIZE 1000
#define NOT_RANSOM 0
#define LOW_PROBABILITY 1
#define MID_PROBABILITY 2
#define HIGH_PROBABILITY 3

#define WRITE_BUFFER_SZ (0x1000)
#define WRITE_BUFFER_OFF (0x200000)
#define READ_BUFFER_SZ (0x8000)
#define READ_BUFFER_OFF (8192 * 512)
#define HMAC_BUFFER_OFF (24 * 512)
#define HMAC_BUFFER_SZ (0x8000)
#define PG_BUFFER_SZ (0x1000)

#define HMAC_KEY_SIZE 16
#define HMAC_LENGTH (32)

// Types shared between SGX enclave/app/non-SGX
#include "types.h"

struct ftl_comm {
    int fd;
    uint8_t * buf_write;
    uint8_t * buf_read;
    uint8_t * pg_read_buf;
    uint8_t * buf_hmac;
    uint64_t * low_num;
    uint64_t * middle_num;
    uint64_t * high_num;
};

typedef std::map<unsigned long long, struct file_properties *> lba_table_t;
typedef std::set<unsigned long long> lba_set_t;

extern lba_table_t lba_file_tbl;
extern lba_set_t lba_set;

void init_ftl_comm(const char * dev, struct ftl_comm * comm);
int process_single_table(struct ftl_comm * comm, struct sus_struct * sus_content);
void load_mapping_table(const char * tbl_name, lba_table_t & table, struct ftl_comm * comm);
#ifndef SGX_ENCLAVE
bool read_single_mapping_entry(FILE * fp, struct file_properties * mid_point, unsigned long long * lba);
#endif
double entropy_calculation(uint8_t *data_buf, uint16_t data_len);
bool lba_query(unsigned long long lba, struct file_properties **file_property);
void tbl_traverse(uint64_t *lba, lba_table_t & table, uint64_t *length);
bool lba_exits_in_set(unsigned long long lba);
void tbl_deletion_reset();
bool tbl_deletion();
bool tbl_deletion_lba(unsigned long long lba);
double chisquare_calculation(uint8_t *data_buf, uint16_t data_len);
bool chisquare_judgement(uint8_t *data_buf, uint16_t data_len);
bool entropy_judgement(uint8_t *data_buf);

// dont use floating point in enclave...
#ifdef SGX_ENCLAVE
uint64_t get_time(void);
#else
double get_time(void);
#endif

#endif //RANSOM_DETECTION_WITH_SGX_DETECTION_H
