#ifndef _RANSOM_TYPES_H
#define _RANSOM_TYPES_H

struct file_properties {
    char file_name[200];
    unsigned long long sector_number;
    double modification_time;
    uint16_t link_num;
    unsigned long long byte_size;
    char file_type[40];
    uint8_t type_change;
    uint8_t file_deletion;
};

struct sus_struct {
    unsigned long long lba;
    uint8_t rw_flag; //0 is read, 1 is write
    uint8_t have_read; // 0 is not RBO, 1 is RBO
};

#endif // _RANSOM_TYPES_H
