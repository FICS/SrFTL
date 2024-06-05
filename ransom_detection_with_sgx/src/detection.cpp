//
// Created by Weidong Zhu on 11/30/19.
//

#include "../include/detection.h"


#ifdef SGX_APP
#include <App.h> // global_eid
#include <Enclave_u.h>
#elif SGX_ENCLAVE
#include <Enclave.h> // printf
#include <Enclave_t.h>
#endif

#ifndef SGX_ENCLAVE
double get_time(void) {
    struct	timeval	mytime;
    gettimeofday(&mytime,NULL);
    return (mytime.tv_sec*1.0+mytime.tv_usec/1000000.0);
}
#endif

#define RANSOM_LABEL 1

struct heuristics {
	uint8_t high_entropy;
	uint8_t low_chi;
	uint8_t rbo;
	uint8_t malicious_rr;
	uint8_t file_type;
	uint8_t file_deletion;
};

static int previous_id = -1;

uint64_t base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                         'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                         'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                         'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

void print_hmac(uint8_t hmac[HMAC_LENGTH]) {
  for (int i = 0; i < HMAC_LENGTH; i++) {
    printf("%02x", hmac[i]);
  }
  printf("\n");
}

#ifndef SGX_APP
int process_single_table(struct ftl_comm * comm, struct sus_struct * sus_content) {
    //read 32768B, write 4096B

    struct file_properties *mid_point = NULL;

    uint8_t cs_buffer[4*4096];
    uint8_t pgs_in_cs;
    uint16_t index_array[4];
    bool entropy_array[4];
    uint8_t *buf_read;
    uint8_t *buf_write;
    uint8_t *pg_read_buf;
    uint8_t *buf_hmac;
    int fd = -1;
    uint16_t id;
    uint8_t type;
    uint16_t length = 0;
    uint16_t read_point = 0;
    uint16_t write_point = 0;
    uint16_t hmac_point =0;
    unsigned long long current_time = 0;

    bool entropy_high_or_low;

    struct heuristics heuristics[TBL_SIZE];

    uint8_t result[TBL_SIZE];
    uint16_t malice_score[TBL_SIZE];
    uint8_t hmac_value[HMAC_LENGTH];
    uint8_t hmac_of_read[HMAC_LENGTH];

    uint8_t table_hmac_value[HMAC_LENGTH];
    uint8_t table_read_hmac[HMAC_LENGTH];
    uint8_t table_write_hmac[HMAC_LENGTH];
    uint16_t read_table_length = 0;

    int flag = 0, len = 0;
    int is_ransom = RANSOM_LABEL;

    fd = comm->fd;
    buf_read = comm->buf_read;
    buf_write = comm->buf_write;
    pg_read_buf = comm->pg_read_buf;
    buf_hmac = comm->buf_hmac;

    char command_str[10];

    memset(command_str, 0, 10);
    memset(buf_read, 0, READ_BUFFER_SZ);
    memset(buf_write, 0, WRITE_BUFFER_SZ);


    memset(heuristics, 0, TBL_SIZE*sizeof(struct heuristics));

    len = pread(fd, buf_read, READ_BUFFER_SZ, READ_BUFFER_OFF);

    if (len == -1) {
        printf("Read error!\n");
        return -1;
    }

    if (len < 15 + (length * 9))
        return 0;

    read_point = 0;
    write_point = 0;

    memcpy(command_str, buf_read, sizeof(command_str)-1);
    read_point += 10;
    if (strcmp(command_str, "Nothing!") == 0 || strcmp(command_str, "result!") != 0) {
//        printf("Nothing!\n");
        return 0;
    }

//    printf("Processing table...\n");

    memcpy(&id, buf_read + read_point, sizeof(uint16_t));
    read_point += sizeof(uint16_t);

    memcpy(&type, buf_read + read_point, sizeof(uint8_t));
    read_point += sizeof(uint8_t);

    memcpy(&length, buf_read + read_point, sizeof(uint16_t));
    read_point += sizeof(uint16_t);

//    printf("id: %d\n", id);
//    printf("type: %d\n", type);
//    printf("length: %d\n", length);

    if (length <= 0 || length > TBL_SIZE) {
        printf("length not correct! length is %u\n", length);
        return -1;
    }

    if (type != TYPE_RANGE && type != TYPE_SUSTBL) {
        printf("Type no correct! type is %u\n", type);
        return -1;
    }

    if(id != previous_id) {
        memset(result, 0, length);
        read_table_length = 10 + 2 * sizeof(uint16_t) + sizeof(uint8_t) + length * (sizeof(unsigned long long) + sizeof(uint8_t) + sizeof(uint8_t));

        memcpy(table_read_hmac, buf_read + read_table_length, HMAC_LENGTH);

#ifdef SGX_ENCLAVE
        compute_hmac(buf_read, table_hmac_value, read_table_length);

        if(memcmp(table_read_hmac, table_hmac_value, HMAC_LENGTH) != 0) {
            printf("Table HMAC not match!\n");
            print_hmac(table_hmac_value);
            printf("required: ");
            print_hmac(table_read_hmac);
            return -1;
        }
#endif
        for (int i = 0; i < length; i++) {
            memcpy(&sus_content[i].lba, buf_read + read_point, sizeof(unsigned long long));
            read_point += sizeof(unsigned long long);

            memcpy(&sus_content[i].rw_flag, buf_read + read_point, sizeof(uint8_t));
            read_point += sizeof(uint8_t);

	    memcpy(&sus_content[i].have_read, buf_read + read_point, sizeof(uint8_t));
            read_point += sizeof(uint8_t);

	    heuristics[i].rbo = sus_content[i].have_read;
        }
        len = pread(fd, buf_hmac, HMAC_BUFFER_SZ, HMAC_BUFFER_OFF);
        if(len == -1) {
            printf("HMAC buffer error!\n");
            return -1;
        }
        hmac_point = 0;


        memset(malice_score, 0, length* sizeof(uint16_t));
        memset(cs_buffer, 0, 4*4096);
        memset(index_array, 0, 4* sizeof(uint16_t));
        memset(entropy_array, 0, 4* sizeof(bool));


        pgs_in_cs = 0;

	if (type != TYPE_RANGE) {
		printf("Table type error!\n");
		return 0;
	}

        if (type == TYPE_RANGE) {
            int ransom_num = 0;
            bool is_redundant;
            uint16_t read_num = 0, total_num = 0;
	    //printf("type range\n");
            read_num = 0;
            for(int i = 0; i < length; i++) {
                    if(sus_content[i].rw_flag == 0)
                        read_num += 1;
                    total_num += 1;
            }

	    uint64_t prior_lba = 0;
	    uint8_t deletion_heu = 0;
	
            for (int i = 0; i < length; i++) {
		
                if (sus_content[i].rw_flag == 0) {
                    if(tbl_deletion_lba(sus_content[i].lba)) {
			    deletion_heu = 1;
			    break;
		    }
		}
	    }	
//	    if (tbl_deletion()) { // This lba has corresponding file.	
//		    deletion_heu = 1;
//	    }


            for (int i = 0; i < length; i++) {

                if (sus_content[i].rw_flag == 0) {
                    continue;
                } else if (sus_content[i].rw_flag == 1) {
                    memset(pg_read_buf, 0, PG_BUFFER_SZ);

//printf("%d duplicate!!! %llu\n", i, sus_content[i].lba);
			if(prior_lba == sus_content[i].lba) { // this is to solve read and write amplification
				prior_lba = sus_content[i].lba;
				hmac_point += HMAC_LENGTH;

				continue;
			}
                    if (lba_query(sus_content[i].lba, &mid_point)) { // This lba has corresponding file.

			    heuristics[i].file_type = mid_point->type_change;
                   }

		    heuristics[i].file_deletion = deletion_heu;


                    len = pread(fd, pg_read_buf, PG_BUFFER_SZ, 512 * sus_content[i].lba);
                    if (len == -1) {
                        printf("PG read error!\n");
                        return -1;
                    }
		    usleep(1000);

		    prior_lba = sus_content[i].lba;

                    memcpy(hmac_value, buf_hmac + hmac_point, HMAC_LENGTH);
                    hmac_point += HMAC_LENGTH;


                    memcpy(cs_buffer+4096*pgs_in_cs, pg_read_buf, 4096);

                    entropy_high_or_low = entropy_judgement(pg_read_buf);

		    if(entropy_high_or_low)
			    heuristics[i].high_entropy = 1;

                    entropy_array[pgs_in_cs] = entropy_high_or_low;
		    index_array[pgs_in_cs] = i;

                    pgs_in_cs++;

                    if(pgs_in_cs == 4 || i == length - 1) {
                        if(chisquare_judgement(cs_buffer, 4096*pgs_in_cs)) { //Low chi-square
                            for(int j = 0; j < pgs_in_cs; j++) {
				    heuristics[index_array[j]].low_chi = 1;
                            }
                        }
                        pgs_in_cs = 0;
                        memset(entropy_array, 0, 4* sizeof(bool));
                        memset(cs_buffer, 0, 4*4096);
                    }

#ifdef SGX_ENCLAVE
                    compute_hmac(pg_read_buf, hmac_of_read, PG_BUFFER_SZ);
                    if(memcmp(hmac_of_read, hmac_value, HMAC_LENGTH) != 0) {
/*                        printf("HMAC not match1!\n");
                        print[   58.265124] serial8250: too much work for irq4
_hmac(hmac_of_read);
                        printf("required: ");
                        print_hmac(hmac_value);
			printf("i: %d, lba: %llu, rw: %d\n", i, sus_content[0].lba, sus_content[0].rw_flag);
                        return -1;
*/                    }
#endif
		    if ((1.0 * read_num / total_num > 0.25 && 1.0 * read_num / total_num < 0.75)) {
			heuristics[i].malicious_rr = 1;
		}
                } else {
                    flag = sus_content[i].rw_flag;
                    printf("RW flag error! %d\n", flag);
                    break;
                }


            if (flag != 0 && flag != 1) {
                flag = 0;
                return 0;
            }

        }


            int w_num = 0;
	    int entropy_num = 0, chi_num = 0, rbo_num = 0, rr_num = 0, type_num = 0, deletion_num = 0;
	    prior_lba = 0;
            for (int i = 0; i < length; i++) {
                if(sus_content[i].rw_flag == 1) {
			if(prior_lba == sus_content[i].lba) { // this is to solve read and write amplification
				prior_lba = sus_content[i].lba;

                                continue;
                        }

			w_num++;

			if(heuristics[i].high_entropy == 1)
				entropy_num++;
			if(heuristics[i].low_chi == 1)
				chi_num++;
			if(heuristics[i].rbo == 1)
				rbo_num++;
			if(heuristics[i].malicious_rr == 1)
				rr_num++;
			if(heuristics[i].file_type == 1)
				type_num++;
			if(heuristics[i].file_deletion == 1)
				deletion_num++;


			if(heuristics[i].high_entropy == 1) {
				if(heuristics[i].rbo == 1)
					ransom_num++;
				else {
					if(heuristics[i].malicious_rr == 1) {
						if(heuristics[i].low_chi == 1) {
							ransom_num++;
						} else {
							if(heuristics[i].file_deletion == 1)
								ransom_num++;
						}
					}
				}
			} else {
				if(heuristics[i].malicious_rr == 1)
					if(heuristics[i].file_type == 1)
						ransom_num++;
			}

/*			if(heuristics[i].file_type == 0) {
				if(heuristics[i].high_entropy == 1) {
					if(heuristics[i].rbo == 1)
						ransom_num++;
					else {
						if(heuristics[i].low_chi == 1) {
							if(heuristics[i].malicious_rr == 1)
								ransom_num++;
						}
					}
				}
			} else {
				if(heuristics[i].high_entropy == 1)
					ransom_num++;
				else {
					if(heuristics[i].rbo == 1)
						ransom_num++;
				}
			}
*/
//    			printf("%d,%d,%d,%d,%d,%d,%d\n", heuristics[i].high_entropy, heuristics[i].low_chi, heuristics[i].rbo, heuristics[i].malicious_rr, heuristics[i].file_type, heuristics[i].file_deletion, is_ransom);
			prior_lba = sus_content[i].lba;

		}
            }

	    printf("result:%d,%d\n",w_num,ransom_num);
	    printf("detail:%d,%d,%d,%d,%d,%d\n", entropy_num,chi_num,rbo_num,rr_num,type_num,deletion_num);

	    if((1.0 * ransom_num / w_num) >= 0.3) {
		    for (int i = 0; i < length; i++) {
        	            if (sus_content[i].rw_flag == 0) {
                	        result[i] = HIGH_PROBABILITY; // mark suspicious victim page.
                        	continue;
	                    } else {
				if(heuristics[i].rbo == 1)
					result[i] = LOW_PROBABILITY;
				else
					result[i] = NOT_RANSOM;

			    }

		    }
	    }
        } else {
            printf("Type error!\n");
            return -1;
        }

        if (flag != 0 && flag != 1) {
            flag = 0;
            return 0;
        }

        previous_id = id;
    }

    memcpy(buf_write, &id, sizeof(uint16_t));
    write_point += sizeof(uint16_t);

    memcpy(buf_write + write_point, &length, sizeof(uint16_t));
    write_point += sizeof(uint16_t);
    for (int i = 0; i < length; i++) {
        memcpy(buf_write + write_point, &result[i], sizeof(uint8_t));
        write_point += sizeof(uint8_t);

        memcpy(buf_write + write_point, &(sus_content[i].rw_flag), sizeof(uint8_t));
        write_point += sizeof(uint8_t);
    }

    tbl_deletion_reset();
#ifdef SGX_ENCLAVE
    compute_hmac(buf_write, table_write_hmac, write_point);
    memcpy(buf_write + write_point, table_write_hmac, HMAC_LENGTH);
#endif
    len = pwrite(fd, buf_write, WRITE_BUFFER_SZ, WRITE_BUFFER_OFF);

    if (len == -1) {
        printf("Result write error!\n");
        return -1;
    }

    return 1;
}
#endif

#ifndef SGX_ENCLAVE
void load_mapping_table(const char * tbl_name, lba_table_t & table, struct ftl_comm * comm) {
    FILE *fp = NULL;
    uint64_t enti_lba;
    uint64_t enti_length;
    char enticing_str[10] = "Enticing";
    int fd = -1;
    int len;

    fd = comm -> fd;

    if ((fp = fopen(tbl_name, "r")) == NULL) {
        std::cout << "Cannot open lba_file table! Exiting!" << std::endl;
        exit(-1);
    }

    while (true) {
        unsigned long long lba = 0;
        struct file_properties *mid_point = (struct file_properties *) malloc(sizeof(struct file_properties));

        if (!read_single_mapping_entry(fp, mid_point, &lba)) {
            free(mid_point);
            break;
        } else {
		if(table.find(lba) == table.end()) {
	            table[lba] = mid_point;
		} else {
		    memcpy(table[lba], mid_point, sizeof(struct file_properties));
		    free(mid_point);
		}
        }
    }

/*    memset(comm -> buf_write, 0, WRITE_BUFFER_SZ);
    memcpy(comm -> buf_write, enticing_str, 10);

    tbl_traverse(&enti_lba, table, &enti_length);

    memcpy(comm -> buf_write + 10, &enti_lba, sizeof(uint64_t));
    memcpy(comm -> buf_write + 10 + sizeof(uint64_t), &enti_length, sizeof(uint64_t));
    len = pwrite(fd, comm -> buf_write, WRITE_BUFFER_SZ, WRITE_BUFFER_OFF);

    if (len == -1) {
        printf("Result write error!\n");
        return;
    }*/

    fclose(fp);



    //std::cout << "Read mapping table " << tbl_name << " with " << table.size() << " files" << std::endl;
}

void init_ftl_comm(const char * dev, struct ftl_comm * comm) {
    int fd, res;
    fd = open(dev, O_RDWR | O_DIRECT | O_LARGEFILE, 0755);

    if (fd < 0) {
      perror("open NVME block device");
      exit(-1);
    }

    comm->fd = fd;

    res = posix_memalign((void **) &comm->buf_write, getpagesize(), WRITE_BUFFER_SZ);

    if (res < 0) {
      perror("memalign");
      exit(-1);
    }

    res = posix_memalign((void **) &comm->buf_read, getpagesize(), READ_BUFFER_SZ);

    if (res < 0) {
      perror("memalign");
      exit(-1);
    }

    res = posix_memalign((void **) &comm->pg_read_buf, getpagesize(), PG_BUFFER_SZ);

    if (res < 0) {
      perror("memalign");
      exit(-1);
    }

    res = posix_memalign((void **) &comm->buf_hmac, getpagesize(), HMAC_BUFFER_SZ);

    if (res < 0) {
        perror("memalign");
        exit(-1);
    }

    //printf("FTL comm %s init\n", dev);
}

bool read_single_mapping_entry(FILE * fp, struct file_properties * mid_point, unsigned long long * lba) {
    char lba_str[30];

    char file_name[300];
    char line[350];

    unsigned long long sector_number;
    char sector_number_str[30];

    double modification_time;
    char modification_time_str[30];

    uint32_t link_num;

    unsigned long long byte_size;
    char byte_size_str[30];
    char file_type[20];

    memset(line, 0, sizeof(line));

    if (fgets(line, 300, fp) == NULL)
        return false;

    if (sscanf(line, "%[^,],%[^,],%[^,],%[^,],%u,%[^,],%s", lba_str, file_name, sector_number_str,
               modification_time_str, &link_num,  byte_size_str, file_type) != 7) {
        std::cout << lba << "," << file_name << "," << sector_number << ","
                  << modification_time << "," << link_num << "," << byte_size << std::endl;
        std::cout << "mapping_tbl reads error!" << std::endl;
        exit(-1);
    }

    *lba = strtoull(lba_str, NULL, 10);
    sector_number = strtoul(sector_number_str, NULL, 10);
    byte_size = strtoul(byte_size_str, NULL, 10);
    modification_time = atof(modification_time_str);

//    std::cout << *lba << "," << file_name << "," << sector_number << ","
//               << modification_time <<"," << link_num << "," << byte_size << "," << file_type<< std::endl;

    mid_point->byte_size = byte_size;
    strcpy(mid_point->file_name, file_name);
    strcpy(mid_point->file_type, file_type);
    mid_point->link_num = link_num;
    mid_point->modification_time = modification_time;
    mid_point->sector_number = sector_number;
    mid_point->file_deletion = 0;

    return true;
}
#endif


void base64_decoding(uint8_t *src, uint8_t *dst, uint16_t len) {
    uint8_t counts = 0;
    uint8_t buffer[4];
    int i = 0, p = 0;

    for(i = 0; i < len; i++) {
        uint8_t k;
        for(k = 0 ; k < 64 && base46_map[k] != src[i]; k++);
        buffer[counts++] = k;
        if(counts == 4) {
            dst[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if(buffer[2] != 64)
                dst[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            if(buffer[3] != 64)
                dst[p++] = (buffer[2] << 6) + buffer[3];
            counts = 0;
        }
    }

}

double entropy_calculation(uint8_t *data_buf, uint16_t data_len) {
    static uint16_t byte_num_array[256];

    double entropy = 0.0;
    double pbi = 0.0;

    bool is_encode = true;

    memset(byte_num_array, 0, sizeof(uint16_t) * 256);

    for(int i = 0; i < data_len; i++) {
        byte_num_array[data_buf[i]] += 1;
        if(data_buf[i] < 43 || (data_buf[i] > 43 && data_buf[i] < 47) ||
           (data_buf[i] > 57 && data_buf[i] < 65) ||
           (data_buf[i] > 91 && data_buf[i] < 97) || data_buf[i] > 122)
            is_encode = false;
    }

    for(int i = 0; i < 256; i++) {
        if(byte_num_array[i] == 0)
            continue;
        pbi = (byte_num_array[i] * 1.0) / data_len;
        entropy += pbi * (-1 * log(pbi) / log(2.0)); // log2(1/PBi) = -1 * (logPBi / log(2))
    }
//  printf("internal entropy: %lf\n", entropy);

    if(entropy < 7 && is_encode) {
        uint8_t dst[data_len];
        uint16_t new_byte_num_array[256];
        pbi = 0.0;
        entropy = 0.0;

    	memset(new_byte_num_array, 0, sizeof(uint16_t) * 256);


        base64_decoding(data_buf, dst, data_len);
        for(int i = 0; i < data_len*3/4; i++) {
            new_byte_num_array[dst[i]] += 1;
        }

        for(int i = 0; i < 256; i++) {
            if(new_byte_num_array[i] == 0)
                continue;
            pbi = (new_byte_num_array[i] * 1.0) / (3.0*data_len/4);
            entropy += pbi * (-1 * log(pbi) / log(2.0)); // log2(1/PBi) = -1 * (logPBi / log(2))
        }

    }

    return entropy;
}

double chisquare_calculation(uint8_t *data_buf, uint16_t data_len) {
    static uint16_t byte_num_array[256];

    uint8_t is_encode_array[data_len/256];
    uint8_t current_sector = 0;

    double diff_square, chisquare = 0.0;
    double expected_freq = 1.0*data_len/256;

    memset(is_encode_array, 1, data_len/256);
    memset(byte_num_array, 0, sizeof(uint16_t) * 256);


    //printf("expected freq: %lf\n", expected_freq);
//    printf("len: %d, data: %s\n", data_len, data_buf);
    for(int i = 0; i < data_len; i++) {
        byte_num_array[data_buf[i]] += 1;

//		printf("data: %d", data_buf[i]);
        if((data_buf[i] < 43 || (data_buf[i] > 43 && data_buf[i] < 47) ||
            (data_buf[i] > 57 && data_buf[i] < 65) ||
            (data_buf[i] >= 91 && data_buf[i] < 97) || data_buf[i] > 122) ) {

//		printf("not base: %d str: %c\n", data_buf[i], data_buf[i]);
           is_encode_array[i/256] = 0;


	}
    }

    for(int i = 0; i < 256; i++) {

//	    if(byte_num_array[i]>80)
//	    printf("i: %d, num: %d\n", i, byte_num_array[i]);
        diff_square = byte_num_array[i] > expected_freq ? (byte_num_array[i] - expected_freq) *
                                                          (byte_num_array[i] - expected_freq) :
                      (expected_freq - byte_num_array[i]) * (expected_freq - byte_num_array[i]);
        chisquare += diff_square;
    }

 //  printf("Internal chi: %lf\n", 1.0*chisquare/expected_freq);


    if(chisquare/expected_freq > 293.25) {
        uint8_t dst[data_len];
        uint8_t src[data_len];
        uint16_t dst_len = 0;

	memcpy(src, data_buf, data_len);

        for(int i = 0; i < data_len/256; i++) {
            if(is_encode_array[i] == 0) {
                memcpy(dst+dst_len, src+256*i, 256);
                dst_len += 256;
            } else {

                base64_decoding(src+256*i, dst+dst_len, 256);
                dst_len += (3*256/4);
            }
        }


        if(dst_len == data_len)
            return (chisquare/expected_freq);

	expected_freq = 1.0 * 3 * data_len/(256*4);
//	printf("decoded: %s\n", dst);
        memset(byte_num_array, 0, 256 * sizeof(uint16_t));
        for(int i = 0; i < dst_len; i++) {
            byte_num_array[dst[i]] += 1;
        }

        chisquare = 0.0;

        for(int i = 0; i < 256; i++) {

            diff_square = byte_num_array[i] > expected_freq ? (byte_num_array[i] - expected_freq) *
                                                              (byte_num_array[i] - expected_freq) :
                          (expected_freq - byte_num_array[i]) * (expected_freq - byte_num_array[i]);
            chisquare += diff_square;
        }
    }

    return (chisquare/expected_freq);
}

/*double entropy_calculation(uint8_t *data_buf, uint16_t data_len) {
    static uint16_t byte_num_array[256];

    double entropy = 0.0;
    double pbi = 0.0;

    memset(byte_num_array, 0, sizeof(uint16_t) * 256);

    for(int i = 0; i < data_len; i++) {
        byte_num_array[data_buf[i]] += 1;
    }

    for(int i = 0; i < data_len; i++) {
        if(byte_num_array[i] == 0)
            continue;
        pbi = (byte_num_array[i] * 1.0) / data_len;
        entropy += pbi * (-1 * log(pbi) / log(2.0)); // log2(1/PBi) = -1 * (logPBi / log(2))
    }

    return entropy;
}*/

#ifndef SGX_APP
bool lba_query(unsigned long long lba, struct file_properties **file_property) {
    lba_table_t::iterator iter;

    iter = lba_file_tbl.find(lba);
    if(iter != lba_file_tbl.end()){
        *file_property = lba_file_tbl[lba];
        return true;
    } else {
        iter = lba_file_tbl.begin();
        while(iter != lba_file_tbl.end()) {
            if(iter -> first > lba) {
                *file_property = NULL;
                return false;
            } else {
                if(lba < (iter -> first + iter -> second -> sector_number)) {
                    *file_property = iter -> second;

                    return true;
                } else {
                    ++iter;
                }
            }

        }
    }
    return false;
}

bool tbl_deletion_lba(unsigned long long lba) {
	lba_table_t::iterator iter;

	iter = lba_file_tbl.begin();

	while(iter != lba_file_tbl.end()) {
		if(iter->first == lba || lba < (iter -> first + iter -> second -> sector_number)) {
			if(iter->second->file_deletion == 1) {
				//printf("%llu,%s\n", iter->first, iter->second->file_name);
				return true;
			}
		}	
		++iter;
	}
	return false;

}

bool tbl_deletion() {
	lba_table_t::iterator iter;

	iter = lba_file_tbl.begin();

	while(iter != lba_file_tbl.end()) {
		if(iter->second->file_deletion == 1)
			return true;
		++iter;
	}
	return false;

}

bool lba_exits_in_set(unsigned long long lba) {
    if (lba_set.find(lba) != lba_set.end())
        return true;
    else
        return false;
}

void tbl_deletion_reset() {
	lba_table_t::iterator iter;

	iter = lba_file_tbl.begin();

	while(iter != lba_file_tbl.end()) {
//		if(iter->second->file_deletion == 1) {
//			lba_file_tbl.erase(iter->first);
//			continue;
//		}
		iter->second->file_deletion = 1;
		++iter;
	}

}

#endif

void tbl_traverse(uint64_t *lba, lba_table_t & table, uint64_t *length) {
    lba_table_t::iterator iter;
    iter = table.begin();
    int f_num = 0;

    while(iter != table.end()) {
        printf("%llu,%s,%llu,%lf,%hu,%llu\n",
                iter->first, iter->second->file_name, iter->second->sector_number,
                iter->second->modification_time, iter->second->link_num,
                iter->second->byte_size);
        if(++f_num == 10) {
            *lba = iter -> first;
            *length = iter -> second -> sector_number;
            return;
        }
        ++iter;
    }
}


bool entropy_judgement(uint8_t *data_buf) {
    double entropy = 0.0;
    int pg_round_num = 0;

    for(pg_round_num = 0; pg_round_num < 16; pg_round_num++) {
        entropy = entropy_calculation(data_buf + pg_round_num * 256, 256);
//	printf("entropy: %lf\n", entropy);
        if(entropy >= 7) { //High entropy
            return true; //high entropy
        }
    }
    return false; // low entropy
}

bool chisquare_judgement(uint8_t *data_buf, uint16_t data_len) {
    double chisquare = 0.0;

    chisquare = chisquare_calculation(data_buf, data_len);

//    printf("chi: %lf\n", chisquare);
    if(chisquare <= 293.25)
        return true;
    else
        return false;
}
