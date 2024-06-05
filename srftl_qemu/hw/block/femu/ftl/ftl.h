#ifndef __FTL_H
#define __FTL_H

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "crypto/init.h"
#include "crypto/hmac.h"

#define INVALID_PPA     (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define UNMAPPED_PPA    (~(0ULL))



enum {
    NAND_READ =  0,
    NAND_WRITE = 1,
    NAND_ERASE = 2,

    NAND_READ_LATENCY = 40000,
    NAND_PROG_LATENCY = 200000,
    NAND_ERASE_LATENCY = 2000000,
};

enum {
    USER_IO = 0,
    GC_IO = 1,
};

enum {
    SEC_FREE = 0,
    SEC_INVALID = 1,
    SEC_VALID = 2,

    PG_FREE = 0,
    PG_INVALID = 1,
    PG_VALID = 2
};

#define BLK_BITS    (16)
#define PG_BITS     (16)
#define SEC_BITS    (8)
#define PL_BITS     (8)
#define LUN_BITS    (8)
#define CH_BITS     (7)

/* describe a physical page addr */
struct ppa {
    union {
        struct {
            uint64_t blk : BLK_BITS;
            uint64_t pg  : PG_BITS;
            uint64_t sec : SEC_BITS;
            uint64_t pl  : PL_BITS;
            uint64_t lun : LUN_BITS;
            uint64_t ch  : CH_BITS;
            uint64_t rsv : 1;
        } g;

        uint64_t ppa;
    };
};

#define HOTNESS_THRESHOLD 2

#define SECTOR_SZ 512

#define TBL_READ_SZ 64
#define TBL_READ_OFF 8192

#define HMAC_READ_SZ 64
#define HMAC_READ_OFF 24

#define WRITE_SZ 8
#define WRITE_OFF 4096

#define SUSTBL_SZ	1000
#define INIT_RESULT 10
#define NOT_RANSOM 0
#define LOW_PROBABILITY 1
#define MID_PROBABILITY 2
#define HIGH_PROBABILITY 3

#define RW_WINDOW_SIZE 1000
#define UPPER_PROBABILITY 0.95
#define DOWN_PROBABILITY 0

#define LOW_FREQUENCY 5
#define MID_FREQUENCY 10
#define HIGH_FREQUENCY 50
#define TEMP_FREQUENCY 40

#define RESULT_READ_RATIO_NAME "result_read_ratio"
#define RESULT_HOTNESS_NAME "result_hotness"
#define VALID_NAME "result_valid_ratio"

#define TYPE_RANGE 0
#define TYPE_SUSTBL 1
#define TYPE_INI 2

struct pg_rw_status {
    uint8_t first : 1; //0 means empty, 1 means read
    uint8_t second : 1; //0 means empty, 1 means write
    uint8_t is_ransom : 1; //0 means not ransomware page, 1 means it is possible that the page is ransomeware page
};

struct pg_rd_wr_freq {
    uint32_t write_freq; //0 means the page has never been written, > 0 means the number that written to this page
    uint32_t read_freq; //0 means this page has never been written, > 0 means the number that the page has been read
};


struct suspicious_pg_info {
	struct ppa ppa;
	uint64_t lpn;
	uint64_t lba; // lba = lpn * secs_per_pg
        uint8_t have_read; // Has previous read: 0 not have, 1 have
	uint8_t rw_flag; //0 means read, 1 means write, 2 means empty.
};

struct immune_sustbl_list {
	uint16_t tbl_sz;
	uint16_t tbl_id;
	uint8_t tbl_type; 
	struct suspicious_pg_info *current_tbl;
	struct immune_sustbl_list *next;
};

struct result {
	uint64_t lpn;
	uint8_t rw_flag; // 0 read, 1 write, 2 means empty
	uint8_t result_level; // 0 means not the ransomware data, 1 means low probability to be ransomware data, 2 means middle probability to be ransomware data, 3 means high probability

};

struct suspend_time {
	uint32_t suspend_gc_time;	//The corresponding page will suspend gc after suspend_gc_time
	uint32_t current_gc_time;
	struct ppa ppa;
};


typedef int nand_sec_status_t;

struct nand_page {
    nand_sec_status_t *sec;
    int nsecs;
    int status;
};

struct nand_block {
    struct nand_page *pg;
    int npgs;
    int ipc; /* invalid page count */
    int vpc; /* valid page count */
    int erase_cnt;
    int wp; /* current write pointer */
};

struct nand_plane {
    struct nand_block *blk;
    int nblks;
};

struct nand_lun {
    struct nand_plane *pl;
    int npls;
    uint64_t next_lun_avail_time;
    bool busy;
    uint64_t gc_endtime;
};

struct ssd_channel {
    struct nand_lun *lun;
    int nluns;
    uint64_t next_ch_avail_time;
    bool busy;
    uint64_t gc_endtime;
};

struct ssdparams {
    int secsz;        /* sector size in bytes */
    int secs_per_pg;  /* # of sectors per page */
    int pgs_per_blk;  /* # of NAND pages per block */
    int blks_per_pl;  /* # of blocks per plane */
    int pls_per_lun;  /* # of planes per LUN (Die) */
    int luns_per_ch;  /* # of LUNs per channel */
    int nchs;         /* # of channels in the SSD */

    int pg_rd_lat;    /* NAND page read latency in nanoseconds */
    int pg_wr_lat;    /* NAND page program latency in nanoseconds */
    int blk_er_lat;   /* NAND block erase latency in nanoseconds */
    int ch_xfer_lat;  /* channel transfer latency for one page in nanoseconds
                       * this defines the channel bandwith
                       */

    double gc_thres_pcent;
    int gc_thres_lines;
    double gc_thres_pcent_high;
    int gc_thres_lines_high;
    bool enable_gc_delay;

    /* below are all calculated values */
    int secs_per_blk; /* # of sectors per block */
    int secs_per_pl;  /* # of sectors per plane */
    int secs_per_lun; /* # of sectors per LUN */
    int secs_per_ch;  /* # of sectors per channel */
    int tt_secs;      /* # of sectors in the SSD */

    int pgs_per_pl;   /* # of pages per plane */
    int pgs_per_lun;  /* # of pages per LUN (Die) */
    int pgs_per_ch;   /* # of pages per channel */
    int tt_pgs;       /* total # of pages in the SSD */

    int blks_per_lun; /* # of blocks per LUN */
    int blks_per_ch;  /* # of blocks per channel */
    int tt_blks;      /* total # of blocks in the SSD */

    int secs_per_line;
    int pgs_per_line;
    int blks_per_line;
    int tt_lines;

    int pls_per_ch;   /* # of planes per channel */
    int tt_pls;       /* total # of planes in the SSD */

    int tt_luns;      /* total # of LUNs in the SSD */
};

typedef struct line {
    int id;  /* line id, the same as corresponding block id */
    int ipc; /* invalid page count in this line */
    int vpc; /* valid page count in this line */
    QTAILQ_ENTRY(line) entry; /* in either {free,victim,full} list */
    /* position in the priority queue for victim lines */
    size_t                  pos;
} line;

/* wp: record next write addr */
struct write_pointer {
    struct line *curline;
    int ch;
    int lun;
    int pg;
    int blk;
    int pl;
};

struct line_mgmt {
    struct line *lines;
    /* free line list, we only need to maintain a list of blk numbers */
    QTAILQ_HEAD(free_line_list, line) free_line_list;
    pqueue_t *victim_line_pq;
//    QTAILQ_HEAD(victim_line_list, line) victim_line_list;
    QTAILQ_HEAD(full_line_list, line) full_line_list;
    int tt_lines;
    int free_line_cnt;
    int victim_line_cnt;
    int full_line_cnt;
};

struct nand_cmd {
    int type;
    int cmd;
    int64_t stime; /* Coperd: request arrival time */
};

struct ssd {
    char *ssdname;
    struct ssdparams sp;
    struct ssd_channel *ch;
    struct ppa *maptbl; /* page level mapping table */
    uint64_t *rmap;     /* reverse mapptbl, assume it's stored in OOB */
    struct write_pointer wp;
    struct line_mgmt lm;

        /*Frequency table for recording */
        struct pg_rd_wr_freq *freq_table;

	/*Statu table of each lpn*/
	struct pg_rw_status *statbl;
	/*Normal suspicious page table and immune suspicious table*/
	
	uint16_t immtbl_num;
	uint16_t sus_num;
	uint16_t range_num;
	struct suspicious_pg_info *sustbl;
	struct suspicious_pg_info *range_info;
	struct immune_sustbl_list *immtbl_list;
	uint16_t immtbl_id;

	/*Record the current read and write number*/
	uint64_t rw_total_number;
	uint64_t r_number;
	uint64_t w_number;
	uint64_t r_w_number;
	uint64_t r_range;
	uint64_t w_range;
	uint16_t r_num_window;
	uint16_t w_num_window;
	uint64_t identified_pg_num;
	uint64_t low_num;
	uint64_t mid_num;
	uint64_t high_num;
	uint64_t fine_num;
	uint64_t sus_range_num;

	uint64_t current_high_num;
	uint64_t current_marked_pg;

	/*Result part*/
	uint64_t marked_pg;
	bool is_result; // false means no result return, true means  result has returned
	bool no_processing;
	struct result *result; 
	struct suspend_time *suspend; 
	
    /* lockless ring for communication with NVMe IO thread */
    struct rte_ring *to_ftl;
    struct rte_ring *to_poller;
    bool *dataplane_started_ptr;
    QemuThread ftl_thread;

	bool key; // 1 means key exchange finished successfully. 0 means not.
	uint8_t hmac_key[16];
	QCryptoHmac * hmac;
	uint8_t buf[32768];
	bool stop;

	double start_time;
	double end_time;
	bool is_time;

	bool push;

	uint64_t start_lba;
	uint64_t block_num;
	bool enticing;

	uint64_t sus_write_num;

        uint64_t written_page_num;
        uint64_t read_page_num;
        uint64_t update_page_num;
        uint64_t read_larger_than_1;
        uint64_t update_larger_than_2;
        uint64_t read_larger_than_2;
        uint64_t update_larger_than_3;
        uint64_t read_larger_than_3;

        bool start_train;
        bool stop_train;

        uint32_t valid_number;
        uint64_t cold_rw_num;
        uint64_t cold_r_num, cold_w_num;

        uint32_t range_r_num;
        uint32_t range_w_num;

        uint64_t total_copies;

	FILE *fp;
        FILE *fp_valid;
        FILE *fp_hotness;
};


#endif
