#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "../nvme.h"
#include "ftl.h"


static void *ftl_thread(void *arg);
static uint32_t get_suspend_time(uint8_t result_level);

/*Initiate the result table*/

static double get_time(void) {
	struct timeval mytime;
	gettimeofday(&mytime, NULL);
	return (mytime.tv_sec * 1.0 + mytime.tv_usec / 1000000.0);
}

static void ssd_init_result(struct ssd *ssd) {
	int i;
	uint16_t length = SUSTBL_SZ>RW_WINDOW_SIZE?SUSTBL_SZ:RW_WINDOW_SIZE;
	ssd->marked_pg = 0;
	ssd->is_result = false;
	ssd->no_processing = true;
	ssd->result = g_malloc0(sizeof(struct result) * length);

	for(i = 0; i < length; i++) {
		ssd->result[i].lpn = 0;
		ssd->result[i].rw_flag = 2;
		ssd->result[i].result_level = INIT_RESULT;
	}
}

static void ssd_re_init_result(struct ssd *ssd) {
	int i;
	uint16_t length = SUSTBL_SZ>RW_WINDOW_SIZE?SUSTBL_SZ:RW_WINDOW_SIZE;

	for(i = 0; i < length; i++) {
		ssd->result[i].lpn = 0;
		ssd->result[i].rw_flag = 2;
		ssd->result[i].result_level = INIT_RESULT;
	}
}

static void update_suspend_time(struct ssd *ssd){
	int i;
	uint32_t sus_time;
	struct result mid_result;
	struct immune_sustbl_list *mid_imm = ssd->immtbl_list;
	
	if(ssd->immtbl_list->tbl_type == TYPE_RANGE) {
		ssd->current_marked_pg = 0;
		ssd->current_high_num = 0;

		for(i = 0; i < mid_imm->tbl_sz; i++){
			mid_result = ssd->result[i];
			//if(ssd->suspend[mid_result.lpn].suspend_gc_time == TEMP_FREQUENCY) {

			//	continue;
			//}
			if(mid_result.rw_flag == 0) {
				sus_time = get_suspend_time(mid_result.result_level);
				//if(ssd->suspend[mid_result.lpn].suspend_gc_time == 0){
					ssd->identified_pg_num += 1;
					if(mid_result.result_level == NOT_RANSOM)
						ssd->fine_num += 1;
					else if(mid_result.result_level == LOW_PROBABILITY){
						ssd->current_marked_pg += 1;
						ssd->marked_pg += 1;
						ssd->low_num += 1;
					}
					else if(mid_result.result_level == MID_PROBABILITY){
						ssd->current_marked_pg += 1;
						ssd->marked_pg += 1;
						ssd->mid_num += 1;
					}
					else{
						ssd->current_marked_pg += 1;
						ssd->marked_pg += 1;
						ssd->high_num += 1;
						ssd->current_high_num += 1;
					}
				//}
                                //if(ssd->suspend[mid_result.lpn].ppa.ppa == UNMAPPED_PPA)
                                //  ssd->suspend[mid_result.lpn].ppa = ssd->maptbl[mid_result.lpn];


				if(sus_time > 0) {
    
                                  if(ssd->suspend[mid_result.lpn].suspend_gc_time == TEMP_FREQUENCY || mid_result.result_level == LOW_PROBABILITY)
                                    ssd->suspend[mid_result.lpn].suspend_gc_time = LOW_FREQUENCY;
                                  if(ssd->suspend[mid_result.lpn].suspend_gc_time < sus_time)
					ssd->suspend[mid_result.lpn].suspend_gc_time = sus_time;
                                  //ssd->suspend[mid_result.lpn].ppa = mid_imm->current_tbl[i].ppa;
				}
			//} else {
			//	ssd->sus_write_num += 1;
			}
		}
        }

}



static uint32_t get_suspend_time(uint8_t result_level) {
	if(result_level == NOT_RANSOM)
		return 0;
	else if(result_level == LOW_PROBABILITY)
		return LOW_FREQUENCY;
	else if(result_level == MID_PROBABILITY)
		return MID_FREQUENCY;
	else // Maybe the status of level is INIT_RESULT
		return HIGH_FREQUENCY ;
}

static void ssd_init_suspend(struct ssd *ssd) {
	int i;

	struct ssdparams *spp = &ssd->sp;
	

	ssd->suspend = g_malloc0(sizeof(struct suspend_time) * spp->tt_pgs);
	for(i = 0; i < spp->tt_pgs; i++) {
		ssd->suspend[i].suspend_gc_time = 0; 
		ssd->suspend[i].current_gc_time = 0;
		ssd->suspend[i].ppa.ppa = UNMAPPED_PPA;
	}
}

/*Initiate the recording parameters*/

static void ssd_init_recording_para(struct ssd *ssd) {
	Error * err = NULL;
    memset(ssd->hmac_key, 1, 16);
	ssd->hmac = qcrypto_hmac_new(QCRYPTO_HASH_ALG_SHA256, (const uint8_t *)ssd->hmac_key, 16, &err);
	g_assert(err == NULL);
	g_assert(ssd->hmac != NULL);
	ssd->current_high_num = 0;
	ssd->current_marked_pg = 0;
	ssd->is_time = true;
	ssd->start_time = 0.0;
	ssd->end_time = 0.0;
	ssd->sus_write_num = 0;
	ssd->push = false;
	ssd->start_lba = 0;
	ssd->block_num = 0;
	ssd->enticing = false;
	ssd->stop = true;
	ssd->rw_total_number = 0;
        ssd->valid_number = 0;
        ssd->cold_rw_num = 0;
        ssd->cold_r_num = 0;
        ssd->cold_w_num = 0;
	ssd->r_number = 0;
	ssd->w_number = 0;
	ssd->r_w_number = 0;
	ssd->r_range = 0;
	ssd->w_range = 0;
	ssd->r_num_window = 0;
	ssd->w_num_window = 0;
        ssd->range_r_num = 0;
        ssd->range_w_num = 0;
	ssd->identified_pg_num = 0;
	ssd->low_num = 0;
	ssd->mid_num = 0;
	ssd->high_num = 0;
	ssd->fine_num = 0;
	ssd->sus_range_num = 0;
}

// Initiate the suspicious ransomware table and immune suspicious ransomware table
static void ssd_init_sus(struct ssd *ssd) {
    int i;
	
    ssd->sustbl = g_malloc0(sizeof(struct suspicious_pg_info) * SUSTBL_SZ);
	ssd->sus_num = 0;
	ssd->immtbl_num = 1;
	ssd->immtbl_list = g_malloc0(sizeof(struct immune_sustbl_list));
	ssd->immtbl_list->next = NULL;

	for(i = 0; i < SUSTBL_SZ; i++) {
        ssd->sustbl[i].ppa.ppa = UNMAPPED_PPA;
        ssd->sustbl[i].lpn = 0;
        ssd->sustbl[i].have_read = 0;
        ssd->sustbl[i].lba = 0;
		ssd->sustbl[i].rw_flag = 2;
	}
}

static void ssd_new_sustbl(struct ssd *ssd){
	int i;
	
    ssd->sustbl = g_malloc0(sizeof(struct suspicious_pg_info) * SUSTBL_SZ);
	ssd->sus_num = 0;
	for(i = 0; i < SUSTBL_SZ; i++) {
        ssd->sustbl[i].ppa.ppa = UNMAPPED_PPA;
        ssd->sustbl[i].lpn = 0;
        ssd->sustbl[i].have_read = 0;
        ssd->sustbl[i].lba = 0;
		ssd->sustbl[i].rw_flag = 2;
	}
}

static void ssd_update_sustbl(struct ssd *ssd, struct suspicious_pg_info sus_info){
	struct immune_sustbl_list *mid_list = ssd->immtbl_list;

	if(ssd->sus_num == SUSTBL_SZ || ssd -> push) {
//		printf("New suspicious table comes!\n");
		if(mid_list->next == NULL) {
			struct immune_sustbl_list *new_l = g_malloc0(sizeof(struct immune_sustbl_list));
			new_l->next = ssd->immtbl_list;
			new_l->tbl_sz = ssd->sus_num;
			new_l->current_tbl = ssd->sustbl;
			new_l->tbl_type = TYPE_SUSTBL;
			new_l->tbl_id = ssd->immtbl_id ++;
			ssd->immtbl_list = new_l;
			ssd->immtbl_num += 1;
		} else {
			while(mid_list->next != NULL) { //insert new immtbl to the end of immutbl_list
				if(mid_list->next->next == NULL) {
					struct immune_sustbl_list *new_l = g_malloc0(sizeof(struct immune_sustbl_list));
					new_l->next = mid_list->next;
					new_l->current_tbl = ssd->sustbl;
					new_l->tbl_sz = ssd->sus_num;
					new_l->tbl_type = TYPE_SUSTBL;
					new_l->tbl_id = ssd->immtbl_id ++;
					mid_list->next = new_l;
					ssd->immtbl_num += 1;
					break;
				} else {
					mid_list = mid_list->next;
				}
			}
		}
		ssd_new_sustbl(ssd);
	}
	if(ssd->push == true)
		return;
	ssd->is_time = false;

	ssd->start_time = get_time();
	assert(ssd->sus_num < SUSTBL_SZ);
//	printf("Sus_num is %"PRIu64"\n", ssd->sus_num);
	ssd->sustbl[ssd->sus_num] = sus_info;
	ssd->sus_num += 1;
//	ssd->suspend[sus_info.lpn].suspend_gc_time = HIGH_FREQUENCY;
//	ssd->suspend[sus_info.lpn].ppa = sus_info.ppa;

}

// Initiate the range table
static void ssd_init_range(struct ssd *ssd) {
    int i;
	
    ssd->range_info = g_malloc0(sizeof(struct suspicious_pg_info) * RW_WINDOW_SIZE);
	ssd->range_num = 0;
	ssd->immtbl_id = 0;

	for(i = 0; i < RW_WINDOW_SIZE; i++) {
        ssd->range_info[i].ppa.ppa = UNMAPPED_PPA;
        ssd->range_info[i].lpn = 0;
        ssd->range_info[i].lba = 0;
		ssd->range_info[i].rw_flag = 2;
	}
}

static void ssd_new_range(struct ssd *ssd){
	int i;
	
    ssd->range_info = g_malloc0(sizeof(struct suspicious_pg_info) * RW_WINDOW_SIZE);
	ssd->range_num = 0;
	for(i = 0; i < RW_WINDOW_SIZE; i++) {
        ssd->range_info[i].ppa.ppa = UNMAPPED_PPA;
        ssd->range_info[i].lpn = 0;
        ssd->range_info[i].lba = 0;
		ssd->range_info[i].rw_flag = 2;
	}
}

static void ssd_update_range(struct ssd *ssd, struct suspicious_pg_info sus_info){
	struct immune_sustbl_list *mid_list = ssd->immtbl_list;

	
//        printf("processing %d, %lf\n", ssd->range_num, (1.0 * ssd->range_r_num)/(ssd->range_w_num + ssd->range_r_num));
	if(ssd->range_num == RW_WINDOW_SIZE || ssd->push) {
          if(((1.0 * ssd->range_r_num)/(ssd->range_w_num + ssd->range_r_num) >= DOWN_PROBABILITY && (1.0 * ssd->range_r_num)/(ssd->range_w_num + ssd->range_r_num) <= UPPER_PROBABILITY) || ssd->push){
			ssd->sus_range_num += 1000;
                        
                        ssd->range_r_num = 0;
                        ssd->range_w_num = 0;

                        //printf("added\n");

			ssd->r_range += ssd->range_r_num;
//		printf("New suspicious table comes!\n");
			if(mid_list->next == NULL) {
				struct immune_sustbl_list *new_l = g_malloc0(sizeof(struct immune_sustbl_list));
				new_l->next = ssd->immtbl_list;
				new_l->current_tbl = ssd->range_info;
				new_l->tbl_sz = ssd->range_num;
				new_l->tbl_type = TYPE_RANGE;
				new_l->tbl_id = ssd->immtbl_id ++;
				ssd->immtbl_list = new_l;
				ssd->immtbl_num += 1;
			} else {
				while(mid_list->next != NULL) { //insert new immtbl to the end of immutbl_list
					if(mid_list->next->next == NULL) {
						struct immune_sustbl_list *new_l = g_malloc0(sizeof(struct immune_sustbl_list));
						new_l->next = mid_list->next;
						new_l->current_tbl = ssd->range_info;
						new_l->tbl_sz = ssd->range_num;
						new_l->tbl_type = TYPE_RANGE;
						new_l->tbl_id = ssd->immtbl_id ++;
						mid_list->next = new_l;
						ssd->immtbl_num += 1;
						break;
					} else {
						mid_list = mid_list->next;
					}
				}
			}
			
			ssd_new_range(ssd);
		} else {
                        ssd->range_r_num = 0;
                        ssd->range_w_num = 0;

			ssd->range_num = 0;
		}
	}
	
	if(ssd->push == true)
		return;
	ssd->is_time = false;
	ssd->start_time = get_time();
	assert(ssd->range_num < RW_WINDOW_SIZE);
//	printf("Sus_num is %"PRIu64"\n", ssd->sus_num);
	ssd->range_info[ssd->range_num] = sus_info;
	ssd->range_num += 1;
        if(sus_info.rw_flag == 0)
          ssd->range_r_num += 1;
        if(sus_info.rw_flag == 1)
          ssd->range_w_num += 1;

}

/////////////////////////////////////
static void ssd_update_freq(struct ssd * ssd, uint64_t lpn, uint8_t rw_flag) {
  struct pg_rd_wr_freq *freq_table = ssd -> freq_table;

  ssd->rw_total_number += 1;
  if(!ssd->stop_train && ssd->start_train) {
  if(rw_flag == 0) {  // read
    if(freq_table[lpn].read_freq == 0)
      ssd->read_page_num ++;
    if(freq_table[lpn].read_freq == 1)
      ssd->read_larger_than_1 ++;
    if(freq_table[lpn].read_freq == 2)
      ssd->read_larger_than_2 ++;
    if(freq_table[lpn].read_freq == 3)
      ssd->read_larger_than_3 ++;


    freq_table[lpn].read_freq += 1;
  }
  if(rw_flag == 1) { // write
    if(freq_table[lpn].write_freq == 0)
      ssd->written_page_num++;
    if(freq_table[lpn].write_freq == 1)
      ssd->update_page_num++;
    if(freq_table[lpn].write_freq == 2)
      ssd->update_larger_than_2++;
    if(freq_table[lpn].write_freq == 3)
      ssd->update_larger_than_3++;

    freq_table[lpn].write_freq += 1;
  }
  }
}

static void ssd_init_rw_freq(struct ssd *ssd) {
    uint64_t i;
    struct ssdparams *spp = &ssd->sp;
    
    ssd->read_page_num = 0;
    ssd->written_page_num == 0;
    ssd->update_page_num == 0;

    ssd->start_train=false;
    ssd->stop_train=false;

    ssd->freq_table = g_malloc0(sizeof(struct pg_rd_wr_freq) * spp->tt_pgs);

    for(i = 0; i < spp->tt_pgs; i++) {
        ssd->freq_table[i].write_freq = 0;
        ssd->freq_table[i].read_freq = 0;
    }
}


static void ssd_init_statbl(struct ssd *ssd) {
	int i;
	struct ssdparams *spp = &ssd->sp;

    ssd->statbl = g_malloc0(sizeof(struct pg_rw_status) * spp->tt_pgs);
    for(i = 0; i < spp->tt_pgs; i++) {
    	ssd->statbl[i].first = 0;
		ssd->statbl[i].second = 0;
        ssd->statbl[i].is_ransom = 0;									
	}
}

static inline struct pg_rw_status get_statbl_ent(struct ssd *ssd, uint64_t lpn) {

	return ssd->statbl[lpn];

}

static inline void update_state(struct ssd *ssd, uint64_t lpn, uint8_t first, uint8_t second, uint8_t is_ransom) {

	ssd->statbl[lpn].first = first;
	ssd->statbl[lpn].second = second;
    ssd->statbl[lpn].is_ransom = is_ransom;
}

/////////////////////////////////////////////////////////////////////////

static inline bool should_gc(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines);
}

static inline bool should_gc_high(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines_high);
}

static inline struct ppa get_maptbl_ent(struct ssd *ssd, uint64_t lpn)
{
    return ssd->maptbl[lpn];
}

static inline void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    assert(lpn < ssd->sp.tt_pgs);
    ssd->maptbl[lpn] = *ppa;
}

static uint64_t ppa2pgidx(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t pgidx;

    pgidx = ppa->g.ch * spp->pgs_per_ch + ppa->g.lun * spp->pgs_per_lun +
        ppa->g.pl * spp->pgs_per_pl + ppa->g.blk * spp->pgs_per_blk + ppa->g.pg;

    assert(pgidx < spp->tt_pgs);

    return pgidx;
}

static inline uint64_t get_rmap_ent(struct ssd *ssd, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    return ssd->rmap[pgidx];
}

/* set rmap[page_no(ppa)] -> lpn */
static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    ssd->rmap[pgidx] = lpn;
}

static int victim_line_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static pqueue_pri_t victim_line_get_pri(void *a)
{
    return ((struct line *)a)->vpc;
}

static void victim_line_set_pri(void *a, pqueue_pri_t pri)
{
    ((struct line *)a)->vpc = pri;
}

static size_t victim_line_get_pos(void *a)
{
    return ((struct line *)a)->pos;
}

static void victim_line_set_pos(void *a, size_t pos)
{
    ((struct line *)a)->pos = pos;
}

static void ssd_init_lines(struct ssd *ssd)
{
    int i;
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *line;

    lm->tt_lines = spp->blks_per_pl;
    assert(lm->tt_lines == spp->tt_lines);
    lm->lines = g_malloc0(sizeof(struct line) * lm->tt_lines);

    QTAILQ_INIT(&lm->free_line_list);
    lm->victim_line_pq = pqueue_init(spp->tt_lines, victim_line_cmp_pri,
            victim_line_get_pri, victim_line_set_pri,
            victim_line_get_pos, victim_line_set_pos);
//    QTAILQ_INIT(&lm->victim_line_list);
    QTAILQ_INIT(&lm->full_line_list);

    lm->free_line_cnt = 0;
    for (i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        line->id = i;
        line->ipc = 0;
        line->vpc = 0;
        /* initialize all the lines as free lines */
        QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
        lm->free_line_cnt++;
    }

    assert(lm->free_line_cnt == lm->tt_lines);
    lm->victim_line_cnt = 0;
    lm->full_line_cnt = 0;
}

static void ssd_init_write_pointer(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;
    /* make sure lines are already initialized by now */
    curline = QTAILQ_FIRST(&lm->free_line_list);
    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;
    /* wpp->curline is always our onging line for writes */
    wpp->curline = curline;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pg = 0;
    wpp->blk = 0;
    wpp->pl = 0;
}

static inline void check_addr(int a, int max)
{
    assert(a >= 0 && a < max);
}

static struct line *get_next_free_line(struct ssd *ssd)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    if (!curline) {
        printf("FEMU-FTL: Error, there is no free lines left in [%s] !!!!\n", ssd->ssdname);
        return NULL;
    }

    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;
    return curline;
}

static void ssd_advance_write_pointer(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;

    check_addr(wpp->ch, spp->nchs);
    wpp->ch++;
    if (wpp->ch == spp->nchs) {
        wpp->ch = 0;
        check_addr(wpp->lun, spp->luns_per_ch);
        wpp->lun++;
        /* in this case, we should go to next lun */
        if (wpp->lun == spp->luns_per_ch) {
            wpp->lun = 0;
            /* go to next page in the block */
            check_addr(wpp->pg, spp->pgs_per_blk);
            wpp->pg++;
            if (wpp->pg == spp->pgs_per_blk) {
                wpp->pg = 0;
                /* move current line to {victim,full} line list */
                if (wpp->curline->vpc == spp->pgs_per_line) {
                    /* all pgs are still valid, move to full line list */
                    assert(wpp->curline->ipc == 0);
                    QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
                    lm->full_line_cnt++;
                } else {
                    assert(wpp->curline->vpc >= 0 && wpp->curline->vpc < spp->pgs_per_line);
                    /* there must be some invalid pages in this line */
                    //printf("Coperd,curline,vpc:%d,ipc:%d\n", wpp->curline->vpc, wpp->curline->ipc);
                    assert(wpp->curline->ipc > 0);
                    pqueue_insert(lm->victim_line_pq, wpp->curline);
                    //QTAILQ_INSERT_TAIL(&lm->victim_line_list, wpp->curline, entry);
                    lm->victim_line_cnt++;
                }
                /* current line is used up, pick another empty line */
                check_addr(wpp->blk, spp->blks_per_pl);
                /* TODO: how should we choose the next block for writes */
                wpp->curline = NULL;
                wpp->curline = get_next_free_line(ssd);
                if (!wpp->curline) {
                    abort();
                }
                wpp->blk = wpp->curline->id;
                check_addr(wpp->blk, spp->blks_per_pl);
                /* make sure we are starting from page 0 in the super block */
                assert(wpp->pg == 0);
                assert(wpp->lun == 0);
                assert(wpp->ch == 0);
                /* TODO: assume # of pl_per_lun is 1, fix later */
                assert(wpp->pl == 0);
            }
        }
    }
    //printf("Next,ch:%d,lun:%d,blk:%d,pg:%d\n", wpp->ch, wpp->lun, wpp->blk, wpp->pg);
}

static struct ppa get_new_page(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct ppa ppa;
    ppa.ppa = 0;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    ppa.g.pl = wpp->pl;
    assert(ppa.g.pl == 0);

    return ppa;
}

static void check_params(struct ssdparams *spp)
{
    /*
     * we are using a general write pointer increment method now, no need to
     * force luns_per_ch and nchs to be power of 2
     */

    //assert(is_power_of_2(spp->luns_per_ch));
    //assert(is_power_of_2(spp->nchs));
}

static void ssd_init_params(struct ssdparams *spp)
{
    spp->secsz = 512;
    spp->secs_per_pg = 8;
    spp->pgs_per_blk = 256;
    spp->blks_per_pl = 4096; /* 16GB */
    spp->pls_per_lun = 1;
    spp->luns_per_ch = 8;
    spp->nchs = 8;

    spp->pg_rd_lat = NAND_READ_LATENCY;
    spp->pg_wr_lat = NAND_PROG_LATENCY;
    spp->blk_er_lat = NAND_ERASE_LATENCY;
    spp->ch_xfer_lat = 0;

    /* calculated values */
    spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
    spp->secs_per_pl = spp->secs_per_blk * spp->blks_per_pl;
    spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
    spp->secs_per_ch = spp->secs_per_lun * spp->luns_per_ch;
    spp->tt_secs = spp->secs_per_ch * spp->nchs;

    spp->pgs_per_pl = spp->pgs_per_blk * spp->blks_per_pl;
    spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
    spp->pgs_per_ch = spp->pgs_per_lun * spp->luns_per_ch;
    spp->tt_pgs = spp->pgs_per_ch * spp->nchs;

    spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun;
    spp->blks_per_ch = spp->blks_per_lun * spp->luns_per_ch;
    spp->tt_blks = spp->blks_per_ch * spp->nchs;

    spp->pls_per_ch =  spp->pls_per_lun * spp->luns_per_ch;
    spp->tt_pls = spp->pls_per_ch * spp->nchs;

    spp->tt_luns = spp->luns_per_ch * spp->nchs;

    /* line is special, put it at the end */
    spp->blks_per_line = spp->tt_luns; /* TODO: to fix under multiplanes */
    spp->pgs_per_line = spp->blks_per_line * spp->pgs_per_blk;
    spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
    spp->tt_lines = spp->blks_per_lun; /* TODO: to fix under multiplanes */

    spp->gc_thres_pcent = 0.6;
    spp->gc_thres_lines = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
    spp->gc_thres_pcent_high = 0.6;
    spp->gc_thres_lines_high = (int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
    spp->enable_gc_delay = true;


    check_params(spp);
}

static void ssd_init_nand_page(struct nand_page *pg, struct ssdparams *spp)
{
    int i;

    pg->nsecs = spp->secs_per_pg;
    pg->sec = g_malloc0(sizeof(nand_sec_status_t) * pg->nsecs);
    for (i = 0; i < pg->nsecs; i++) {
        pg->sec[i] = SEC_FREE;
    }
    pg->status = PG_FREE;
}

static void ssd_init_nand_blk(struct nand_block *blk, struct ssdparams *spp)
{
    int i;

    blk->npgs = spp->pgs_per_blk;
    blk->pg = g_malloc0(sizeof(struct nand_page) * blk->npgs);
    for (i = 0; i < blk->npgs; i++) {
        ssd_init_nand_page(&blk->pg[i], spp);
    }
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt = 0;
    blk->wp = 0;
}

static void ssd_init_nand_plane(struct nand_plane *pl, struct ssdparams *spp)
{
    int i;

    pl->nblks = spp->blks_per_pl;
    pl->blk = g_malloc0(sizeof(struct nand_block) * pl->nblks);
    for (i = 0; i < pl->nblks; i++) {
        ssd_init_nand_blk(&pl->blk[i], spp);
    }
}

static void ssd_init_nand_lun(struct nand_lun *lun, struct ssdparams *spp)
{
    int i;

    lun->npls = spp->pls_per_lun;
    lun->pl = g_malloc0(sizeof(struct nand_plane) * lun->npls);
    for (i = 0; i < lun->npls; i++) {
        ssd_init_nand_plane(&lun->pl[i], spp);
    }
    lun->next_lun_avail_time = 0;
    lun->busy = false;
}

static void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp)
{
    int i;

    ch->nluns = spp->luns_per_ch;
    ch->lun = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
    for (i = 0; i < ch->nluns; i++) {
        ssd_init_nand_lun(&ch->lun[i], spp);
    }
    ch->next_ch_avail_time = 0;
    ch->busy = 0;
}

static void ssd_init_maptbl(struct ssd *ssd)
{
    int i;
    struct ssdparams *spp = &ssd->sp;

    ssd->maptbl = g_malloc0(sizeof(struct ppa) * spp->tt_pgs);
    for (i = 0; i < spp->tt_pgs; i++) {
        ssd->maptbl[i].ppa = UNMAPPED_PPA;
    }
}

static void ssd_init_rmap(struct ssd *ssd)
{
    int i;
    struct ssdparams *spp = &ssd->sp;
    ssd->rmap = g_malloc0(sizeof(uint64_t) * spp->tt_pgs);
    for (i = 0; i < spp->tt_pgs; i++) {
        ssd->rmap[i] = INVALID_LPN;
    }
}

void ssd_init(struct ssd *ssd)
{
    int i;
    struct ssdparams *spp = &ssd->sp;

    assert(ssd);

    ssd->total_copies = 0;

    ssd_init_params(spp);
	
	ssd->fp = fopen(RESULT_READ_RATIO_NAME, "w");
	ssd->fp_hotness = fopen(RESULT_HOTNESS_NAME, "w");
        ssd->fp_valid = fopen(VALID_NAME, "w");

    /* initialize ssd internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (i = 0; i < spp->nchs; i++) {
        ssd_init_ch(&ssd->ch[i], spp);
    }
        /*initialize the page frequency table*/
        ssd_init_rw_freq(ssd);

	/*initialize the result parameters*/
	ssd_init_result(ssd);

	/*Initialize the suspend times for each pages*/
	ssd_init_suspend(ssd);

	/*Initialize the recording parameters*/
	ssd_init_recording_para(ssd);

    /* initialize maptbl */
    ssd_init_maptbl(ssd);

	/*initialize state table for each lpn*/
	ssd_init_statbl(ssd);
	
	/*initialize suspicious ransomware table*/
	ssd_init_sus(ssd);

	/*initialize range table*/
	ssd_init_range(ssd);

    /* initialize rmap */
    ssd_init_rmap(ssd);

    /* initialize all the lines */
    ssd_init_lines(ssd);

    /* initialize write pointer, this is how we allocate new pages for writes */
    ssd_init_write_pointer(ssd);

    qemu_thread_create(&ssd->ftl_thread, "ftl_thread", ftl_thread, ssd,
            QEMU_THREAD_JOINABLE);
}




static inline bool valid_ppa(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    int ch = ppa->g.ch;
    int lun = ppa->g.lun;
    int pl = ppa->g.pl;
    int blk = ppa->g.blk;
    int pg = ppa->g.pg;
    int sec = ppa->g.sec;

    if (ch >= 0 && ch < spp->nchs && lun >= 0 && lun < spp->luns_per_ch &&
            pl >= 0 && pl < spp->pls_per_lun && blk >= 0 &&
            blk < spp->blks_per_pl && pg >= 0 && pg < spp->pgs_per_blk &&
            sec >= 0 && sec < spp->secs_per_pg)
        return true;

    return false;
}

static inline bool valid_lpn(struct ssd *ssd, uint64_t lpn)
{
    return (lpn < ssd->sp.tt_pgs);
}

static inline bool mapped_ppa(struct ppa *ppa)
{
    return !(ppa->ppa == UNMAPPED_PPA);
}

static inline struct ssd_channel *get_ch(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->ch[ppa->g.ch]);
}

static inline struct nand_lun *get_lun(struct ssd *ssd, struct ppa *ppa)
{
    struct ssd_channel *ch = get_ch(ssd, ppa);
    return &(ch->lun[ppa->g.lun]);
}

static inline struct nand_plane *get_pl(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_lun *lun = get_lun(ssd, ppa);
    return &(lun->pl[ppa->g.pl]);
}

static inline struct nand_block *get_blk(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_plane *pl = get_pl(ssd, ppa);
    return &(pl->blk[ppa->g.blk]);
}

static inline struct line *get_line(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->lm.lines[ppa->g.blk]);
}

static inline struct nand_page *get_pg(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = get_blk(ssd, ppa);
    return &(blk->pg[ppa->g.pg]);
}

static uint64_t ssd_advance_status(struct ssd *ssd, struct ppa *ppa,
        struct nand_cmd *ncmd)
{
    int c = ncmd->cmd;
    uint64_t cmd_stime = (ncmd->stime == 0) ? \
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : ncmd->stime;
    uint64_t nand_stime;
    struct ssdparams *spp = &ssd->sp;
    //struct ssd_channel *ch = get_ch(ssd, ppa);
    struct nand_lun *lun = get_lun(ssd, ppa);
    uint64_t lat = 0;

    switch (c) {
    case NAND_READ:
        /* read: perform NAND cmd first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;
        lat = lun->next_lun_avail_time - cmd_stime;
#if 0
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;

        /* read: then data transfer through channel */
        chnl_stime = (ch->next_ch_avail_time < lun->next_lun_avail_time) ? \
            lun->next_lun_avail_time : ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        lat = ch->next_ch_avail_time - cmd_stime;
#endif
        break;

    case NAND_WRITE:
        /* write: transfer data through channel first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        if (ncmd->type == USER_IO) {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        } else {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        }
        lat = lun->next_lun_avail_time - cmd_stime;

#if 0
        chnl_stime = (ch->next_ch_avail_time < cmd_stime) ? cmd_stime : \
                     ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        /* write: then do NAND program */
        nand_stime = (lun->next_lun_avail_time < ch->next_ch_avail_time) ? \
            ch->next_ch_avail_time : lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
#endif
        break;

    case NAND_ERASE:
        /* erase: only need to advance NAND status */

        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->blk_er_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
        break;

    default:
        printf("Unsupported NAND command: 0x%x\n", c);
    }

    return lat;
}

/* update SSD status about one page from PG_VALID -> PG_VALID */
static void mark_page_invalid(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    bool was_full_line = false;
    struct line *line;

    /* update corresponding page status */
    pg = get_pg(ssd, ppa);
    if(pg->status != PG_VALID)
      return;
    pg->status = PG_INVALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    assert(blk->ipc >= 0 && blk->ipc < spp->pgs_per_blk);
    blk->ipc++;
    assert(blk->vpc > 0 && blk->vpc <= spp->pgs_per_blk);
    blk->vpc--;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    assert(line->ipc >= 0 && line->ipc < spp->pgs_per_line);
    if (line->vpc == spp->pgs_per_line) {
        assert(line->ipc == 0);
        was_full_line = true;
    }
    line->ipc++;
    assert(line->vpc > 0 && line->vpc <= spp->pgs_per_line);
    line->vpc--;
    if (was_full_line) {
        /* move line: "full" -> "victim" */
        QTAILQ_REMOVE(&lm->full_line_list, line, entry);
        lm->full_line_cnt--;
        pqueue_insert(lm->victim_line_pq, line);
        //QTAILQ_INSERT_TAIL(&lm->victim_line_list, line, entry);
        lm->victim_line_cnt++;
    }
}

static void update_suspension_after_gc(struct ssd *ssd) {
	int i;
	struct result mid_result;
	struct ssdparams *spp = &ssd->sp;	

	if(ssd->marked_pg > 0) {	
		for(i = 0; i < spp->tt_pgs; i++) {
			if(ssd->suspend[i].suspend_gc_time == 0)
				continue;
			if(ssd->suspend[i].suspend_gc_time > ssd->suspend[i].current_gc_time && valid_ppa(ssd, &ssd->suspend[i].ppa))
				ssd->suspend[i].current_gc_time += 1;
			if(ssd->suspend[i].suspend_gc_time <= ssd->suspend[i].current_gc_time && ssd->suspend[i].suspend_gc_time != 0) {
				ssd->marked_pg -= 1;
				mark_page_invalid(ssd, &ssd->suspend[i].ppa);
				set_rmap_ent(ssd, INVALID_LPN, &ssd->suspend[i].ppa);
				ssd->suspend[i].current_gc_time = 0;
				ssd->suspend[i].suspend_gc_time = 0;
				ssd->suspend[i].ppa.ppa = UNMAPPED_PPA;
				
			}

		}
	}
}


/* update SSD status about one page from PG_FREE -> PG_VALID */
static void mark_page_valid(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;

    /* update page status */
    pg = get_pg(ssd, ppa);
    assert(pg->status == PG_FREE);
    pg->status = PG_VALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    assert(blk->vpc >= 0 && blk->vpc < spp->pgs_per_blk);
    blk->vpc++;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    assert(line->vpc >= 0 && line->vpc < spp->pgs_per_line);
    line->vpc++;
}

/* only for erase, reset one block to free state */
static void mark_block_free(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = get_blk(ssd, ppa);
    struct nand_page *pg = NULL;
    int i;

    for (i = 0; i < spp->pgs_per_blk; i++) {
        /* reset page status */
        pg = &blk->pg[i];
        assert(pg->nsecs == spp->secs_per_pg);
        pg->status = PG_FREE;
    }

    /* reset block status */
    assert(blk->npgs == spp->pgs_per_blk);
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt++;
}

/* assume the read data will staged in DRAM and then flushed back to NAND */
static void gc_read_page(struct ssd *ssd, struct ppa *ppa)
{
    /* advance ssd status, we don't care about how long it takes */
    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcr;
        gcr.type = GC_IO;
        gcr.cmd = NAND_READ;
        gcr.stime = 0;
        ssd_advance_status(ssd, ppa, &gcr);
    }
}

/* move valid page data (already in DRAM) from victim line to a new page */
static uint64_t gc_write_page(struct ssd *ssd, struct ppa *old_ppa)
{
    struct ppa new_ppa;
    //struct ssd_channel *new_ch;
    struct nand_lun *new_lun;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);
    /* first read out current mapping info */
    //set_rmap(ssd, lpn, new_ppa);

    assert(valid_lpn(ssd, lpn));
    new_ppa = get_new_page(ssd);
    /* update maptbl */
    set_maptbl_ent(ssd, lpn, &new_ppa);

    if(ssd->suspend[lpn].ppa.ppa != UNMAPPED_PPA) {
      ssd->suspend[lpn].ppa = new_ppa;
    }

    ssd->total_copies += 1;

    /* update rmap */
    set_rmap_ent(ssd, lpn, &new_ppa);

    //mark_page_invalid(ssd, old_ppa);
    mark_page_valid(ssd, &new_ppa);

    /* need to advance the write pointer here */
    ssd_advance_write_pointer(ssd);

    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcw;
        gcw.type = GC_IO;
        gcw.cmd = NAND_WRITE;
        gcw.stime = 0;
        ssd_advance_status(ssd, &new_ppa, &gcw);
    }

    /* advance per-ch gc_endtime as well */
    //new_ch = get_ch(ssd, &new_ppa);
    //new_ch->gc_endtime = new_ch->next_ch_avail_time;

    new_lun = get_lun(ssd, &new_ppa);
    new_lun->gc_endtime = new_lun->next_lun_avail_time;

    return 0;
}

/* TODO: now O(n) list traversing, optimize it later */
static struct line *select_victim_line(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *victim_line = NULL, *line = NULL;
    int max_ipc = 0;
    //int cnt = 0;

#if 0
    if (QTAILQ_EMPTY(&lm->victim_line_list)) {
        return NULL;
    }

    QTAILQ_FOREACH(line, &lm->victim_line_list, entry) {
        //printf("Coperd,%s,victim_line_list[%d],ipc=%d,vpc=%d\n", __func__, ++cnt, line->ipc, line->vpc);
        if (line->ipc > max_ipc) {
            victim_line = line;
            max_ipc = line->ipc;
        }
    }
#endif

    victim_line = pqueue_peek(lm->victim_line_pq);
    if (!victim_line) {
        return NULL;
    }

    if (!force && victim_line->ipc < ssd->sp.pgs_per_line / 8) {
        //printf("Coperd,select a victim line: ipc=%d (< 1/8)\n", victim_line->ipc);
        return NULL;
    }

    pqueue_pop(lm->victim_line_pq);
//    QTAILQ_REMOVE(&lm->victim_line_list, victim_line, entry);
    lm->victim_line_cnt--;
    //printf("Coperd,%s,victim_line_list,chooose-victim-block,id=%d,ipc=%d,vpc=%d\n", __func__, victim_line->id, victim_line->ipc, victim_line->vpc);

    /* victim_line is a danggling node now */
    return victim_line;
}

/* here ppa identifies the block we want to clean */
static void clean_one_block(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = get_blk(ssd, ppa);
    struct nand_page *pg_iter = NULL;
    int cnt = 0;
    int pg;

    for (pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ssd, ppa);
        /* there shouldn't be any free page in victim blocks */
        assert(pg_iter->status != PG_FREE);
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ssd, ppa);
            /* delay the maptbl update until "write" happens */
            gc_write_page(ssd, ppa);
            cnt++;
        }
    }

    assert(blk->vpc == cnt);
    /* do we do "erase" here? */
}

static void mark_line_free(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *line = get_line(ssd, ppa);
    line->ipc = 0;
    line->vpc = 0;
    /* move this line to free line list */
    QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
    lm->free_line_cnt++;
    //printf("Coperd,%s,one more free line,free_line_cnt=%d\n", __func__, lm->free_line_cnt);
}

static int do_gc(struct ssd *ssd, bool force)
{
    struct line *victim_line = NULL;
    struct ssdparams *spp = &ssd->sp;
    //struct ssd_channel *chp;
    struct nand_lun *lunp;
    struct ppa ppa;
    int ch, lun;

    victim_line = select_victim_line(ssd, force);
    if (!victim_line) {
        ///////printf("FEMU-FTL: failed to get a victim line!\n");
        //abort();
        return -1;
    }

    ppa.g.blk = victim_line->id;
    printf("Coperd,%s,FTL,GCing line:%d,ipc=%d,victim=%d,full=%d,free=%d\n",
            ssd->ssdname, ppa.g.blk, victim_line->ipc, ssd->lm.victim_line_cnt,
            ssd->lm.full_line_cnt, ssd->lm.free_line_cnt);
    /* copy back valid data */
    for (ch = 0; ch < spp->nchs; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            ppa.g.ch = ch;
            ppa.g.lun = lun;
            ppa.g.pl = 0;
            //chp = get_ch(ssd, &ppa);
            lunp = get_lun(ssd, &ppa);
            clean_one_block(ssd, &ppa);
            mark_block_free(ssd, &ppa);

            if (spp->enable_gc_delay) {
                struct nand_cmd gce;
                gce.type = GC_IO;
                gce.cmd = NAND_ERASE;
                gce.stime = 0;
                ssd_advance_status(ssd, &ppa, &gce);
            }

            //chp->gc_endtime = chp->next_ch_avail_time;
            lunp->gc_endtime = lunp->next_lun_avail_time;
        }
    }

    /* update line status */
    mark_line_free(ssd, &ppa);

    return 0;
}

static void *ftl_thread(void *arg)
{
    struct ssd *ssd = (struct ssd *)arg;
    NvmeRequest *req = NULL;
    uint64_t lat = 0;
    int rc;
	struct suspicious_pg_info sus_info;


    while (!*(ssd->dataplane_started_ptr)) {
        usleep(100000);
    }

    while (1) {
		if(ssd->is_result) {
			
			update_suspend_time(ssd);
			ssd_re_init_result(ssd);
//			printf("ratio %lf\n", 1.0 * ssd->current_high_num / ssd->current_marked_pg);
			if(1.0 * ssd->current_high_num / ssd->current_marked_pg > 0.8 || ssd->current_high_num > 10){
				ssd->stop = false;
				printf("Ransomware happened!\n");
			}



			struct immune_sustbl_list *mid_imm = NULL;
			mid_imm = ssd->immtbl_list;
			ssd->immtbl_list = ssd->immtbl_list->next;
			g_free(mid_imm);
			ssd->immtbl_num -= 1;
			if(ssd->immtbl_num == 0)
				ssd->immtbl_list = NULL;
			
			ssd->no_processing = true;
			ssd->is_result = false;
			//assert(ssd->immtbl_num > 0);
//not finish
		}
//		if(ssd->is_time == false) {
			ssd->end_time = get_time();
			if(ssd->end_time - ssd->start_time > 5) {

		//	printf("elpse time: %lf\n", ssd->end_time - ssd->start_time);
				if(ssd->sus_num > 0) {
					ssd->push = true;
					ssd_update_sustbl(ssd, sus_info);
					ssd->push = false;
					ssd->is_time = true;
				}
				if(ssd->range_num > 0){
					if((1.0 * ssd->range_r_num)/(ssd->range_w_num + ssd->range_r_num) > DOWN_PROBABILITY && (1.0 * ssd->range_r_num)/(ssd->range_w_num + ssd->range_r_num) < UPPER_PROBABILITY){
						ssd->push = true;
						ssd_update_range(ssd, sus_info);
						ssd->push = false;
						ssd->is_time = true;
					
					}
				}
				ssd->end_time = 0;
			}
//		}

        if (!ssd->to_ftl || !femu_ring_count(ssd->to_ftl))
            continue;
		
		
        rc = femu_ring_dequeue(ssd->to_ftl, (void *)&req, 1);
        if (rc != 1) {
            printf("FEMU: FTL to_ftl dequeue failed\n");
        }
        assert(req);
        switch (req->is_write) {
            case 1:
                lat = ssd_write(ssd, req);
                break;
            case 0:
                lat = ssd_read(ssd, req);
#if 0
                if (lat >= 20000000) {
                    lat /= 4;
                }
#endif
                break;
            default:
                printf("FEMU: FTL received unkown request type, ERROR\n");
        }

        lat = 0;
        req->reqlat = lat;
        req->expire_time += lat;
		
//		printf("Latency is: %"PRIu64"\n", lat);


        rc = femu_ring_enqueue(ssd->to_poller, (void *)&req, 1);
        if (rc != 1) {
            printf("FEMU: FTL to_poller enqueue failed\n");
        }

        /* clean one line if needed (in the background) */
//        if (should_gc(ssd)) {
//            do_gc(ssd, false);
//			update_suspend_after_gc(ssd);

//        }
    }
}

/* accept NVMe cmd as input, in order to support more command types in future */
uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req)
{
    /* TODO: reads need to go through caching layer first */
    /* ... */


    /* on cache miss, read from NAND */
    struct ssdparams *spp = &ssd->sp;
    uint64_t lba = req->slba; /* sector addr */
    int nsecs = req->nlb;
    struct ppa ppa;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + nsecs) / spp->secs_per_pg;
    uint64_t lpn;
    uint64_t sublat, maxlat = 0;

	struct suspicious_pg_info mid_range_info;
	struct pg_rw_status state;

    //printf("SSD_R, the lba is: %"PRIu64", secs_per_pg is: %d, start_lpn is: %"PRIu64", nsecs is: %d\n", lba, spp->secs_per_pg, start_lpn, nsecs);    

    //struct ssd_channel *ch;
    struct nand_lun *lun;
    bool in_gc = false; /* indicate whether any subIO met GC */

    if (end_lpn >= spp->tt_pgs) {
        printf("RD-ERRRRRRRRRR,start_lpn=%"PRIu64",end_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, end_lpn, ssd->sp.tt_pgs);
    }

    //printf("Coperd,%s,end_lpn=%"PRIu64" (%d),len=%d\n", __func__, end_lpn, spp->tt_pgs, nsecs);
    //assert(end_lpn < spp->tt_pgs);
    /* for list of NAND page reads involved in this external request, do: */

    req->gcrt = 0;
#define NVME_CMD_GCT (911)
    if (req->tifa_cmd_flag == NVME_CMD_GCT) {
        /* fastfail IO path */
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
	    
            		
            ppa = get_maptbl_ent(ssd, lpn);
            if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
                //printf("%s,lpn(%" PRId64 ") not mapped to valid ppa\n", ssd->ssdname, lpn);
                //printf("Invalid ppa,ch:%d,lun:%d,blk:%d,pl:%d,pg:%d,sec:%d\n",
                //ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pl, ppa.g.pg, ppa.g.sec);
                continue;
            }
                        
                        ssd_update_freq(ssd, lpn, 0);


			ssd->r_number += 1;


			ssd->r_num_window += 1;
			mid_range_info.ppa = ppa;
			mid_range_info.lpn = lpn;
			mid_range_info.lba = lpn * spp->secs_per_pg;
			mid_range_info.rw_flag = 0;
                        mid_range_info.have_read = 0;
                        if(ssd->start_train) {
                          //if(ssd->freq_table[lpn].read_freq < HOTNESS_THRESHOLD) { //Cold read
                            ssd->cold_rw_num ++;
                            ssd->cold_r_num ++;
                            ssd->valid_number ++;
                            ssd_update_range(ssd, mid_range_info);
//                            ssd->freq_table[lpn].read_freq ++;
                          //}
                        } 
                        /*else {
                          ssd->valid_number++;
                          ssd_update_range(ssd, mid_range_info);
                        }*/


			if(ssd->w_num_window + ssd->r_num_window == RW_WINDOW_SIZE) {
				//printf("The read percentage is: %lf%\n", (100.0 * ssd->r_num_window)/(ssd->w_num_window + ssd->r_num_window));
			fprintf(ssd->fp, "%.6lf\n", (1.0 * ssd->r_num_window)/(ssd->w_num_window + ssd->r_num_window));
                        fprintf(ssd->fp_valid, "%.6lf\n", (1.0 * ssd->valid_number)/(ssd->w_num_window + ssd->r_num_window));

				ssd->w_num_window = 0;
				ssd->r_num_window = 0;
                                ssd->valid_number = 0;
			}


			/*Ransomware read update*/
			state = get_statbl_ent(ssd, lpn);
			if(state.first == 0) {
				state.first = 1;
				state.second = 0;
				state.is_ransom = 0;
	            update_state(ssd, lpn, state.first, state.second, state.is_ransom);
			}
            //ch = get_ch(ssd, &ppa);
            lun = get_lun(ssd, &ppa);
            if (req->stime < lun->gc_endtime) {
                in_gc = true;
                int tgcrt = lun->gc_endtime - req->stime;
                if (req->gcrt < tgcrt) {
                    req->gcrt = tgcrt;
                }
            } else {
                /* NoGC under fastfail path */
                struct nand_cmd srd;
                srd.type = USER_IO;
                srd.cmd = NAND_READ;
                srd.stime = req->stime;
                sublat = ssd_advance_status(ssd, &ppa, &srd);
                maxlat = (sublat > maxlat) ? sublat : maxlat;
            }
        }

        if (!in_gc) {
            assert(req->gcrt == 0);
            return maxlat;
        }

        assert(req->gcrt > 0);
        if (maxlat > req->gcrt) {
            printf("Coperd,%s,%s,%d,inGC,but qlat(%lu) > gclat(%lu)\n", ssd->ssdname, __func__,
                    __LINE__, maxlat, req->gcrt);
        }
        return 0;
    } else {
        /* normal IO read path */
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
          
            
            ppa = get_maptbl_ent(ssd, lpn);
            if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
                //printf("%s,lpn(%" PRId64 ") not mapped to valid ppa\n", ssd->ssdname, lpn);
                //printf("Invalid ppa,ch:%d,lun:%d,blk:%d,pl:%d,pg:%d,sec:%d\n",
                //ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pl, ppa.g.pg, ppa.g.sec);
                continue;
            }
                        ssd_update_freq(ssd, lpn, 0);

			ssd->r_num_window += 1;

			ssd->r_number += 1;

			mid_range_info.ppa = ppa;
			mid_range_info.lpn = lpn;
			mid_range_info.lba = lpn * spp->secs_per_pg;
			mid_range_info.rw_flag = 0;
                        mid_range_info.have_read = 0;

                        if(ssd->start_train) {
                          //if(ssd->freq_table[lpn].read_freq < HOTNESS_THRESHOLD) { //Cold read
                            ssd->cold_rw_num ++;
                            ssd->cold_r_num ++;

                            ssd->valid_number ++;
                            ssd_update_range(ssd, mid_range_info);
//                            ssd->freq_table[lpn].read_freq ++;
                          //}
                        } 
                        /*else {
                            ssd->valid_number++;
                            ssd_update_range(ssd, mid_range_info);
                        }*/

			if(ssd->w_num_window + ssd->r_num_window == RW_WINDOW_SIZE) {
				//printf("The read percentage is: %lf%\n", (100.0 * ssd->r_num_window)/(ssd->w_num_window + ssd->r_num_window));
				fprintf(ssd->fp, "%.6lf\n", (1.0 * ssd->r_num_window)/(ssd->w_num_window + ssd->r_num_window));
                                fprintf(ssd->fp_valid, "%.6lf\n", (1.0 * ssd->valid_number)/(ssd->w_num_window + ssd->r_num_window));

				ssd->w_num_window = 0;
				ssd->r_num_window = 0;
                                ssd->valid_number = 0;
			}

                        /* Ransomware read update */
			state = get_statbl_ent(ssd, lpn);
			if(state.first == 0) {
				state.first = 1;
				state.second = 0;
				state.is_ransom = 0;
	            update_state(ssd, lpn, state.first, state.second, state.is_ransom);
			}

            struct nand_cmd srd;
            srd.type = USER_IO;
            srd.cmd = NAND_READ;
            srd.stime = req->stime;
            sublat = ssd_advance_status(ssd, &ppa, &srd);
            maxlat = (sublat > maxlat) ? sublat : maxlat;
        }

        /* this is the latency taken by this read request */
        //req->expire_time = maxlat;
        //printf("Coperd,%s,rd,lba:%lu,lat:%lu\n", ssd->ssdname, req->slba, maxlat);
        return maxlat;
    }
}

uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
    uint64_t lba = req->slba;
    struct ssdparams *spp = &ssd->sp;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    struct ppa ppa;
	struct pg_rw_status state;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
	struct suspicious_pg_info mid_range_info;
    int r;

	bool is_gc = true;
    /* TODO: writes need to go to cache first */
    /* ... */
//    printf("SSD_W, the lba is: %"PRIu64", secs_per_pg is: %d, start_lpn is: %"PRIu64", nsecs is: %d\n", lba, spp->secs_per_pg, start_lpn, len);    


    if (end_lpn >= spp->tt_pgs) {
        printf("ERRRRRRRRRR,start_lpn=%"PRIu64",end_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, end_lpn, ssd->sp.tt_pgs);
    }
    //assert(end_lpn < spp->tt_pgs);
    //printf("Coperd,%s,end_lpn=%"PRIu64" (%d),len=%d\n", __func__, end_lpn, spp->tt_pgs, len);

    while (should_gc_high(ssd)) {
        /* perform GC here until !should_gc(ssd) */
        r = do_gc(ssd, true);
		update_suspension_after_gc(ssd);
        if (r == -1)
            break;
        //break;
    }

    /* on cache eviction, write to NAND page */

    // are we doing fresh writes ? maptbl[lpn] == FREE, pick a new page
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        ppa = get_maptbl_ent(ssd, lpn);
		ssd_update_freq(ssd, lpn, 1);

		is_gc = true;
		ssd->w_number += 1;

		ssd->w_num_window += 1;

		mid_range_info.ppa = ppa;
		mid_range_info.lpn = lpn;
		mid_range_info.lba = lpn * spp->secs_per_pg;
		mid_range_info.rw_flag = 1;
                mid_range_info.have_read=0;

                ssd->total_copies += 1;

               if(ssd->start_train) {
                  //if(ssd->freq_table[lpn].write_freq < HOTNESS_THRESHOLD) { //Cold write
                    ssd->cold_rw_num ++;
                    ssd->cold_w_num ++;

                    ssd->valid_number ++;

                    state = get_statbl_ent(ssd, lpn);
                    if(state.first == 1 && state.second == 0) {
			ssd->r_w_number += 1;
			state.first = 0;
			is_gc == false;
			update_state(ssd, lpn, state.first, state.second, state.is_ransom);
			/*struct suspicious_pg_info sus_info;
			sus_info.ppa = ppa;
			sus_info.lpn = lpn;
			sus_info.lba = lpn * spp->secs_per_pg;
			sus_info.rw_flag = 1;*/
                        
			if(ssd->suspend[lpn].suspend_gc_time == 0)
                          ssd->suspend[lpn].suspend_gc_time = TEMP_FREQUENCY;
                        
                        mid_range_info.have_read=1;
			//ssd_update_sustbl(ssd, sus_info);
                    }



                    ssd_update_range(ssd, mid_range_info);
//                    ssd->freq_table[lpn].write_freq ++;
                  //}
                }
               /*else {
                  ssd->valid_number++;
		  ssd_update_range(ssd, mid_range_info);
               }*/
		if(ssd->w_num_window + ssd->r_num_window == RW_WINDOW_SIZE) {
			//printf("The read percentage is: %lf%\n", (100.0 * ssd->r_num_window)/(ssd->w_num_window + ssd->r_num_window));
			fprintf(ssd->fp, "%.6lf\n", (1.0 * ssd->r_num_window)/(ssd->w_num_window + ssd->r_num_window));
                        fprintf(ssd->fp_valid, "%.6lf\n", (1.0 * ssd->valid_number)/(ssd->w_num_window + ssd->r_num_window));

				
			
			ssd->w_num_window = 0;
			ssd->r_num_window = 0;
                        ssd->valid_number = 0;
		}


		/*Ransomware write judgment*/

		if(state.is_ransom == 1 && state.first == 0)
			printf("Error happens in ftl.c line 1273!");

        if (mapped_ppa(&ppa)) {
            /* overwrite */
            /* update old page information first */
            //printf("Coperd,before-overwrite,line[%d],ipc=%d,vpc=%d\n", ppa.g.blk, get_line(ssd, &ppa)->ipc, get_line(ssd, &ppa)->vpc);
            if(mid_range_info.have_read == 1) {
              if(mapped_ppa(&(ssd->suspend[lpn].ppa))) {
                mark_page_invalid(ssd,&(ssd->suspend[lpn].ppa));
                set_rmap_ent(ssd, INVALID_LPN, &(ssd->suspend[lpn].ppa));
              }
              ssd->suspend[lpn].ppa = ppa;
            } else {
              mark_page_invalid(ssd, &ppa);
            //printf("Coperd,after-overwrite,line[%d],ipc=%d,vpc=%d\n", ppa.g.blk, get_line(ssd, &ppa)->ipc, get_line(ssd, &ppa)->vpc);
              set_rmap_ent(ssd, INVALID_LPN, &ppa);
            }
            
        }

        /* new write */
        /* find a new page */
        ppa = get_new_page(ssd);
        /* update maptbl */
        set_maptbl_ent(ssd, lpn, &ppa);
        /* update rmap */
        set_rmap_ent(ssd, lpn, &ppa);

        mark_page_valid(ssd, &ppa);

        /* need to advance the write pointer here */
        ssd_advance_write_pointer(ssd);

        struct nand_cmd swr;
        swr.type = USER_IO;
        swr.cmd = NAND_WRITE;
        swr.stime = req->stime;
        /* get latency statistics */
        curlat = ssd_advance_status(ssd, &ppa, &swr);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
    }

    return maxlat;
}
