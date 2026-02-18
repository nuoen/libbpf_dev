/* SPDX-License-Identifier: GPL-2.0-or-later */


#ifndef _LINUX_DELAYACCT_H
#define _LINUX_DELAYACCT_H

#include <uapi/linux/taskstats.h>

#ifdef CONFIG_TASK_DELAY_ACCT
struct task_delay_info {
	raw_spinlock_t	lock;

	

	
	u64 blkio_start;
	u64 blkio_delay;	
	u64 swapin_start;
	u64 swapin_delay;	
	u32 blkio_count;	
				
	u32 swapin_count;	

	u64 freepages_start;
	u64 freepages_delay;	

	u64 thrashing_start;
	u64 thrashing_delay;	

	u64 compact_start;
	u64 compact_delay;	

	u64 wpcopy_start;
	u64 wpcopy_delay;	

	u32 freepages_count;	
	u32 thrashing_count;	
	u32 compact_count;	
	u32 wpcopy_count;	
};
#endif

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/jump_label.h>

#ifdef CONFIG_TASK_DELAY_ACCT
DECLARE_STATIC_KEY_FALSE(delayacct_key);
extern int delayacct_on;	
extern struct kmem_cache *delayacct_cache;
extern void delayacct_init(void);

extern void __delayacct_tsk_init(struct task_struct *);
extern void __delayacct_tsk_exit(struct task_struct *);
extern void __delayacct_blkio_start(void);
extern void __delayacct_blkio_end(struct task_struct *);
extern int delayacct_add_tsk(struct taskstats *, struct task_struct *);
extern __u64 __delayacct_blkio_ticks(struct task_struct *);
extern void __delayacct_freepages_start(void);
extern void __delayacct_freepages_end(void);
extern void __delayacct_thrashing_start(bool *in_thrashing);
extern void __delayacct_thrashing_end(bool *in_thrashing);
extern void __delayacct_swapin_start(void);
extern void __delayacct_swapin_end(void);
extern void __delayacct_compact_start(void);
extern void __delayacct_compact_end(void);
extern void __delayacct_wpcopy_start(void);
extern void __delayacct_wpcopy_end(void);

static inline void delayacct_tsk_init(struct task_struct *tsk)
{
	
	tsk->delays = NULL;
	if (delayacct_on)
		__delayacct_tsk_init(tsk);
}


static inline void delayacct_tsk_free(struct task_struct *tsk)
{
	if (tsk->delays)
		kmem_cache_free(delayacct_cache, tsk->delays);
	tsk->delays = NULL;
}

static inline void delayacct_blkio_start(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_blkio_start();
}

static inline void delayacct_blkio_end(struct task_struct *p)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (p->delays)
		__delayacct_blkio_end(p);
}

static inline __u64 delayacct_blkio_ticks(struct task_struct *tsk)
{
	if (tsk->delays)
		return __delayacct_blkio_ticks(tsk);
	return 0;
}

static inline void delayacct_freepages_start(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_freepages_start();
}

static inline void delayacct_freepages_end(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_freepages_end();
}

static inline void delayacct_thrashing_start(bool *in_thrashing)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_thrashing_start(in_thrashing);
}

static inline void delayacct_thrashing_end(bool *in_thrashing)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_thrashing_end(in_thrashing);
}

static inline void delayacct_swapin_start(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_swapin_start();
}

static inline void delayacct_swapin_end(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_swapin_end();
}

static inline void delayacct_compact_start(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_compact_start();
}

static inline void delayacct_compact_end(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_compact_end();
}

static inline void delayacct_wpcopy_start(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_wpcopy_start();
}

static inline void delayacct_wpcopy_end(void)
{
	if (!static_branch_unlikely(&delayacct_key))
		return;

	if (current->delays)
		__delayacct_wpcopy_end();
}

#else
extern void _trace_android_rvh_delayacct_init(void);
extern void _trace_android_rvh_delayacct_tsk_init(struct task_struct *tsk);
extern void _trace_android_rvh_delayacct_tsk_free(struct task_struct *tsk);
extern void _trace_android_vh_delayacct_blkio_start(void);
extern void _trace_android_vh_delayacct_blkio_end(struct task_struct *p);
extern void _trace_android_vh_delayacct_add_tsk(struct taskstats *d,
						struct task_struct *tsk,
						int *ret);
extern void _trace_android_vh_delayacct_blkio_ticks(struct task_struct *tsk, __u64 *ret);
extern void _trace_android_vh_delayacct_freepages_start(void);
extern void _trace_android_vh_delayacct_freepages_end(void);
extern void _trace_android_vh_delayacct_thrashing_start(bool *in_thrashing);
extern void _trace_android_vh_delayacct_thrashing_end(bool *in_thrashing);
extern void _trace_android_vh_delayacct_swapin_start(void);
extern void _trace_android_vh_delayacct_swapin_end(void);
extern void _trace_android_vh_delayacct_compact_start(void);
extern void _trace_android_vh_delayacct_compact_end(void);
extern void _trace_android_vh_delayacct_wpcopy_start(void);
extern void _trace_android_vh_delayacct_wpcopy_end(void);
extern void set_delayacct_enabled(bool enabled);
extern bool get_delayacct_enabled(void);

static inline void delayacct_init(void)
{
	if (get_delayacct_enabled())
		_trace_android_rvh_delayacct_init();
}

static inline void delayacct_tsk_init(struct task_struct *tsk)
{
	if (get_delayacct_enabled())
		_trace_android_rvh_delayacct_tsk_init(tsk);
}

static inline void delayacct_tsk_free(struct task_struct *tsk)
{
	if (get_delayacct_enabled())
		_trace_android_rvh_delayacct_tsk_free(tsk);
}

static inline void delayacct_blkio_start(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_blkio_start();
}

static inline void delayacct_blkio_end(struct task_struct *p)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_blkio_end(p);
}

static inline int delayacct_add_tsk(struct taskstats *d,
					struct task_struct *tsk)
{
	int ret = 0;

	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_add_tsk(d, tsk, &ret);

	return ret;
}

static inline __u64 delayacct_blkio_ticks(struct task_struct *tsk)
{
	__u64 ret = 0;

	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_blkio_ticks(tsk, &ret);

	return ret;
}

static inline int delayacct_is_task_waiting_on_io(struct task_struct *p)
{ return 0; }

static inline void delayacct_freepages_start(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_freepages_start();
}

static inline void delayacct_freepages_end(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_freepages_end();
}

static inline void delayacct_thrashing_start(bool *in_thrashing)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_thrashing_start(in_thrashing);
}

static inline void delayacct_thrashing_end(bool *in_thrashing)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_thrashing_end(in_thrashing);
}

static inline void delayacct_swapin_start(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_swapin_start();
}

static inline void delayacct_swapin_end(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_swapin_end();
}

static inline void delayacct_compact_start(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_compact_start();
}

static inline void delayacct_compact_end(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_compact_end();
}

static inline void delayacct_wpcopy_start(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_wpcopy_start();
}

static inline void delayacct_wpcopy_end(void)
{
	if (get_delayacct_enabled())
		_trace_android_vh_delayacct_wpcopy_end();
}

#endif 

#endif
