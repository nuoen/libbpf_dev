/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_TLBFLUSH_H
#define __ASM_TLBFLUSH_H

#ifndef __ASSEMBLY__

#include <linux/bitfield.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <asm/cputype.h>
#include <asm/mmu.h>


#define __TLBI_0(op, arg) asm (ARM64_ASM_PREAMBLE			       \
			       "tlbi " #op "\n"				       \
		   ALTERNATIVE("nop\n			nop",		       \
			       "dsb ish\n		tlbi " #op,	       \
			       ARM64_WORKAROUND_REPEAT_TLBI,		       \
			       CONFIG_ARM64_WORKAROUND_REPEAT_TLBI)	       \
			    : : )

#define __TLBI_1(op, arg) asm (ARM64_ASM_PREAMBLE			       \
			       "tlbi " #op ", %0\n"			       \
		   ALTERNATIVE("nop\n			nop",		       \
			       "dsb ish\n		tlbi " #op ", %0",     \
			       ARM64_WORKAROUND_REPEAT_TLBI,		       \
			       CONFIG_ARM64_WORKAROUND_REPEAT_TLBI)	       \
			    : : "r" (arg))

#define __TLBI_N(op, arg, n, ...) __TLBI_##n(op, arg)

#define __tlbi(op, ...)		__TLBI_N(op, ##__VA_ARGS__, 1, 0)

#define __tlbi_user(op, arg) do {						\
	if (arm64_kernel_unmapped_at_el0())					\
		__tlbi(op, (arg) | USER_ASID_FLAG);				\
} while (0)


#define __TLBI_VADDR(addr, asid)				\
	({							\
		unsigned long __ta = (addr) >> 12;		\
		__ta &= GENMASK_ULL(43, 0);			\
		__ta |= (unsigned long)(asid) << 48;		\
		__ta;						\
	})


#define TLBI_TTL_TG_4K		1
#define TLBI_TTL_TG_16K		2
#define TLBI_TTL_TG_64K		3

static inline unsigned long get_trans_granule(void)
{
	switch (PAGE_SIZE) {
	case SZ_4K:
		return TLBI_TTL_TG_4K;
	case SZ_16K:
		return TLBI_TTL_TG_16K;
	case SZ_64K:
		return TLBI_TTL_TG_64K;
	default:
		return 0;
	}
}


#define TLBI_TTL_MASK		GENMASK_ULL(47, 44)

#define __tlbi_level(op, addr, level) do {				\
	u64 arg = addr;							\
									\
	if (cpus_have_const_cap(ARM64_HAS_ARMv8_4_TTL) &&		\
	    level) {							\
		u64 ttl = level & 3;					\
		ttl |= get_trans_granule() << 2;			\
		arg &= ~TLBI_TTL_MASK;					\
		arg |= FIELD_PREP(TLBI_TTL_MASK, ttl);			\
	}								\
									\
	__tlbi(op, arg);						\
} while(0)

#define __tlbi_user_level(op, arg, level) do {				\
	if (arm64_kernel_unmapped_at_el0())				\
		__tlbi_level(op, (arg | USER_ASID_FLAG), level);	\
} while (0)


#define __TLBI_VADDR_RANGE(addr, asid, scale, num, ttl)		\
	({							\
		unsigned long __ta = (addr) >> PAGE_SHIFT;	\
		__ta &= GENMASK_ULL(36, 0);			\
		__ta |= (unsigned long)(ttl) << 37;		\
		__ta |= (unsigned long)(num) << 39;		\
		__ta |= (unsigned long)(scale) << 44;		\
		__ta |= get_trans_granule() << 46;		\
		__ta |= (unsigned long)(asid) << 48;		\
		__ta;						\
	})


#define __TLBI_RANGE_PAGES(num, scale)	\
	((unsigned long)((num) + 1) << (5 * (scale) + 1))
#define MAX_TLBI_RANGE_PAGES		__TLBI_RANGE_PAGES(31, 3)


#define TLBI_RANGE_MASK			GENMASK_ULL(4, 0)
#define __TLBI_RANGE_NUM(pages, scale)	\
	((((pages) >> (5 * (scale) + 1)) & TLBI_RANGE_MASK) - 1)


static inline void local_flush_tlb_all(void)
{
	dsb(nshst);
	__tlbi(vmalle1);
	dsb(nsh);
	isb();
}

static inline void flush_tlb_all(void)
{
	dsb(ishst);
	__tlbi(vmalle1is);
	dsb(ish);
	isb();
}

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	unsigned long asid;

	dsb(ishst);
	asid = __TLBI_VADDR(0, ASID(mm));
	__tlbi(aside1is, asid);
	__tlbi_user(aside1is, asid);
	dsb(ish);
}

static inline void flush_tlb_page_nosync(struct vm_area_struct *vma,
					 unsigned long uaddr)
{
	unsigned long addr;

	dsb(ishst);
	addr = __TLBI_VADDR(uaddr, ASID(vma->vm_mm));
	__tlbi(vale1is, addr);
	__tlbi_user(vale1is, addr);
}

static inline void flush_tlb_page(struct vm_area_struct *vma,
				  unsigned long uaddr)
{
	flush_tlb_page_nosync(vma, uaddr);
	dsb(ish);
}


#define MAX_TLBI_OPS	PTRS_PER_PTE

static inline void __flush_tlb_range(struct vm_area_struct *vma,
				     unsigned long start, unsigned long end,
				     unsigned long stride, bool last_level,
				     int tlb_level)
{
	int num = 0;
	int scale = 0;
	unsigned long asid, addr, pages;

	start = round_down(start, stride);
	end = round_up(end, stride);
	pages = (end - start) >> PAGE_SHIFT;

	
	if ((!system_supports_tlb_range() &&
	     (end - start) >= (MAX_TLBI_OPS * stride)) ||
	    pages >= MAX_TLBI_RANGE_PAGES) {
		flush_tlb_mm(vma->vm_mm);
		return;
	}

	dsb(ishst);
	asid = ASID(vma->vm_mm);

	
	while (pages > 0) {
		if (!system_supports_tlb_range() ||
		    pages % 2 == 1) {
			addr = __TLBI_VADDR(start, asid);
			if (last_level) {
				__tlbi_level(vale1is, addr, tlb_level);
				__tlbi_user_level(vale1is, addr, tlb_level);
			} else {
				__tlbi_level(vae1is, addr, tlb_level);
				__tlbi_user_level(vae1is, addr, tlb_level);
			}
			start += stride;
			pages -= stride >> PAGE_SHIFT;
			continue;
		}

		num = __TLBI_RANGE_NUM(pages, scale);
		if (num >= 0) {
			addr = __TLBI_VADDR_RANGE(start, asid, scale,
						  num, tlb_level);
			if (last_level) {
				__tlbi(rvale1is, addr);
				__tlbi_user(rvale1is, addr);
			} else {
				__tlbi(rvae1is, addr);
				__tlbi_user(rvae1is, addr);
			}
			start += __TLBI_RANGE_PAGES(num, scale) << PAGE_SHIFT;
			pages -= __TLBI_RANGE_PAGES(num, scale);
		}
		scale++;
	}
	dsb(ish);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	
	__flush_tlb_range(vma, start, end, PAGE_SIZE, false, 0);
}

static inline void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	unsigned long addr;

	if ((end - start) > (MAX_TLBI_OPS * PAGE_SIZE)) {
		flush_tlb_all();
		return;
	}

	start = __TLBI_VADDR(start, 0);
	end = __TLBI_VADDR(end, 0);

	dsb(ishst);
	for (addr = start; addr < end; addr += 1 << (PAGE_SHIFT - 12))
		__tlbi(vaale1is, addr);
	dsb(ish);
	isb();
}


static inline void __flush_tlb_kernel_pgtable(unsigned long kaddr)
{
	unsigned long addr = __TLBI_VADDR(kaddr, 0);

	dsb(ishst);
	__tlbi(vaae1is, addr);
	dsb(ish);
	isb();
}
#endif

#endif
