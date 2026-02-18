// SPDX-License-Identifier: GPL-2.0-only


#ifndef __ARM64_KVM_PGTABLE_H__
#define __ARM64_KVM_PGTABLE_H__

#include <linux/bits.h>
#include <linux/kvm_host.h>
#include <linux/types.h>

#define KVM_PGTABLE_MAX_LEVELS		4U


#ifdef CONFIG_ARM64_4K_PAGES
#define KVM_PGTABLE_MIN_BLOCK_LEVEL	1U
#else
#define KVM_PGTABLE_MIN_BLOCK_LEVEL	2U
#endif

static inline u64 kvm_get_parange(u64 mmfr0)
{
	u64 parange = cpuid_feature_extract_unsigned_field(mmfr0,
				ID_AA64MMFR0_EL1_PARANGE_SHIFT);
	if (parange > ID_AA64MMFR0_EL1_PARANGE_MAX)
		parange = ID_AA64MMFR0_EL1_PARANGE_MAX;

	return parange;
}

typedef u64 kvm_pte_t;

#define KVM_PTE_VALID			BIT(0)

#define KVM_PTE_ADDR_MASK		GENMASK(47, PAGE_SHIFT)
#define KVM_PTE_ADDR_51_48		GENMASK(15, 12)

#define KVM_PHYS_INVALID		(-1ULL)

#define KVM_PTE_TYPE			BIT(1)
#define KVM_PTE_TYPE_BLOCK		0
#define KVM_PTE_TYPE_PAGE		1
#define KVM_PTE_TYPE_TABLE		1

#define KVM_PTE_LEAF_ATTR_LO		GENMASK(11, 2)

#define KVM_PTE_LEAF_ATTR_LO_S1_ATTRIDX	GENMASK(4, 2)
#define KVM_PTE_LEAF_ATTR_LO_S1_AP	GENMASK(7, 6)
#define KVM_PTE_LEAF_ATTR_LO_S1_AP_RO	3
#define KVM_PTE_LEAF_ATTR_LO_S1_AP_RW	1
#define KVM_PTE_LEAF_ATTR_LO_S1_SH	GENMASK(9, 8)
#define KVM_PTE_LEAF_ATTR_LO_S1_SH_IS	3
#define KVM_PTE_LEAF_ATTR_LO_S1_AF	BIT(10)

#define KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR	GENMASK(5, 2)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R	BIT(6)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W	BIT(7)
#define KVM_PTE_LEAF_ATTR_LO_S2_SH	GENMASK(9, 8)
#define KVM_PTE_LEAF_ATTR_LO_S2_SH_IS	3
#define KVM_PTE_LEAF_ATTR_LO_S2_AF	BIT(10)

#define KVM_PTE_LEAF_ATTR_HI		GENMASK(63, 51)

#define KVM_PTE_LEAF_ATTR_HI_SW		GENMASK(58, 55)

#define KVM_PTE_LEAF_ATTR_HI_S1_XN	BIT(54)

#define KVM_PTE_LEAF_ATTR_HI_S2_XN_PXN	1
#define KVM_PTE_LEAF_ATTR_HI_S2_XN_UXN	3
#define KVM_PTE_LEAF_ATTR_HI_S2_XN_XN	2
#define KVM_PTE_LEAF_ATTR_HI_S2_XN	GENMASK(54, 53)

static inline bool kvm_pte_valid(kvm_pte_t pte)
{
	return pte & KVM_PTE_VALID;
}

static inline u64 kvm_pte_to_phys(kvm_pte_t pte)
{
	u64 pa = pte & KVM_PTE_ADDR_MASK;

	if (PAGE_SHIFT == 16)
		pa |= FIELD_GET(KVM_PTE_ADDR_51_48, pte) << 48;

	return pa;
}

static inline kvm_pte_t kvm_phys_to_pte(u64 pa)
{
	kvm_pte_t pte = pa & KVM_PTE_ADDR_MASK;

	if (PAGE_SHIFT == 16) {
		pa &= GENMASK(51, 48);
		pte |= FIELD_PREP(KVM_PTE_ADDR_51_48, pa >> 48);
	}

	return pte;
}

static inline u64 kvm_granule_shift(u32 level)
{
	
	return ARM64_HW_PGTABLE_LEVEL_SHIFT(level);
}

static inline u64 kvm_granule_size(u32 level)
{
	return BIT(kvm_granule_shift(level));
}

static inline bool kvm_level_supports_block_mapping(u32 level)
{
	return level >= KVM_PGTABLE_MIN_BLOCK_LEVEL;
}

static inline bool kvm_pte_table(kvm_pte_t pte, u32 level)
{
	if (level == KVM_PGTABLE_MAX_LEVELS - 1)
		return false;

	if (!kvm_pte_valid(pte))
		return false;

	return FIELD_GET(KVM_PTE_TYPE, pte) == KVM_PTE_TYPE_TABLE;
}


struct kvm_pgtable_mm_ops {
	void*		(*zalloc_page)(void *arg);
	void*		(*zalloc_pages_exact)(size_t size);
	void		(*free_pages_exact)(void *addr, size_t size);
	void		(*get_page)(void *addr);
	void		(*put_page)(void *addr);
	int		(*page_count)(void *addr);
	void*		(*phys_to_virt)(phys_addr_t phys);
	phys_addr_t	(*virt_to_phys)(void *addr);
	void		(*dcache_clean_inval_poc)(void *addr, size_t size);
	void		(*icache_inval_pou)(void *addr, size_t size);
};

static inline kvm_pte_t *kvm_pte_follow(kvm_pte_t pte, struct kvm_pgtable_mm_ops *mm_ops)
{
	return mm_ops->phys_to_virt(kvm_pte_to_phys(pte));
}


enum kvm_pgtable_stage2_flags {
	KVM_PGTABLE_S2_NOFWB			= BIT(0),
	KVM_PGTABLE_S2_IDMAP			= BIT(1),
};


enum kvm_pgtable_prot {
	KVM_PGTABLE_PROT_X			= BIT(0),
	KVM_PGTABLE_PROT_W			= BIT(1),
	KVM_PGTABLE_PROT_R			= BIT(2),

	KVM_PGTABLE_PROT_DEVICE			= BIT(3),
	KVM_PGTABLE_PROT_NC			= BIT(4),
	KVM_PGTABLE_PROT_PXN			= BIT(5),
	KVM_PGTABLE_PROT_UXN			= BIT(6),

	KVM_PGTABLE_PROT_SW0			= BIT(55),
	KVM_PGTABLE_PROT_SW1			= BIT(56),
	KVM_PGTABLE_PROT_SW2			= BIT(57),
	KVM_PGTABLE_PROT_SW3			= BIT(58),
};

#define KVM_PGTABLE_PROT_RW	(KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W)
#define KVM_PGTABLE_PROT_RWX	(KVM_PGTABLE_PROT_RW | KVM_PGTABLE_PROT_X)

#define PKVM_HOST_MEM_PROT	KVM_PGTABLE_PROT_RWX
#define PKVM_HOST_MMIO_PROT	KVM_PGTABLE_PROT_RW

#define KVM_HOST_S2_DEFAULT_MASK   (KVM_PTE_LEAF_ATTR_HI |	\
				    KVM_PTE_LEAF_ATTR_LO)

#define KVM_HOST_S2_DEFAULT_MEM_PTE		\
	(PTE_S2_MEMATTR(MT_S2_NORMAL) |		\
	KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R |	\
	KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W |	\
	KVM_PTE_LEAF_ATTR_LO_S2_AF |		\
	FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S2_SH, KVM_PTE_LEAF_ATTR_LO_S2_SH_IS))

#define KVM_HOST_S2_DEFAULT_MMIO_PTE		\
	(KVM_HOST_S2_DEFAULT_MEM_PTE |		\
	FIELD_PREP(KVM_PTE_LEAF_ATTR_HI_S2_XN, KVM_PTE_LEAF_ATTR_HI_S2_XN_XN))

#define PAGE_HYP		KVM_PGTABLE_PROT_RW
#define PAGE_HYP_EXEC		(KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_X)
#define PAGE_HYP_RO		(KVM_PGTABLE_PROT_R)
#define PAGE_HYP_DEVICE		(PAGE_HYP | KVM_PGTABLE_PROT_DEVICE)

typedef bool (*kvm_pgtable_force_pte_cb_t)(u64 addr, u64 end,
					   enum kvm_pgtable_prot prot);

typedef bool (*kvm_pgtable_pte_is_counted_cb_t)(kvm_pte_t pte, u32 level);


struct kvm_pgtable_pte_ops {
	kvm_pgtable_force_pte_cb_t		force_pte_cb;
	kvm_pgtable_pte_is_counted_cb_t		pte_is_counted_cb;
};


struct kvm_pgtable {
	u32					ia_bits;
	u32					start_level;
	kvm_pte_t				*pgd;
	struct kvm_pgtable_mm_ops		*mm_ops;

	
	struct kvm_s2_mmu			*mmu;
	enum kvm_pgtable_stage2_flags		flags;
	struct kvm_pgtable_pte_ops		*pte_ops;
};


enum kvm_pgtable_walk_flags {
	KVM_PGTABLE_WALK_LEAF			= BIT(0),
	KVM_PGTABLE_WALK_TABLE_PRE		= BIT(1),
	KVM_PGTABLE_WALK_TABLE_POST		= BIT(2),
};

typedef int (*kvm_pgtable_visitor_fn_t)(u64 addr, u64 end, u32 level,
					kvm_pte_t *ptep,
					enum kvm_pgtable_walk_flags flag,
					void * const arg);


struct kvm_pgtable_walker {
	const kvm_pgtable_visitor_fn_t		cb;
	void * const				arg;
	const enum kvm_pgtable_walk_flags	flags;
};


int kvm_pgtable_hyp_init(struct kvm_pgtable *pgt, u32 va_bits,
			 struct kvm_pgtable_mm_ops *mm_ops);


void kvm_pgtable_hyp_destroy(struct kvm_pgtable *pgt);


int kvm_pgtable_hyp_map(struct kvm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum kvm_pgtable_prot prot);


u64 kvm_pgtable_hyp_unmap(struct kvm_pgtable *pgt, u64 addr, u64 size);


u64 kvm_get_vtcr(u64 mmfr0, u64 mmfr1, u32 phys_shift);


size_t kvm_pgtable_stage2_pgd_size(u64 vtcr);


int __kvm_pgtable_stage2_init(struct kvm_pgtable *pgt, struct kvm_s2_mmu *mmu,
			      struct kvm_pgtable_mm_ops *mm_ops,
			      enum kvm_pgtable_stage2_flags flags,
			      struct kvm_pgtable_pte_ops *pte_ops);

#define kvm_pgtable_stage2_init(pgt, mmu, mm_ops, pte_ops) \
	__kvm_pgtable_stage2_init(pgt, mmu, mm_ops, 0, pte_ops)


void kvm_pgtable_stage2_destroy(struct kvm_pgtable *pgt);


int kvm_pgtable_stage2_map(struct kvm_pgtable *pgt, u64 addr, u64 size,
			   u64 phys, enum kvm_pgtable_prot prot,
			   void *mc);


int kvm_pgtable_stage2_annotate(struct kvm_pgtable *pgt, u64 addr, u64 size,
				void *mc, kvm_pte_t annotation);


int kvm_pgtable_stage2_unmap(struct kvm_pgtable *pgt, u64 addr, u64 size);


int kvm_pgtable_stage2_reclaim_leaves(struct kvm_pgtable *pgt, u64 addr, u64 size);


int kvm_pgtable_stage2_wrprotect(struct kvm_pgtable *pgt, u64 addr, u64 size);


kvm_pte_t kvm_pgtable_stage2_mkyoung(struct kvm_pgtable *pgt, u64 addr);


kvm_pte_t kvm_pgtable_stage2_mkold(struct kvm_pgtable *pgt, u64 addr);


int kvm_pgtable_stage2_relax_perms(struct kvm_pgtable *pgt, u64 addr,
				   enum kvm_pgtable_prot prot);


bool kvm_pgtable_stage2_is_young(struct kvm_pgtable *pgt, u64 addr);


int kvm_pgtable_stage2_flush(struct kvm_pgtable *pgt, u64 addr, u64 size);


int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size,
		     struct kvm_pgtable_walker *walker);


int kvm_pgtable_get_leaf(struct kvm_pgtable *pgt, u64 addr,
			 kvm_pte_t *ptep, u32 *level);


enum kvm_pgtable_prot kvm_pgtable_stage2_pte_prot(kvm_pte_t pte);


enum kvm_pgtable_prot kvm_pgtable_hyp_pte_prot(kvm_pte_t pte);
#endif	
