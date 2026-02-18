/* SPDX-License-Identifier: GPL-2.0-only */


#ifndef __ARM64_KVM_HOST_H__
#define __ARM64_KVM_HOST_H__

#include <linux/arm-smccc.h>
#include <linux/bitmap.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <linux/kvm_types.h>
#include <linux/percpu.h>
#include <linux/psci.h>
#include <asm/arch_gicv3.h>
#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/cputype.h>
#include <asm/daifflags.h>
#include <asm/fpsimd.h>
#include <asm/kvm.h>
#include <asm/kvm_asm.h>

#define __KVM_HAVE_ARCH_INTC_INITIALIZED

#define KVM_HALT_POLL_NS_DEFAULT 500000

#include <kvm/arm_vgic.h>
#include <kvm/arm_arch_timer.h>
#include <kvm/arm_pmu.h>

#define KVM_MAX_VCPUS VGIC_V3_MAX_CPUS

#define KVM_VCPU_MAX_FEATURES 7

#define KVM_REQ_SLEEP \
	KVM_ARCH_REQ_FLAGS(0, KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_IRQ_PENDING	KVM_ARCH_REQ(1)
#define KVM_REQ_VCPU_RESET	KVM_ARCH_REQ(2)
#define KVM_REQ_RECORD_STEAL	KVM_ARCH_REQ(3)
#define KVM_REQ_RELOAD_GICv4	KVM_ARCH_REQ(4)
#define KVM_REQ_RELOAD_PMU	KVM_ARCH_REQ(5)
#define KVM_REQ_SUSPEND		KVM_ARCH_REQ(6)

#define KVM_DIRTY_LOG_MANUAL_CAPS   (KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE | \
				     KVM_DIRTY_LOG_INITIALLY_SET)

#define KVM_HAVE_MMU_RWLOCK


enum kvm_mode {
	KVM_MODE_DEFAULT,
	KVM_MODE_PROTECTED,
	KVM_MODE_NONE,
};
enum kvm_mode kvm_get_mode(void);

DECLARE_STATIC_KEY_FALSE(userspace_irqchip_in_use);

extern unsigned int kvm_sve_max_vl;
extern unsigned int kvm_host_sve_max_vl;
int kvm_arm_init_sve(void);

u32 __attribute_const__ kvm_target_cpu(void);
int kvm_reset_vcpu(struct kvm_vcpu *vcpu);
void kvm_arm_vcpu_destroy(struct kvm_vcpu *vcpu);

struct kvm_hyp_memcache {
	phys_addr_t head;
	unsigned long nr_pages;
};

static inline void push_hyp_memcache(struct kvm_hyp_memcache *mc,
				     phys_addr_t *p,
				     phys_addr_t (*to_pa)(void *virt))
{
	*p = mc->head;
	mc->head = to_pa(p);
	mc->nr_pages++;
}

static inline void *pop_hyp_memcache(struct kvm_hyp_memcache *mc,
				     void *(*to_va)(phys_addr_t phys))
{
	phys_addr_t *p = to_va(mc->head);

	if (!mc->nr_pages)
		return NULL;

	mc->head = *p;
	mc->nr_pages--;

	return p;
}

static inline int __topup_hyp_memcache(struct kvm_hyp_memcache *mc,
				       unsigned long min_pages,
				       void *(*alloc_fn)(void *arg),
				       phys_addr_t (*to_pa)(void *virt),
				       void *arg)
{
	while (mc->nr_pages < min_pages) {
		phys_addr_t *p = alloc_fn(arg);

		if (!p)
			return -ENOMEM;
		push_hyp_memcache(mc, p, to_pa);
	}

	return 0;
}

static inline void __free_hyp_memcache(struct kvm_hyp_memcache *mc,
				       void (*free_fn)(void *virt, void *arg),
				       void *(*to_va)(phys_addr_t phys),
				       void *arg)
{
	while (mc->nr_pages)
		free_fn(pop_hyp_memcache(mc, to_va), arg);
}

void free_hyp_memcache(struct kvm_hyp_memcache *mc, struct kvm *kvm);
void free_hyp_stage2_memcache(struct kvm_hyp_memcache *mc, struct kvm *kvm);
int topup_hyp_memcache(struct kvm_vcpu *vcpu);

struct kvm_vmid {
	atomic64_t id;
};

struct kvm_s2_mmu {
	struct kvm_vmid vmid;

	
	phys_addr_t	pgd_phys;
	struct kvm_pgtable *pgt;

	
	int __percpu *last_vcpu_ran;

	struct kvm_arch *arch;
};

struct kvm_arch_memory_slot {
};


struct kvm_smccc_features {
	unsigned long std_bmap;
	unsigned long std_hyp_bmap;
	unsigned long vendor_hyp_bmap;
};

struct kvm_pinned_page {
	struct rb_node		node;
	struct page		*page;
	u64			ipa;
};

typedef unsigned int pkvm_handle_t;

struct kvm_protected_vm {
	pkvm_handle_t handle;
	struct kvm_hyp_memcache teardown_mc;
	struct kvm_hyp_memcache teardown_stage2_mc;
	struct rb_root pinned_pages;
	gpa_t pvmfw_load_addr;
	bool enabled;
};

struct kvm_arch {
	struct kvm_s2_mmu mmu;

	
	u64    vtcr;

	
	struct vgic_dist	vgic;

	
	u32 psci_version;

#ifndef __GENKSYMS__
	
	struct mutex config_lock;
#endif

	
#define KVM_ARCH_FLAG_RETURN_NISV_IO_ABORT_TO_USER	0
	
#define KVM_ARCH_FLAG_MTE_ENABLED			1
	
#define KVM_ARCH_FLAG_HAS_RAN_ONCE			2
	
#define KVM_ARCH_FLAG_REG_WIDTH_CONFIGURED		3
#define KVM_ARCH_FLAG_EL1_32BIT				4
	
#define KVM_ARCH_FLAG_SYSTEM_SUSPEND_ENABLED		5
	
#define KVM_ARCH_FLAG_MMIO_GUARD			6
	unsigned long flags;

	
	unsigned long *pmu_filter;
	struct arm_pmu *arm_pmu;

	cpumask_var_t supported_cpus;

	u8 pfr0_csv2;
	u8 pfr0_csv3;

	
	struct kvm_smccc_features smccc_feat;

	
	struct kvm_protected_vm pkvm;
};

struct kvm_vcpu_fault_info {
	u64 esr_el2;		
	u64 far_el2;		
	u64 hpfar_el2;		
	u64 disr_el1;		
};

enum vcpu_sysreg {
	__INVALID_SYSREG__,   
	MPIDR_EL1,	
	CSSELR_EL1,	
	SCTLR_EL1,	
	ACTLR_EL1,	
	CPACR_EL1,	
	ZCR_EL1,	
	TTBR0_EL1,	
	TTBR1_EL1,	
	TCR_EL1,	
	ESR_EL1,	
	AFSR0_EL1,	
	AFSR1_EL1,	
	FAR_EL1,	
	MAIR_EL1,	
	VBAR_EL1,	
	CONTEXTIDR_EL1,	
	TPIDR_EL0,	
	TPIDRRO_EL0,	
	TPIDR_EL1,	
	AMAIR_EL1,	
	CNTKCTL_EL1,	
	PAR_EL1,	
	MDSCR_EL1,	
	MDCCINT_EL1,	
	OSLSR_EL1,	
	DISR_EL1,	

	
	PMCR_EL0,	
	PMSELR_EL0,	
	PMEVCNTR0_EL0,	
	PMEVCNTR30_EL0 = PMEVCNTR0_EL0 + 30,
	PMCCNTR_EL0,	
	PMEVTYPER0_EL0,	
	PMEVTYPER30_EL0 = PMEVTYPER0_EL0 + 30,
	PMCCFILTR_EL0,	
	PMCNTENSET_EL0,	
	PMINTENSET_EL1,	
	PMOVSSET_EL0,	
	PMUSERENR_EL0,	

	
	APIAKEYLO_EL1,
	APIAKEYHI_EL1,
	APIBKEYLO_EL1,
	APIBKEYHI_EL1,
	APDAKEYLO_EL1,
	APDAKEYHI_EL1,
	APDBKEYLO_EL1,
	APDBKEYHI_EL1,
	APGAKEYLO_EL1,
	APGAKEYHI_EL1,

	ELR_EL1,
	SP_EL1,
	SPSR_EL1,

	CNTVOFF_EL2,
	CNTV_CVAL_EL0,
	CNTV_CTL_EL0,
	CNTP_CVAL_EL0,
	CNTP_CTL_EL0,

	
	RGSR_EL1,	
	GCR_EL1,	
	TFSR_EL1,	
	TFSRE0_EL1,	

	
	DACR32_EL2,	
	IFSR32_EL2,	
	FPEXC32_EL2,	
	DBGVCR32_EL2,	

	NR_SYS_REGS	
};

struct kvm_cpu_context {
	struct user_pt_regs regs;	

	u64	spsr_abt;
	u64	spsr_und;
	u64	spsr_irq;
	u64	spsr_fiq;

	struct user_fpsimd_state fp_regs;

	u64 sys_regs[NR_SYS_REGS];

#ifdef __GENKSYMS__
	struct kvm_vcpu *__hyp_running_vcpu;
#else
	void *__hyp_running_vcpu;
#endif
};

struct kvm_host_data {
	struct kvm_cpu_context host_ctxt;
};

struct kvm_host_psci_config {
	
	u32 version;
	u32 smccc_version;

	
	struct psci_0_1_function_ids function_ids_0_1;

	bool psci_0_1_cpu_suspend_implemented;
	bool psci_0_1_cpu_on_implemented;
	bool psci_0_1_cpu_off_implemented;
	bool psci_0_1_migrate_implemented;
};

extern struct kvm_host_psci_config kvm_nvhe_sym(kvm_host_psci_config);
#define kvm_host_psci_config CHOOSE_NVHE_SYM(kvm_host_psci_config)

extern s64 kvm_nvhe_sym(hyp_physvirt_offset);
#define hyp_physvirt_offset CHOOSE_NVHE_SYM(hyp_physvirt_offset)

extern u64 kvm_nvhe_sym(hyp_cpu_logical_map)[NR_CPUS];
#define hyp_cpu_logical_map CHOOSE_NVHE_SYM(hyp_cpu_logical_map)

enum pkvm_iommu_pm_event {
	PKVM_IOMMU_PM_SUSPEND,
	PKVM_IOMMU_PM_RESUME,
};

struct pkvm_iommu_ops;

struct pkvm_iommu_driver {
	const struct pkvm_iommu_ops *ops;
	struct list_head list;
	atomic_t state;
};

int pkvm_iommu_driver_init(u64 drv, void *data, size_t size);
int pkvm_iommu_register(struct device *dev, u64 drv, phys_addr_t pa,
			size_t size, struct device *parent, u8 flags);
int pkvm_iommu_suspend(struct device *dev);
int pkvm_iommu_resume(struct device *dev);


int pkvm_iommu_finalize(int err);

bool pkvm_iommu_finalized(void);

struct vcpu_reset_state {
	unsigned long	pc;
	unsigned long	r0;
	bool		be;
	bool		reset;
};

struct kvm_vcpu_arch {
	struct kvm_cpu_context ctxt;

	
	void *sve_state;
	unsigned int sve_max_vl;
	u64 svcr;

	
	struct kvm_s2_mmu *hw_mmu;

	
	u64 hcr_el2;
	u64 mdcr_el2;
	u64 cptr_el2;

	
	u64 mdcr_el2_host;

	
	struct kvm_vcpu_fault_info fault;

	
	enum {
		FP_STATE_FREE,
		FP_STATE_HOST_OWNED,
		FP_STATE_GUEST_OWNED,
	} fp_state;

	
	u8 cflags;

	
	u8 iflags;

	
	u8 sflags;

	
	bool pause;

	
	struct kvm_guest_debug_arch *debug_ptr;
	struct kvm_guest_debug_arch vcpu_debug_state;
	struct kvm_guest_debug_arch external_debug_state;

	struct user_fpsimd_state *host_fpsimd_state;	

	struct {
		
		struct kvm_guest_debug_arch regs;
		
		u64 pmscr_el1;
		
		u64 trfcr_el1;
	} host_debug_state;

	
	struct vgic_cpu vgic_cpu;
	struct arch_timer_cpu timer_cpu;
	struct kvm_pmu pmu;

	
	struct {
		u32	mdscr_el1;
		bool	pstate_ss;
	} guest_debug_preserved;

	
	struct kvm_mp_state mp_state;
#ifndef __GENKSYMS__
	spinlock_t mp_state_lock;
#endif

	union {
		
		struct kvm_mmu_memory_cache mmu_page_cache;
		
		struct kvm_hyp_memcache pkvm_memcache;
	};

	
	int target;
	DECLARE_BITMAP(features, KVM_VCPU_MAX_FEATURES);

	
	u64 vsesr_el2;

	
	struct vcpu_reset_state	reset_state;

	
	struct {
		u64 last_steal;
		gpa_t base;
	} steal;
};


#define __vcpu_single_flag(_set, _f)	_set, (_f), (_f)

#define __unpack_flag(_set, _f, _m)	_f
#define unpack_vcpu_flag(...)		__unpack_flag(__VA_ARGS__)

#define __build_check_flag(v, flagset, f, m)			\
	do {							\
		typeof(v->arch.flagset) *_fset;			\
								\
			\
		BUILD_BUG_ON(HWEIGHT(m) != HWEIGHT((f) | (m)));	\
			\
		BUILD_BUG_ON((sizeof(*_fset) * 8) <= __fls(m));	\
	} while (0)

#define __vcpu_get_flag(v, flagset, f, m)			\
	({							\
		__build_check_flag(v, flagset, f, m);		\
								\
		READ_ONCE(v->arch.flagset) & (m);		\
	})


#ifdef __KVM_NVHE_HYPERVISOR__

#define __vcpu_flags_preempt_disable()
#define __vcpu_flags_preempt_enable()
#else
#define __vcpu_flags_preempt_disable()	preempt_disable()
#define __vcpu_flags_preempt_enable()	preempt_enable()
#endif

#define __vcpu_set_flag(v, flagset, f, m)			\
	do {							\
		typeof(v->arch.flagset) *fset;			\
								\
		__build_check_flag(v, flagset, f, m);		\
								\
		fset = &v->arch.flagset;			\
		__vcpu_flags_preempt_disable();			\
		if (HWEIGHT(m) > 1)				\
			*fset &= ~(m);				\
		*fset |= (f);					\
		__vcpu_flags_preempt_enable();			\
	} while (0)

#define __vcpu_clear_flag(v, flagset, f, m)			\
	do {							\
		typeof(v->arch.flagset) *fset;			\
								\
		__build_check_flag(v, flagset, f, m);		\
								\
		fset = &v->arch.flagset;			\
		__vcpu_flags_preempt_disable();			\
		*fset &= ~(m);					\
		__vcpu_flags_preempt_enable();			\
	} while (0)

#define __vcpu_copy_flag(vt, vs, flagset, f, m)			\
	do {							\
		typeof(vs->arch.flagset) tmp, val;		\
								\
		__build_check_flag(vs, flagset, f, m);		\
								\
		__vcpu_flags_preempt_disable();			\
		val = READ_ONCE(vs->arch.flagset);		\
		val &= (m);					\
		tmp = READ_ONCE(vt->arch.flagset);		\
		tmp &= ~(m);					\
		tmp |= val;					\
		WRITE_ONCE(vt->arch.flagset, tmp);		\
		__vcpu_flags_preempt_enable();			\
	} while (0)


#define vcpu_get_flag(v, ...)	__vcpu_get_flag((v), __VA_ARGS__)
#define vcpu_set_flag(v, ...)	__vcpu_set_flag((v), __VA_ARGS__)
#define vcpu_clear_flag(v, ...)	__vcpu_clear_flag((v), __VA_ARGS__)
#define vcpu_copy_flag(vt, vs,...) __vcpu_copy_flag((vt), (vs), __VA_ARGS__)


#define GUEST_HAS_SVE		__vcpu_single_flag(cflags, BIT(0))

#define VCPU_SVE_FINALIZED	__vcpu_single_flag(cflags, BIT(1))

#define GUEST_HAS_PTRAUTH	__vcpu_single_flag(cflags, BIT(2))


#define PENDING_EXCEPTION	__vcpu_single_flag(iflags, BIT(0))

#define INCREMENT_PC		__vcpu_single_flag(iflags, BIT(1))

#define EXCEPT_MASK		__vcpu_single_flag(iflags, GENMASK(3, 1))

#define PC_UPDATE_REQ		__vcpu_single_flag(iflags, GENMASK(3, 0))


#define __EXCEPT_MASK_VAL	unpack_vcpu_flag(EXCEPT_MASK)
#define __EXCEPT_SHIFT		__builtin_ctzl(__EXCEPT_MASK_VAL)
#define __vcpu_except_flags(_f)	iflags, (_f << __EXCEPT_SHIFT), __EXCEPT_MASK_VAL


#define EXCEPT_AA32_UND		__vcpu_except_flags(0)
#define EXCEPT_AA32_IABT	__vcpu_except_flags(1)
#define EXCEPT_AA32_DABT	__vcpu_except_flags(2)

#define EXCEPT_AA64_EL1_SYNC	__vcpu_except_flags(0)
#define EXCEPT_AA64_EL1_IRQ	__vcpu_except_flags(1)
#define EXCEPT_AA64_EL1_FIQ	__vcpu_except_flags(2)
#define EXCEPT_AA64_EL1_SERR	__vcpu_except_flags(3)

#define EXCEPT_AA64_EL2_SYNC	__vcpu_except_flags(4)
#define EXCEPT_AA64_EL2_IRQ	__vcpu_except_flags(5)
#define EXCEPT_AA64_EL2_FIQ	__vcpu_except_flags(6)
#define EXCEPT_AA64_EL2_SERR	__vcpu_except_flags(7)

#define DEBUG_DIRTY		__vcpu_single_flag(iflags, BIT(4))

#define DEBUG_STATE_SAVE_SPE	__vcpu_single_flag(iflags, BIT(5))

#define DEBUG_STATE_SAVE_TRBE	__vcpu_single_flag(iflags, BIT(6))

#define PKVM_HOST_STATE_DIRTY	__vcpu_single_flag(iflags, BIT(7))


#define HOST_SVE_ENABLED	__vcpu_single_flag(sflags, BIT(0))

#define HOST_SME_ENABLED	__vcpu_single_flag(sflags, BIT(1))

#define ON_UNSUPPORTED_CPU	__vcpu_single_flag(sflags, BIT(2))

#define IN_WFIT			__vcpu_single_flag(sflags, BIT(3))

#define SYSREGS_ON_CPU		__vcpu_single_flag(sflags, BIT(4))

#define DBG_SS_ACTIVE_PENDING	__vcpu_single_flag(sflags, BIT(5))

#define IN_WFI			__vcpu_single_flag(sflags, BIT(7))



#define vcpu_sve_pffr(vcpu) (kern_hyp_va((vcpu)->arch.sve_state) +	\
			     sve_ffr_offset((vcpu)->arch.sve_max_vl))

#define vcpu_sve_max_vq(vcpu)	sve_vq_from_vl((vcpu)->arch.sve_max_vl)

#define vcpu_sve_state_size(vcpu) ({					\
	size_t __size_ret;						\
	unsigned int __vcpu_vq;						\
									\
	if (WARN_ON(!sve_vl_valid((vcpu)->arch.sve_max_vl))) {		\
		__size_ret = 0;						\
	} else {							\
		__vcpu_vq = vcpu_sve_max_vq(vcpu);			\
		__size_ret = SVE_SIG_REGS_SIZE(__vcpu_vq);		\
	}								\
									\
	__size_ret;							\
})

#define KVM_GUESTDBG_VALID_MASK (KVM_GUESTDBG_ENABLE | \
				 KVM_GUESTDBG_USE_SW_BP | \
				 KVM_GUESTDBG_USE_HW | \
				 KVM_GUESTDBG_SINGLESTEP)

#define vcpu_has_sve(vcpu) (system_supports_sve() &&			\
			    vcpu_get_flag(vcpu, GUEST_HAS_SVE))

#ifdef CONFIG_ARM64_PTR_AUTH
#define vcpu_has_ptrauth(vcpu)						\
	((cpus_have_final_cap(ARM64_HAS_ADDRESS_AUTH) ||		\
	  cpus_have_final_cap(ARM64_HAS_GENERIC_AUTH)) &&		\
	  vcpu_get_flag(vcpu, GUEST_HAS_PTRAUTH))
#else
#define vcpu_has_ptrauth(vcpu)		false
#endif

#define vcpu_on_unsupported_cpu(vcpu)					\
	vcpu_get_flag(vcpu, ON_UNSUPPORTED_CPU)

#define vcpu_set_on_unsupported_cpu(vcpu)				\
	vcpu_set_flag(vcpu, ON_UNSUPPORTED_CPU)

#define vcpu_clear_on_unsupported_cpu(vcpu)				\
	vcpu_clear_flag(vcpu, ON_UNSUPPORTED_CPU)

#define vcpu_gp_regs(v)		(&(v)->arch.ctxt.regs)


#define __ctxt_sys_reg(c,r)	(&(c)->sys_regs[(r)])

#define ctxt_sys_reg(c,r)	(*__ctxt_sys_reg(c,r))

#define __vcpu_sys_reg(v,r)	(ctxt_sys_reg(&(v)->arch.ctxt, (r)))

static inline bool __vcpu_read_sys_reg_from_cpu(int reg, u64 *val)
{
	
	if (!has_vhe())
		return false;

	switch (reg) {
	case CSSELR_EL1:	*val = read_sysreg_s(SYS_CSSELR_EL1);	break;
	case SCTLR_EL1:		*val = read_sysreg_s(SYS_SCTLR_EL12);	break;
	case CPACR_EL1:		*val = read_sysreg_s(SYS_CPACR_EL12);	break;
	case TTBR0_EL1:		*val = read_sysreg_s(SYS_TTBR0_EL12);	break;
	case TTBR1_EL1:		*val = read_sysreg_s(SYS_TTBR1_EL12);	break;
	case TCR_EL1:		*val = read_sysreg_s(SYS_TCR_EL12);	break;
	case ESR_EL1:		*val = read_sysreg_s(SYS_ESR_EL12);	break;
	case AFSR0_EL1:		*val = read_sysreg_s(SYS_AFSR0_EL12);	break;
	case AFSR1_EL1:		*val = read_sysreg_s(SYS_AFSR1_EL12);	break;
	case FAR_EL1:		*val = read_sysreg_s(SYS_FAR_EL12);	break;
	case MAIR_EL1:		*val = read_sysreg_s(SYS_MAIR_EL12);	break;
	case VBAR_EL1:		*val = read_sysreg_s(SYS_VBAR_EL12);	break;
	case CONTEXTIDR_EL1:	*val = read_sysreg_s(SYS_CONTEXTIDR_EL12);break;
	case TPIDR_EL0:		*val = read_sysreg_s(SYS_TPIDR_EL0);	break;
	case TPIDRRO_EL0:	*val = read_sysreg_s(SYS_TPIDRRO_EL0);	break;
	case TPIDR_EL1:		*val = read_sysreg_s(SYS_TPIDR_EL1);	break;
	case AMAIR_EL1:		*val = read_sysreg_s(SYS_AMAIR_EL12);	break;
	case CNTKCTL_EL1:	*val = read_sysreg_s(SYS_CNTKCTL_EL12);	break;
	case ELR_EL1:		*val = read_sysreg_s(SYS_ELR_EL12);	break;
	case PAR_EL1:		*val = read_sysreg_par();		break;
	case DACR32_EL2:	*val = read_sysreg_s(SYS_DACR32_EL2);	break;
	case IFSR32_EL2:	*val = read_sysreg_s(SYS_IFSR32_EL2);	break;
	case DBGVCR32_EL2:	*val = read_sysreg_s(SYS_DBGVCR32_EL2);	break;
	default:		return false;
	}

	return true;
}

static inline bool __vcpu_write_sys_reg_to_cpu(u64 val, int reg)
{
	
	if (!has_vhe())
		return false;

	switch (reg) {
	case CSSELR_EL1:	write_sysreg_s(val, SYS_CSSELR_EL1);	break;
	case SCTLR_EL1:		write_sysreg_s(val, SYS_SCTLR_EL12);	break;
	case CPACR_EL1:		write_sysreg_s(val, SYS_CPACR_EL12);	break;
	case TTBR0_EL1:		write_sysreg_s(val, SYS_TTBR0_EL12);	break;
	case TTBR1_EL1:		write_sysreg_s(val, SYS_TTBR1_EL12);	break;
	case TCR_EL1:		write_sysreg_s(val, SYS_TCR_EL12);	break;
	case ESR_EL1:		write_sysreg_s(val, SYS_ESR_EL12);	break;
	case AFSR0_EL1:		write_sysreg_s(val, SYS_AFSR0_EL12);	break;
	case AFSR1_EL1:		write_sysreg_s(val, SYS_AFSR1_EL12);	break;
	case FAR_EL1:		write_sysreg_s(val, SYS_FAR_EL12);	break;
	case MAIR_EL1:		write_sysreg_s(val, SYS_MAIR_EL12);	break;
	case VBAR_EL1:		write_sysreg_s(val, SYS_VBAR_EL12);	break;
	case CONTEXTIDR_EL1:	write_sysreg_s(val, SYS_CONTEXTIDR_EL12);break;
	case TPIDR_EL0:		write_sysreg_s(val, SYS_TPIDR_EL0);	break;
	case TPIDRRO_EL0:	write_sysreg_s(val, SYS_TPIDRRO_EL0);	break;
	case TPIDR_EL1:		write_sysreg_s(val, SYS_TPIDR_EL1);	break;
	case AMAIR_EL1:		write_sysreg_s(val, SYS_AMAIR_EL12);	break;
	case CNTKCTL_EL1:	write_sysreg_s(val, SYS_CNTKCTL_EL12);	break;
	case ELR_EL1:		write_sysreg_s(val, SYS_ELR_EL12);	break;
	case PAR_EL1:		write_sysreg_s(val, SYS_PAR_EL1);	break;
	case DACR32_EL2:	write_sysreg_s(val, SYS_DACR32_EL2);	break;
	case IFSR32_EL2:	write_sysreg_s(val, SYS_IFSR32_EL2);	break;
	case DBGVCR32_EL2:	write_sysreg_s(val, SYS_DBGVCR32_EL2);	break;
	default:		return false;
	}

	return true;
}

#define vcpu_read_sys_reg(__vcpu, reg)					\
	({								\
		u64 __val = 0x8badf00d8badf00d;				\
									\
				\
		((!is_nvhe_hyp_code() &&				\
		  vcpu_get_flag(__vcpu, SYSREGS_ON_CPU) &&		\
		  __vcpu_read_sys_reg_from_cpu(reg, &__val))) ?		\
		 __val							\
		 :							\
		 ctxt_sys_reg(&__vcpu->arch.ctxt, reg);			\
	 })

#define vcpu_write_sys_reg(__vcpu, __val, reg)				\
	do {								\
				\
		if (is_nvhe_hyp_code() ||				\
		    !vcpu_get_flag(__vcpu, SYSREGS_ON_CPU) ||		\
		    !__vcpu_write_sys_reg_to_cpu(__val, reg))		\
			ctxt_sys_reg(&__vcpu->arch.ctxt, reg) = __val;	\
	} while (0)

struct kvm_vm_stat {
	struct kvm_vm_stat_generic generic;
	atomic64_t protected_hyp_mem;
	atomic64_t protected_shared_mem;
};

struct kvm_vcpu_stat {
	struct kvm_vcpu_stat_generic generic;
	u64 hvc_exit_stat;
	u64 wfe_exit_stat;
	u64 wfi_exit_stat;
	u64 mmio_exit_user;
	u64 mmio_exit_kernel;
	u64 signal_exits;
	u64 exits;
};

void kvm_vcpu_preferred_target(struct kvm_vcpu_init *init);
unsigned long kvm_arm_num_regs(struct kvm_vcpu *vcpu);
int kvm_arm_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *indices);
int kvm_arm_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);
int kvm_arm_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);

unsigned long kvm_arm_num_sys_reg_descs(struct kvm_vcpu *vcpu);
int kvm_arm_copy_sys_reg_indices(struct kvm_vcpu *vcpu, u64 __user *uindices);

int __kvm_arm_vcpu_get_events(struct kvm_vcpu *vcpu,
			      struct kvm_vcpu_events *events);

int __kvm_arm_vcpu_set_events(struct kvm_vcpu *vcpu,
			      struct kvm_vcpu_events *events);

#define KVM_ARCH_WANT_MMU_NOTIFIER

void kvm_arm_halt_guest(struct kvm *kvm);
void kvm_arm_resume_guest(struct kvm *kvm);

#define vcpu_has_run_once(vcpu)	!!rcu_access_pointer((vcpu)->pid)

#ifndef __KVM_NVHE_HYPERVISOR__
#define kvm_call_hyp_nvhe(f, ...)						\
	({								\
		struct arm_smccc_res res;				\
									\
		arm_smccc_1_1_hvc(KVM_HOST_SMCCC_FUNC(f),		\
				  ##__VA_ARGS__, &res);			\
		WARN_ON(res.a0 != SMCCC_RET_SUCCESS);			\
									\
		res.a1;							\
	})


#define kvm_call_hyp(f, ...)						\
	do {								\
		if (has_vhe()) {					\
			f(__VA_ARGS__);					\
			isb();						\
		} else {						\
			kvm_call_hyp_nvhe(f, ##__VA_ARGS__);		\
		}							\
	} while(0)

#define kvm_call_hyp_ret(f, ...)					\
	({								\
		typeof(f(__VA_ARGS__)) ret;				\
									\
		if (has_vhe()) {					\
			ret = f(__VA_ARGS__);				\
			isb();						\
		} else {						\
			ret = kvm_call_hyp_nvhe(f, ##__VA_ARGS__);	\
		}							\
									\
		ret;							\
	})
#else 
#define kvm_call_hyp(f, ...) f(__VA_ARGS__)
#define kvm_call_hyp_ret(f, ...) f(__VA_ARGS__)
#define kvm_call_hyp_nvhe(f, ...) f(__VA_ARGS__)
#endif 

void force_vm_exit(const cpumask_t *mask);

int handle_exit(struct kvm_vcpu *vcpu, int exception_index);
void handle_exit_early(struct kvm_vcpu *vcpu, int exception_index);

int kvm_handle_cp14_load_store(struct kvm_vcpu *vcpu);
int kvm_handle_cp14_32(struct kvm_vcpu *vcpu);
int kvm_handle_cp14_64(struct kvm_vcpu *vcpu);
int kvm_handle_cp15_32(struct kvm_vcpu *vcpu);
int kvm_handle_cp15_64(struct kvm_vcpu *vcpu);
int kvm_handle_sys_reg(struct kvm_vcpu *vcpu);
int kvm_handle_cp10_id(struct kvm_vcpu *vcpu);

void kvm_reset_sys_regs(struct kvm_vcpu *vcpu);

int kvm_sys_reg_table_init(void);


void kvm_mmio_write_buf(void *buf, unsigned int len, unsigned long data);
unsigned long kvm_mmio_read_buf(const void *buf, unsigned int len);

int kvm_handle_mmio_return(struct kvm_vcpu *vcpu);
int io_mem_abort(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa);


static inline bool kvm_arch_pmi_in_guest(struct kvm_vcpu *vcpu)
{
	return IS_ENABLED(CONFIG_GUEST_PERF_EVENTS) && !!vcpu;
}

long kvm_hypercall_pv_features(struct kvm_vcpu *vcpu);
gpa_t kvm_init_stolen_time(struct kvm_vcpu *vcpu);
void kvm_update_stolen_time(struct kvm_vcpu *vcpu);

bool kvm_arm_pvtime_supported(void);
int kvm_arm_pvtime_set_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);
int kvm_arm_pvtime_get_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);
int kvm_arm_pvtime_has_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);

extern unsigned int kvm_arm_vmid_bits;
int kvm_arm_vmid_alloc_init(void);
void kvm_arm_vmid_alloc_free(void);
void kvm_arm_vmid_update(struct kvm_vmid *kvm_vmid);
void kvm_arm_vmid_clear_active(void);

static inline void kvm_arm_pvtime_vcpu_init(struct kvm_vcpu_arch *vcpu_arch)
{
	vcpu_arch->steal.base = GPA_INVALID;
}

static inline bool kvm_arm_is_pvtime_enabled(struct kvm_vcpu_arch *vcpu_arch)
{
	return (vcpu_arch->steal.base != GPA_INVALID);
}

void kvm_set_sei_esr(struct kvm_vcpu *vcpu, u64 syndrome);

struct kvm_vcpu *kvm_mpidr_to_vcpu(struct kvm *kvm, unsigned long mpidr);

DECLARE_KVM_HYP_PER_CPU(struct kvm_host_data, kvm_host_data);

static inline void kvm_init_host_cpu_context(struct kvm_cpu_context *cpu_ctxt)
{
	
	ctxt_sys_reg(cpu_ctxt, MPIDR_EL1) = read_cpuid_mpidr();
}

static inline bool kvm_system_needs_idmapped_vectors(void)
{
	return cpus_have_const_cap(ARM64_SPECTRE_V3A);
}

void kvm_arm_vcpu_ptrauth_trap(struct kvm_vcpu *vcpu);

static inline void kvm_arch_hardware_unsetup(void) {}
static inline void kvm_arch_sync_events(struct kvm *kvm) {}
static inline void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu) {}

void kvm_arm_init_debug(void);
void kvm_arm_vcpu_init_debug(struct kvm_vcpu *vcpu);
void kvm_arm_setup_debug(struct kvm_vcpu *vcpu);
void kvm_arm_clear_debug(struct kvm_vcpu *vcpu);
void kvm_arm_reset_debug_ptr(struct kvm_vcpu *vcpu);

#define __vcpu_save_guest_debug_regs(vcpu)				\
	do {								\
		u64 val = vcpu_read_sys_reg(vcpu, MDSCR_EL1);		\
									\
		(vcpu)->arch.guest_debug_preserved.mdscr_el1 = val;	\
	} while(0)

#define __vcpu_restore_guest_debug_regs(vcpu)				\
	do {								\
		u64 val = (vcpu)->arch.guest_debug_preserved.mdscr_el1;	\
									\
		vcpu_write_sys_reg(vcpu, val, MDSCR_EL1);		\
	} while (0)

#define kvm_vcpu_os_lock_enabled(vcpu)		\
	(!!(__vcpu_sys_reg(vcpu, OSLSR_EL1) & SYS_OSLSR_OSLK))

#define kvm_vcpu_needs_debug_regs(vcpu)		\
	((vcpu)->guest_debug || kvm_vcpu_os_lock_enabled(vcpu))

int kvm_arm_vcpu_arch_set_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr);
int kvm_arm_vcpu_arch_get_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr);
int kvm_arm_vcpu_arch_has_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr);

long kvm_vm_ioctl_mte_copy_tags(struct kvm *kvm,
				struct kvm_arm_copy_mte_tags *copy_tags);


int kvm_arch_vcpu_run_map_fp(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_load_fp(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_ctxflush_fp(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_ctxsync_fp(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_put_fp(struct kvm_vcpu *vcpu);

static inline bool kvm_pmu_counter_deferred(struct perf_event_attr *attr)
{
	return (!has_vhe() && attr->exclude_host);
}


void kvm_arch_vcpu_load_debug_state_flags(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_put_debug_state_flags(struct kvm_vcpu *vcpu);

#ifdef CONFIG_KVM
void kvm_set_pmu_events(u32 set, struct perf_event_attr *attr);
void kvm_clr_pmu_events(u32 clr);
#else
static inline void kvm_set_pmu_events(u32 set, struct perf_event_attr *attr) {}
static inline void kvm_clr_pmu_events(u32 clr) {}
#endif

void kvm_vcpu_load_sysregs_vhe(struct kvm_vcpu *vcpu);
void kvm_vcpu_put_sysregs_vhe(struct kvm_vcpu *vcpu);

int kvm_set_ipa_limit(void);

#define __KVM_HAVE_ARCH_VM_ALLOC
struct kvm *kvm_arch_alloc_vm(void);

#define kvm_vm_is_protected(kvm)	((kvm)->arch.pkvm.enabled)

void kvm_init_protected_traps(struct kvm_vcpu *vcpu);

int kvm_arm_vcpu_finalize(struct kvm_vcpu *vcpu, int feature);
bool kvm_arm_vcpu_is_finalized(struct kvm_vcpu *vcpu);

#define kvm_arm_vcpu_sve_finalized(vcpu) vcpu_get_flag(vcpu, VCPU_SVE_FINALIZED)

#define kvm_has_mte(kvm)					\
	(system_supports_mte() &&				\
	 test_bit(KVM_ARCH_FLAG_MTE_ENABLED, &(kvm)->arch.flags))

#define kvm_supports_32bit_el0()				\
	(system_supports_32bit_el0() &&				\
	 !static_branch_unlikely(&arm64_mismatched_32bit_el0))

int kvm_trng_call(struct kvm_vcpu *vcpu);
#ifdef CONFIG_KVM
extern phys_addr_t hyp_mem_base;
extern phys_addr_t hyp_mem_size;
void __init kvm_hyp_reserve(void);
#else
static inline void kvm_hyp_reserve(void) { }
#endif

void kvm_arm_vcpu_power_off(struct kvm_vcpu *vcpu);
bool kvm_arm_vcpu_stopped(struct kvm_vcpu *vcpu);

#endif 
