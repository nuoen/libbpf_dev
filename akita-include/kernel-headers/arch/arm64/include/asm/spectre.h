/* SPDX-License-Identifier: GPL-2.0-only */


#ifndef __ASM_SPECTRE_H
#define __ASM_SPECTRE_H

#define BP_HARDEN_EL2_SLOTS 4
#define __BP_HARDEN_HYP_VECS_SZ	((BP_HARDEN_EL2_SLOTS - 1) * SZ_2K)

#ifndef __ASSEMBLY__

#include <linux/percpu.h>

#include <asm/cpufeature.h>
#include <asm/virt.h>


enum mitigation_state {
	SPECTRE_UNAFFECTED,
	SPECTRE_MITIGATED,
	SPECTRE_VULNERABLE,
};

struct task_struct;


enum arm64_hyp_spectre_vector {
	
	HYP_VECTOR_DIRECT,

	
	HYP_VECTOR_SPECTRE_DIRECT,

	
	HYP_VECTOR_INDIRECT,

	
	HYP_VECTOR_SPECTRE_INDIRECT,
};

typedef void (*bp_hardening_cb_t)(void);

struct bp_hardening_data {
	enum arm64_hyp_spectre_vector	slot;
	bp_hardening_cb_t		fn;
};

DECLARE_PER_CPU_READ_MOSTLY(struct bp_hardening_data, bp_hardening_data);


static __always_inline void arm64_apply_bp_hardening(void)
{
	struct bp_hardening_data *d;

	if (!cpus_have_const_cap(ARM64_SPECTRE_V2))
		return;

	d = this_cpu_ptr(&bp_hardening_data);
	if (d->fn)
		d->fn();
}

enum mitigation_state arm64_get_spectre_v2_state(void);
bool has_spectre_v2(const struct arm64_cpu_capabilities *cap, int scope);
void spectre_v2_enable_mitigation(const struct arm64_cpu_capabilities *__unused);

bool has_spectre_v3a(const struct arm64_cpu_capabilities *cap, int scope);
void spectre_v3a_enable_mitigation(const struct arm64_cpu_capabilities *__unused);

enum mitigation_state arm64_get_spectre_v4_state(void);
bool has_spectre_v4(const struct arm64_cpu_capabilities *cap, int scope);
void spectre_v4_enable_mitigation(const struct arm64_cpu_capabilities *__unused);
void spectre_v4_enable_task_mitigation(struct task_struct *tsk);

enum mitigation_state arm64_get_meltdown_state(void);

enum mitigation_state arm64_get_spectre_bhb_state(void);
bool is_spectre_bhb_affected(const struct arm64_cpu_capabilities *entry, int scope);
u8 spectre_bhb_loop_affected(int scope);
void spectre_bhb_enable_mitigation(const struct arm64_cpu_capabilities *__unused);
#endif	
#endif	
