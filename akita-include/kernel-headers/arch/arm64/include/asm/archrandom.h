/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARCHRANDOM_H
#define _ASM_ARCHRANDOM_H

#include <linux/arm-smccc.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <asm/cpufeature.h>

#define ARM_SMCCC_TRNG_MIN_VERSION	0x10000UL

extern bool smccc_trng_available;

static inline bool __init smccc_probe_trng(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_TRNG_VERSION, &res);
	if ((s32)res.a0 < 0)
		return false;

	return res.a0 >= ARM_SMCCC_TRNG_MIN_VERSION;
}

static inline bool __arm64_rndr(unsigned long *v)
{
	bool ok;

	
	asm volatile(
		__mrs_s("%0", SYS_RNDR_EL0) "\n"
	"	cset %w1, ne\n"
	: "=r" (*v), "=r" (ok)
	:
	: "cc");

	return ok;
}

static inline bool __arm64_rndrrs(unsigned long *v)
{
	bool ok;

	
	asm volatile(
		__mrs_s("%0", SYS_RNDRRS_EL0) "\n"
	"	cset %w1, ne\n"
	: "=r" (*v), "=r" (ok)
	:
	: "cc");

	return ok;
}

static inline size_t __must_check arch_get_random_longs(unsigned long *v, size_t max_longs)
{
	
	if (max_longs && cpus_have_const_cap(ARM64_HAS_RNG) && __arm64_rndr(v))
		return 1;
	return 0;
}

static inline size_t __must_check arch_get_random_seed_longs(unsigned long *v, size_t max_longs)
{
	if (!max_longs)
		return 0;

	
	if (smccc_trng_available) {
		struct arm_smccc_res res;

		max_longs = min_t(size_t, 3, max_longs);
		arm_smccc_1_1_invoke(ARM_SMCCC_TRNG_RND64, max_longs * 64, &res);
		if ((int)res.a0 >= 0) {
			switch (max_longs) {
			case 3:
				*v++ = res.a1;
				fallthrough;
			case 2:
				*v++ = res.a2;
				fallthrough;
			case 1:
				*v++ = res.a3;
				break;
			}
			return max_longs;
		}
	}

	
	if (cpus_have_const_cap(ARM64_HAS_RNG) && __arm64_rndrrs(v))
		return 1;

	return 0;
}

static inline bool __init __early_cpu_has_rndr(void)
{
	
	unsigned long ftr = read_sysreg_s(SYS_ID_AA64ISAR0_EL1);
	return (ftr >> ID_AA64ISAR0_EL1_RNDR_SHIFT) & 0xf;
}

static inline size_t __init __must_check
arch_get_random_seed_longs_early(unsigned long *v, size_t max_longs)
{
	WARN_ON(system_state != SYSTEM_BOOTING);

	if (!max_longs)
		return 0;

	if (smccc_trng_available) {
		struct arm_smccc_res res;

		max_longs = min_t(size_t, 3, max_longs);
		arm_smccc_1_1_invoke(ARM_SMCCC_TRNG_RND64, max_longs * 64, &res);
		if ((int)res.a0 >= 0) {
			switch (max_longs) {
			case 3:
				*v++ = res.a1;
				fallthrough;
			case 2:
				*v++ = res.a2;
				fallthrough;
			case 1:
				*v++ = res.a3;
				break;
			}
			return max_longs;
		}
	}

	if (__early_cpu_has_rndr() && __arm64_rndr(v))
		return 1;

	return 0;
}
#define arch_get_random_seed_longs_early arch_get_random_seed_longs_early

#endif 
