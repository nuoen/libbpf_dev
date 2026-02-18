/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_COMPILER_H
#define __ASM_COMPILER_H

#ifdef ARM64_ASM_ARCH
#define ARM64_ASM_PREAMBLE ".arch " ARM64_ASM_ARCH "\n"
#else
#define ARM64_ASM_PREAMBLE
#endif


#define ptrauth_user_pac_mask()		GENMASK_ULL(54, vabits_actual)
#define ptrauth_kernel_pac_mask()	GENMASK_ULL(63, vabits_actual)


#define ptrauth_clear_pac(ptr)						\
	((ptr & BIT_ULL(55)) ? (ptr | ptrauth_kernel_pac_mask()) :	\
			       (ptr & ~ptrauth_user_pac_mask()))

#define __builtin_return_address(val)					\
	(void *)(ptrauth_clear_pac((unsigned long)__builtin_return_address(val)))

#endif 
