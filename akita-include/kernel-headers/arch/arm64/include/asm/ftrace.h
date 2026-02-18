/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_FTRACE_H
#define __ASM_FTRACE_H

#include <asm/insn.h>

#define HAVE_FUNCTION_GRAPH_FP_TEST


#define HAVE_FUNCTION_GRAPH_RET_ADDR_PTR

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
#define ARCH_SUPPORTS_FTRACE_OPS 1
#else
#define MCOUNT_ADDR		((unsigned long)_mcount)
#endif


#define MCOUNT_INSN_SIZE	AARCH64_INSN_SIZE

#define FTRACE_PLT_IDX		0
#define FTRACE_REGS_PLT_IDX	1
#define NR_FTRACE_PLTS		2


#define ARCH_FTRACE_SHIFT_STACK_TRACER 1

#ifndef __ASSEMBLY__
#include <linux/compat.h>

extern void _mcount(unsigned long);
extern void *return_address(unsigned int);

struct dyn_arch_ftrace {
	
};

extern unsigned long ftrace_graph_call;

extern void return_to_handler(void);

static inline unsigned long ftrace_call_adjust(unsigned long addr)
{
	
	if (IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_REGS))
		return addr + AARCH64_INSN_SIZE;
	
	return addr;
}

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
struct dyn_ftrace;
struct ftrace_ops;
struct ftrace_regs;

int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec);
#define ftrace_init_nop ftrace_init_nop

void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
		       struct ftrace_ops *op, struct ftrace_regs *fregs);
#define ftrace_graph_func ftrace_graph_func
#endif

#define ftrace_return_address(n) return_address(n)


#define ARCH_TRACE_IGNORE_COMPAT_SYSCALLS
static inline bool arch_trace_is_compat_syscall(struct pt_regs *regs)
{
	return is_compat_task();
}

#define ARCH_HAS_SYSCALL_MATCH_SYM_NAME

static inline bool arch_syscall_match_sym_name(const char *sym,
					       const char *name)
{
	
	return !strcmp(sym + 8, name);
}
#endif 

#endif 
