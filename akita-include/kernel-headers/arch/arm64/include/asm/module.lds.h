/* SPDX-License-Identifier: GPL-2.0-only */
#include <asm/page-def.h>

SECTIONS {
#ifdef CONFIG_ARM64_MODULE_PLTS
	.plt 0 : { BYTE(0) }
	.init.plt 0 : { BYTE(0) }
	.text.ftrace_trampoline 0 : { BYTE(0) }
#endif

#ifdef CONFIG_KASAN_SW_TAGS
	
	.text.hot : { *(.text.hot) }
#endif

#ifdef CONFIG_KVM
	.hyp.text : ALIGN(PAGE_SIZE) {
		*(.hyp.text)
		. = ALIGN(PAGE_SIZE);
	}
	.hyp.bss : ALIGN(PAGE_SIZE) {
		*(.hyp.bss)
		. = ALIGN(PAGE_SIZE);
	}
	.hyp.rodata : ALIGN(PAGE_SIZE) {
		*(.hyp.rodata)
		. = ALIGN(PAGE_SIZE);
	}
	.hyp.data : ALIGN(PAGE_SIZE) {
		*(.hyp.data)
		. = ALIGN(PAGE_SIZE);
	}
	.hyp.reloc : ALIGN(4) {	*(.hyp.reloc) }
#endif

#ifdef CONFIG_UNWIND_TABLES
	
	.init.eh_frame : { *(.eh_frame) }
#endif
}
