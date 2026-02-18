/* SPDX-License-Identifier: GPL-2.0-only */


#ifndef __MEM_RELINQUISH_H__
#define __MEM_RELINQUISH_H__

#ifdef CONFIG_MEMORY_RELINQUISH

#include <asm/mem_relinquish.h>

#else	

static inline bool kvm_has_memrelinquish_services(void) { return false; }
static inline void page_relinquish(struct page *page) { }
static inline void post_page_relinquish_tlb_inv(void) { }

#endif	

#endif	
