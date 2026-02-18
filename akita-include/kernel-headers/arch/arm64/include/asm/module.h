/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_MODULE_H
#define __ASM_MODULE_H

#include <asm-generic/module.h>

#ifdef CONFIG_ARM64_MODULE_PLTS
struct mod_plt_sec {
	int			plt_shndx;
	int			plt_num_entries;
	int			plt_max_entries;
};

#define ARM64_MODULE_PLTS_ARCHDATA					\
	struct mod_plt_sec	core;					\
	struct mod_plt_sec	init;					\
									\
						\
	struct plt_entry	*ftrace_trampolines;
#else
#define ARM64_MODULE_PLTS_ARCHDATA
#endif

#ifdef CONFIG_KVM
struct pkvm_module_section {
	void *start;
	void *end;
};

typedef s32 kvm_nvhe_reloc_t;
struct pkvm_module_ops;

struct pkvm_el2_module {
	struct pkvm_module_section text;
	struct pkvm_module_section bss;
	struct pkvm_module_section rodata;
	struct pkvm_module_section data;
	kvm_nvhe_reloc_t *relocs;
	unsigned int nr_relocs;
	int (*init)(const struct pkvm_module_ops *ops);
};

void kvm_apply_hyp_module_relocations(void *mod_start, void *hyp_va,
				      kvm_nvhe_reloc_t *begin,
				      kvm_nvhe_reloc_t *end);

#define ARM64_MODULE_KVM_ARCHDATA					\
					\
	struct pkvm_el2_module	hyp;
#else
#define ARM64_MODULE_KVM_ARCHDATA
#endif

#ifdef CONFIG_HAVE_MOD_ARCH_SPECIFIC
struct mod_arch_specific {
	ARM64_MODULE_PLTS_ARCHDATA
	ARM64_MODULE_KVM_ARCHDATA
};
#endif

u64 module_emit_plt_entry(struct module *mod, Elf64_Shdr *sechdrs,
			  void *loc, const Elf64_Rela *rela,
			  Elf64_Sym *sym);

u64 module_emit_veneer_for_adrp(struct module *mod, Elf64_Shdr *sechdrs,
				void *loc, u64 val);

#ifdef CONFIG_RANDOMIZE_BASE
extern u64 module_alloc_base;
#else
#define module_alloc_base	((u64)_etext - MODULES_VSIZE)
#endif

struct plt_entry {
	
	__le32	adrp;	
	__le32	add;	
	__le32	br;	
};

static inline bool is_forbidden_offset_for_adrp(void *place)
{
	return IS_ENABLED(CONFIG_ARM64_ERRATUM_843419) &&
	       cpus_have_const_cap(ARM64_WORKAROUND_843419) &&
	       ((u64)place & 0xfff) >= 0xff8;
}

struct plt_entry get_plt_entry(u64 dst, void *pc);

static inline const Elf_Shdr *find_section(const Elf_Ehdr *hdr,
				    const Elf_Shdr *sechdrs,
				    const char *name)
{
	const Elf_Shdr *s, *se;
	const char *secstrs = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (s = sechdrs, se = sechdrs + hdr->e_shnum; s < se; s++) {
		if (strcmp(name, secstrs + s->sh_name) == 0)
			return s;
	}

	return NULL;
}

#endif 
