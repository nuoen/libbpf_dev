/* SPDX-License-Identifier: GPL-2.0-only */


#ifndef _GUNYAH_VM_MGR_H
#define _GUNYAH_VM_MGR_H

#include <linux/compiler_types.h>
#include <linux/gunyah.h>
#include <linux/gunyah_rsc_mgr.h>
#include <linux/list.h>
#include <linux/mod_devicetable.h>
#include <linux/notifier.h>

#include <uapi/linux/gunyah.h>

struct gh_vm;

int __must_check gh_vm_get(struct gh_vm *ghvm);
void gh_vm_put(struct gh_vm *ghvm);

struct gh_vm_function_instance;

struct gh_vm_function {
	u32 type;
	const char *name;
	struct module *mod;
	long (*bind)(struct gh_vm_function_instance *f);
	void (*unbind)(struct gh_vm_function_instance *f);
	bool (*compare)(const struct gh_vm_function_instance *f, const void *arg, size_t size);
};


struct gh_vm_function_instance {
	size_t arg_size;
	void *argp;
	struct gh_vm *ghvm;
	struct gh_rm *rm;
	struct gh_vm_function *fn;
	void *data;
	struct list_head vm_list;
};

int gh_vm_function_register(struct gh_vm_function *f);
void gh_vm_function_unregister(struct gh_vm_function *f);


#define MODULE_ALIAS_GH_VM_FUNCTION(_type, _idx)			\
	static inline void __maybe_unused __chk##_idx(void)		\
	{								\
		BUILD_BUG_ON(_type != _idx);				\
	}								\
	MODULE_ALIAS("ghfunc:" __stringify(_idx))

#define DECLARE_GH_VM_FUNCTION(_name, _type, _bind, _unbind, _compare)	\
	static struct gh_vm_function _name = {				\
		.type = _type,						\
		.name = __stringify(_name),				\
		.mod = THIS_MODULE,					\
		.bind = _bind,						\
		.unbind = _unbind,					\
		.compare = _compare,					\
	}

#define module_gh_vm_function(__gf)					\
	module_driver(__gf, gh_vm_function_register, gh_vm_function_unregister)

#define DECLARE_GH_VM_FUNCTION_INIT(_name, _type, _idx, _bind, _unbind, _compare)	\
	DECLARE_GH_VM_FUNCTION(_name, _type, _bind, _unbind, _compare);			\
	module_gh_vm_function(_name);							\
	MODULE_ALIAS_GH_VM_FUNCTION(_type, _idx)


struct gh_vm_resource_ticket {
	struct list_head vm_list;
	struct list_head resources;
	enum gh_resource_type resource_type;
	u32 label;

	struct module *owner;
	bool (*populate)(struct gh_vm_resource_ticket *ticket, struct gh_resource *ghrsc);
	void (*unpopulate)(struct gh_vm_resource_ticket *ticket, struct gh_resource *ghrsc);
};

int gh_vm_add_resource_ticket(struct gh_vm *ghvm, struct gh_vm_resource_ticket *ticket);
void gh_vm_remove_resource_ticket(struct gh_vm *ghvm, struct gh_vm_resource_ticket *ticket);


struct gh_vm_io_handler {
	struct rb_node node;
	u64 addr;

	bool datamatch;
	u8 len;
	u64 data;
	struct gh_vm_io_handler_ops *ops;
};


struct gh_vm_io_handler_ops {
	int (*read)(struct gh_vm_io_handler *io_dev, u64 addr, u32 len, u64 data);
	int (*write)(struct gh_vm_io_handler *io_dev, u64 addr, u32 len, u64 data);
};

int gh_vm_add_io_handler(struct gh_vm *ghvm, struct gh_vm_io_handler *io_dev);
void gh_vm_remove_io_handler(struct gh_vm *ghvm, struct gh_vm_io_handler *io_dev);

#endif
