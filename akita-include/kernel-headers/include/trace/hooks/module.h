/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM module

#define TRACE_INCLUDE_PATH trace/hooks
#if !defined(_TRACE_HOOK_MODULE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_MODULE_H
#include <trace/hooks/vendor_hooks.h>

struct module;
DECLARE_RESTRICTED_HOOK(android_rvh_set_module_permit_before_init,
	TP_PROTO(const struct module *mod),
	TP_ARGS(mod), 1);

DECLARE_RESTRICTED_HOOK(android_rvh_set_module_permit_after_init,
	TP_PROTO(const struct module *mod),
	TP_ARGS(mod), 1);

DECLARE_RESTRICTED_HOOK(android_rvh_set_module_core_rw_nx,
	TP_PROTO(const struct module *mod),
	TP_ARGS(mod), 1);

DECLARE_RESTRICTED_HOOK(android_rvh_set_module_init_rw_nx,
	TP_PROTO(const struct module *mod),
	TP_ARGS(mod), 1);

#endif 

#include <trace/define_trace.h>
