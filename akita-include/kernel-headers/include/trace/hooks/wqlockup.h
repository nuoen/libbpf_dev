/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM wqlockup
#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_WQLOCKUP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_WQLOCKUP_H
#include <trace/hooks/vendor_hooks.h>

DECLARE_HOOK(android_vh_wq_lockup_pool,
	TP_PROTO(int cpu, unsigned long pool_ts),
	TP_ARGS(cpu, pool_ts));

#endif 

#include <trace/define_trace.h>
