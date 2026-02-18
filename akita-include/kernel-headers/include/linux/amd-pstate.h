/* SPDX-License-Identifier: GPL-2.0-only */


#ifndef _LINUX_AMD_PSTATE_H
#define _LINUX_AMD_PSTATE_H

#include <linux/pm_qos.h>



struct amd_aperf_mperf {
	u64 aperf;
	u64 mperf;
	u64 tsc;
};


struct amd_cpudata {
	int	cpu;

	struct	freq_qos_request req[2];
	u64	cppc_req_cached;

	u32	highest_perf;
	u32	nominal_perf;
	u32	lowest_nonlinear_perf;
	u32	lowest_perf;

	u32	max_freq;
	u32	min_freq;
	u32	nominal_freq;
	u32	lowest_nonlinear_freq;

	struct amd_aperf_mperf cur;
	struct amd_aperf_mperf prev;

	u64	freq;
	bool	boost_supported;
};

#endif 
