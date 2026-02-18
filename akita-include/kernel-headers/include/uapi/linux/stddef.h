/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_STDDEF_H
#define _UAPI_LINUX_STDDEF_H

#include <linux/compiler_types.h>

#ifndef __always_inline
#define __always_inline inline
#endif


#ifndef __cplusplus
#define __struct_group_tag(TAG)		TAG
#else
#define __struct_group_tag(TAG)
#endif


#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct __struct_group_tag(TAG) { MEMBERS } ATTRS NAME; \
	} ATTRS


#define __DECLARE_FLEX_ARRAY(TYPE, NAME)	\
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}
#endif
