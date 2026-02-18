/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ANDROID_KABI_H
#define _ANDROID_KABI_H

#include <linux/compiler.h>
#include <linux/stringify.h>



#define __ANDROID_KABI_CHECK_SIZE_ALIGN(_orig, _new)				\
	union {									\
		_Static_assert(sizeof(struct{_new;}) <= sizeof(struct{_orig;}),	\
			       __FILE__ ":" __stringify(__LINE__) ": "		\
			       __stringify(_new)				\
			       " is larger than "				\
			       __stringify(_orig) );				\
		_Static_assert(__alignof__(struct{_new;}) <= __alignof__(struct{_orig;}),	\
			       __FILE__ ":" __stringify(__LINE__) ": "		\
			       __stringify(_orig)				\
			       " is not aligned the same as "			\
			       __stringify(_new) );				\
	}

#ifdef __GENKSYMS__

#define _ANDROID_KABI_REPLACE(_orig, _new)		_orig

#else

#define _ANDROID_KABI_REPLACE(_orig, _new)			\
	union {							\
		_new;						\
		struct {					\
			_orig;					\
		};						\
		__ANDROID_KABI_CHECK_SIZE_ALIGN(_orig, _new);	\
	}

#endif 

#define _ANDROID_KABI_RESERVE(n)		u64 android_kabi_reserved##n





#ifdef CONFIG_ANDROID_KABI_RESERVE
#define ANDROID_KABI_RESERVE(number)	_ANDROID_KABI_RESERVE(number)
#else
#define ANDROID_KABI_RESERVE(number)
#endif


#define ANDROID_KABI_BACKPORT_OK(number) ANDROID_KABI_RESERVE(number)




#define ANDROID_KABI_USE(number, _new)		\
	_ANDROID_KABI_REPLACE(_ANDROID_KABI_RESERVE(number), _new)


#define ANDROID_KABI_BACKPORT_USE(number, _new) \
	ANDROID_KABI_USE(number, _new)


#define ANDROID_KABI_USE2(number, _new1, _new2)			\
	_ANDROID_KABI_REPLACE(_ANDROID_KABI_RESERVE(number), struct{ _new1; _new2; })


#endif 
