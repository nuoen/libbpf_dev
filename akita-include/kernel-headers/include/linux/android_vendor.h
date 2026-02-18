/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ANDROID_VENDOR_H
#define _ANDROID_VENDOR_H

#include "android_kabi.h"

#define _ANDROID_BACKPORT_RESERVED(n)	u64 android_backport_reserved##n


#ifdef CONFIG_ANDROID_VENDOR_OEM_DATA
#define ANDROID_VENDOR_DATA(n)		u64 android_vendor_data##n
#define ANDROID_VENDOR_DATA_ARRAY(n, s)	u64 android_vendor_data##n[s]

#define ANDROID_OEM_DATA(n)		u64 android_oem_data##n
#define ANDROID_OEM_DATA_ARRAY(n, s)	u64 android_oem_data##n[s]
#define ANDROID_BACKPORT_RESERVED(n)	_ANDROID_BACKPORT_RESERVED(n)

#define android_init_vendor_data(p, n) \
	memset(&p->android_vendor_data##n, 0, sizeof(p->android_vendor_data##n))
#define android_init_oem_data(p, n) \
	memset(&p->android_oem_data##n, 0, sizeof(p->android_oem_data##n))
#else
#define ANDROID_VENDOR_DATA(n)
#define ANDROID_VENDOR_DATA_ARRAY(n, s)
#define ANDROID_OEM_DATA(n)
#define ANDROID_OEM_DATA_ARRAY(n, s)
#define ANDROID_BACKPORT_RESERVED(n)

#define android_init_vendor_data(p, n)
#define android_init_oem_data(p, n)
#endif





#define ANDROID_BACKPORT_RESERVED_USE(number, _new)		\
	_ANDROID_KABI_REPLACE(_ANDROID_BACKPORT_RESERVED(number), _new)


#define ANDROID_BACKPORT_RESERVED_USE2(number, _new1, _new2)			\
	_ANDROID_KABI_REPLACE(_ANDROID_BACKPORT_RESERVED(number), struct{ _new1; _new2; })

#endif 
