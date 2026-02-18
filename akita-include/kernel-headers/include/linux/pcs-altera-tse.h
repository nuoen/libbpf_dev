/* SPDX-License-Identifier: GPL-2.0 */


#ifndef __LINUX_PCS_ALTERA_TSE_H
#define __LINUX_PCS_ALTERA_TSE_H

struct phylink_pcs;
struct net_device;

struct phylink_pcs *alt_tse_pcs_create(struct net_device *ndev,
				       void __iomem *pcs_base, int reg_width);

#endif 
