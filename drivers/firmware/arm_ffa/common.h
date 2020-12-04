/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 ARM Ltd.
 */

#ifndef _FFA_COMMON_H
#define _FFA_COMMON_H

#include <linux/arm_ffa.h>
#include <linux/arm-smccc.h>
#include <linux/err.h>

typedef struct arm_smccc_v1_2_res ffa_res_t;

typedef ffa_res_t
(ffa_fn)(unsigned long, unsigned long, unsigned long, unsigned long,
	 unsigned long, unsigned long, unsigned long, unsigned long);

int __init arm_ffa_bus_init(void);
void __exit arm_ffa_bus_exit(void);
bool ffa_device_is_valid(struct ffa_device *ffa_dev);

#ifdef CONFIG_ARM_FFA_SMCCC
int __init ffa_transport_init(ffa_fn **invoke_ffa_fn);
#else
static inline int __init ffa_transport_init(ffa_fn **invoke_ffa_fn)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* _FFA_COMMON_H */
