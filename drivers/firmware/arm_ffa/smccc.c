// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 ARM Ltd.
 */

#include <linux/printk.h>

#include "common.h"

static struct arm_smccc_v1_2_res
__arm_ffa_fn_smc(unsigned long function_id, unsigned long arg0,
		 unsigned long arg1, unsigned long arg2, unsigned long arg3,
		 unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	struct arm_smccc_v1_2_res res;

	arm_smccc_v1_2_smc(function_id, arg0, arg1, arg2, arg3, arg4, arg5,
			   arg6, &res);

	return res;
}

static struct arm_smccc_v1_2_res
__arm_ffa_fn_hvc(unsigned long function_id, unsigned long arg0,
		 unsigned long arg1, unsigned long arg2, unsigned long arg3,
		 unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	struct arm_smccc_v1_2_res res;

	arm_smccc_v1_2_hvc(function_id, arg0, arg1, arg2, arg3, arg4, arg5,
			   arg6, &res);
	return res;
}

int __init ffa_transport_init(ffa_fn **invoke_ffa_fn)
{
	enum arm_smccc_conduit conduit;

	if (arm_smccc_get_version() < ARM_SMCCC_VERSION_1_2)
		return -EOPNOTSUPP;

	conduit = arm_smccc_1_1_get_conduit();
	if (conduit == SMCCC_CONDUIT_NONE) {
		pr_err("%s: invalid SMCCC conduit\n", __func__);
		return -EOPNOTSUPP;
	}

	if (conduit == SMCCC_CONDUIT_SMC)
		*invoke_ffa_fn = __arm_ffa_fn_smc;
	else
		*invoke_ffa_fn = __arm_ffa_fn_hvc;

	return 0;
}
