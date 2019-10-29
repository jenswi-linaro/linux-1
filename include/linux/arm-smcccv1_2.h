/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 Arm Ltd.
 */

struct arm_smcccv1_2_return {
	u64 func;
	u64 arg1;
	u64 arg2;
	u64 arg3;
	u64 arg4;
	u64 arg5;
	u64 arg6;
	u64 arg7;
};

/**
 * __arm_smcccv1_2_hvc() - make HVC calls
 * @a0-a7: arguments passed in registers 0 to 7
 * @res: result values from registers 0 to 7
 */
asmlinkage
void __arm_smcccv1_2_hvc(unsigned long a0, unsigned long a1, unsigned long a2,
			 unsigned long a3, unsigned long a4, unsigned long a5,
			 unsigned long a6, unsigned long a7,
			 struct arm_smcccv1_2_return  *res);
