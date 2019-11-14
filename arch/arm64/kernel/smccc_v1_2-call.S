/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 Arm Ltd.
 */

#include <linux/linkage.h>

.macro SMC_CALL conduit
	\conduit #0
	ldr x8, [sp]
	stp x0, x1, [x8]
	stp x2, x3, [x8, #16]
	stp x4, x5, [x8, #32]
	stp x6, x7, [x8, #48]
	ret
.endm

ENTRY(__arm_smcccv1_2_hvc)
	SMC_CALL hvc
ENDPROC(__arm_smcccv1_2_hvc)

ENTRY(__arm_smcccv1_2_smc)
	SMC_CALL smc
ENDPROC(__arm_smcccv1_2_smc)
