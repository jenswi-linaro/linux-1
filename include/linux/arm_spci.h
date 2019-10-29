/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Arm Ltd.
 */

#define SPCI_ERROR_32                 0x84000060
#define SPCI_SUCCESS_32               0x84000061

#define SPCI_ID_GET_32                0x84000069

#define SPCI_MSG_SEND_32              0x8400006E
#define SPCI_MSG_SEND_DIRECT_REQ_32   0x8400006F
#define SPCI_MSG_SEND_DIRECT_RESP_32  0x84000070

/* SPCI error codes. */
#define SPCI_SUCCESS            (0)
#define SPCI_NOT_SUPPORTED      (-1)
#define SPCI_INVALID_PARAMETERS (-2)
#define SPCI_NO_MEMORY          (-3)
#define SPCI_BUSY               (-4)
#define SPCI_INTERRUPTED        (-5)
#define SPCI_DENIED             (-6)
#define SPCI_RETRY              (-7)

/* The type of a SPCI endpoint ID */
typedef u16 spci_sp_id_t;

/**
 * struct spci_ops - represents the various SPCI protocol operations
 * available for an SCPI endpoint.
 */
struct spci_ops {
	int (*async_msg_send)(spci_sp_id_t dst_id, u32 len, u32 attributes);
	struct arm_smcccv1_2_return
	(*sync_msg_send)(spci_sp_id_t dst_id, u64 w3, u64 w4, u64 w5,
			 u64 w6, u64 w7);
};

#if IS_REACHABLE(CONFIG_ARM_SPCI_TRANSPORT)
struct spci_ops *get_spci_ops(void);
#else
static inline struct spci_ops *get_spci_ops(void) { return NULL; }
#endif
