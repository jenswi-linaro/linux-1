/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 */
#ifndef SPCI_PRIVATE_H
#define SPCI_PRIVATE_H

#include <linux/arm_spci.h>

#define PAGE_COUNT(x) (((x) + PAGE_SIZE - 1) >> PAGE_SHIFT)

/* One buffer for each security state */
#define SPCI_BUF_RX             0U
#define SPCI_BUF_TX             1U
#define SPCI_MAX_BUFS           2U

struct spci_smc_call_get_version_result {
	unsigned short minor;
	unsigned short major;
};

struct spci_smc_call_generic_result {
	int32_t status;
};

typedef struct spci_msg_buf_desc {
	unsigned long va;
	phys_addr_t pa;
	struct mutex buf_mutex;
} spci_msg_buf_desc_t;

/* Size of spec. defined meta data in SPCI message buffer */
#define SPCI_BUF_META_DATA_SIZE	(sizeof(spci_msg_hdr_t) + sizeof(spci_buf_t))

/* Structure to encode the biggest imp. def. message possible */
struct spci_msg_imp_def {
	uint8_t data[PAGE_SIZE - SPCI_BUF_META_DATA_SIZE];
};

struct spci_ops {
	uint32_t (*get_version)(void);
	uint32_t (*get_features)(void);
	int32_t  (*msg_send_recv)(struct spci_msg_imp_def *in,
				  uint32_t in_len,
				  struct spci_msg_imp_def *out,
				  uint32_t *out_len,
				  uint32_t flags);
};

struct spci_ops *get_spci_ops(void);

#endif /* SPCI_PRIVATE_H */
