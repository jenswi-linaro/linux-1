/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */

#ifndef _UAPI_LINUX_VIRTIO_RPMB_H
#define _UAPI_LINUX_VIRTIO_RPMB_H

#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>

struct virtio_rpmb_config {
	__u8 capacity;
	__u8 max_wr_cnt;
	__u8 max_rd_cnt;
} __attribute__((packed));

/* RPMB Request Types (in .req_resp) */
#define VIRTIO_RPMB_REQ_PROGRAM_KEY        0x0001
#define VIRTIO_RPMB_REQ_GET_WRITE_COUNTER  0x0002
#define VIRTIO_RPMB_REQ_DATA_WRITE         0x0003
#define VIRTIO_RPMB_REQ_DATA_READ          0x0004
#define VIRTIO_RPMB_REQ_RESULT_READ        0x0005

/* RPMB Response Types (in .req_resp) */
#define VIRTIO_RPMB_RESP_PROGRAM_KEY       0x0100
#define VIRTIO_RPMB_RESP_GET_COUNTER       0x0200
#define VIRTIO_RPMB_RESP_DATA_WRITE        0x0300
#define VIRTIO_RPMB_RESP_DATA_READ         0x0400

struct virtio_rpmb_frame {
	__u8 stuff[196];
	__u8 key_mac[32];
	__u8 data[256];
	__u8 nonce[16];
	__be32 write_counter;
	__be16 address;
	__be16 block_count;
	__be16 result;
	__be16 req_resp;
} __attribute__((packed));

/* RPMB Operation Results (in .result) */
#define VIRTIO_RPMB_RES_OK                     0x0000
#define VIRTIO_RPMB_RES_GENERAL_FAILURE        0x0001
#define VIRTIO_RPMB_RES_AUTH_FAILURE           0x0002
#define VIRTIO_RPMB_RES_COUNT_FAILURE          0x0003
#define VIRTIO_RPMB_RES_ADDR_FAILURE           0x0004
#define VIRTIO_RPMB_RES_WRITE_FAILURE          0x0005
#define VIRTIO_RPMB_RES_READ_FAILURE           0x0006
#define VIRTIO_RPMB_RES_NO_AUTH_KEY            0x0007
#define VIRTIO_RPMB_RES_WRITE_COUNTER_EXPIRED  0x0080


#endif /* _UAPI_LINUX_VIRTIO_RPMB_H */
