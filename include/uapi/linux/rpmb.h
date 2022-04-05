/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Copyright (C) 2015-2018 Intel Corp. All rights reserved
 * Copyright (C) 2021-2022 Linaro Ltd
 */
#ifndef _UAPI_LINUX_RPMB_H_
#define _UAPI_LINUX_RPMB_H_

#include <linux/types.h>

/**
 * struct rpmb_ioc_ver_cmd - rpmb api version
 *
 * @api_version: rpmb API version.
 */
struct rpmb_ioc_ver_cmd {
	__u32 api_version;
} __packed;

enum rpmb_auth_method {
	RPMB_HMAC_ALGO_SHA_256 = 0,
};

/**
 * struct rpmb_ioc_cap_cmd - rpmb capabilities
 *
 * @target: rpmb target/region within RPMB partition.
 * @capacity: storage capacity (in units of 128K)
 * @block_size: storage data block size (in units of 256B)
 * @wr_cnt_max: maximal number of block that can be written in a single request.
 * @rd_cnt_max: maximal number of block that can be read in a single request.
 * @auth_method: authentication method: currently always HMAC_SHA_256
 * @reserved: reserved to align to 4 bytes.
 */
struct rpmb_ioc_cap_cmd {
	__u16 target;
	__u16 capacity;
	__u16 block_size;
	__u16 wr_cnt_max;
	__u16 rd_cnt_max;
	__u16 auth_method;
	__u16 reserved;
} __packed;

/**
 * struct rpmb_ioc_reqresp_cmd - general purpose reqresp
 *
 * Most RPMB operations consist of a set of request frames and an
 * optional response frame. If a response is requested the user must
 * allocate enough space for the response, otherwise the fields should
 * be set to 0/NULL.
 *
 * It is used for programming the key, reading the counter and writing
 * blocks to the device. If the frames are malformed they may be
 * rejected by the underlying driver or the device itself.
 *
 * Assuming the transaction succeeds it is still up to user space to
 * validate the response and check MAC values correspond to the
 * programmed keys.
 *
 * @len: length of write counter request
 * @request: ptr to device specific request frame
 * @rlen: length of response frame
 * @resp: ptr to device specific response frame
 */
struct rpmb_ioc_reqresp_cmd {
	__u32 len;
	__u8 __user *request;
	__u32 rlen;
	__u8 __user *response;
} __packed;

/**
 * struct rpmb_ioc_rblocks_cmd - read blocks from RPMB
 *
 * @addr: index into device (units of 256B blocks)
 * @count: number of 256B blocks
 * @len: length of response frame
 * @data: block data (in device specific framing)
 *
 * Reading blocks from an RPMB device doesn't require any specific
 * authentication. However the result still needs to be validated by
 * user space.
 */
struct rpmb_ioc_rblocks_cmd {
	__u32 addr;
	__u32 count;
	__u32 len;
	__u8 __user *data;
} __packed;

#define RPMB_IOC_VER_CMD     _IOR(0xB8, 80, struct rpmb_ioc_ver_cmd)
#define RPMB_IOC_CAP_CMD     _IOR(0xB8, 81, struct rpmb_ioc_cap_cmd)
#define RPMB_IOC_PKEY_CMD    _IOWR(0xB8, 82, struct rpmb_ioc_reqresp_cmd)
#define RPMB_IOC_COUNTER_CMD _IOWR(0xB8, 84, struct rpmb_ioc_reqresp_cmd)
#define RPMB_IOC_WBLOCKS_CMD _IOWR(0xB8, 85, struct rpmb_ioc_reqresp_cmd)
#define RPMB_IOC_RBLOCKS_CMD _IOR(0xB8, 86, struct rpmb_ioc_rblocks_cmd)

#endif /* _UAPI_LINUX_RPMB_H_ */
