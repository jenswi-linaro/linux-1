/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Intel Corp. All rights reserved
 * Copyright (C) 2021-2022 Linaro Ltd
 */
#ifndef __RPMB_H__
#define __RPMB_H__

#include <linux/types.h>
#include <linux/device.h>
#include <linux/kref.h>

/**
 * struct rpmb_ops - RPMB ops to be implemented by underlying block device
 *
 * @program_key    : program device key (once only op).
 * @get_capacity   : rpmb size in 128K units in for region/target.
 * @get_write_count: return the device write counter
 * @write_blocks   : write blocks to RPMB device
 * @read_blocks    : read blocks from RPMB device
 * @block_size     : block size in half sectors (1 == 256B)
 * @wr_cnt_max     : maximal number of blocks that can be
 *                   written in one access.
 * @rd_cnt_max     : maximal number of blocks that can be
 *                   read in one access.
 * @dev_id         : unique device identifier
 * @dev_id_len     : unique device identifier length
 */
struct rpmb_ops {
	int (*program_key)(struct device *dev, u8 target,
			   int keylen, u8 *key_frame,
			   int rlen, u8 *resp);
	int (*get_capacity)(struct device *dev, u8 target);
	int (*get_write_count)(struct device *dev, u8 target,
			       int len, u8 *requests,
			       int rlen, u8 *resp);
	int (*write_blocks)(struct device *dev, u8 target,
			    int len, u8 *requests,
			    int rlen, u8 *resp);
	int (*read_blocks)(struct device *dev, u8 target,
			   int addr, int count,
			   int len, u8 *data);
	u16 block_size;
	u16 wr_cnt_max;
	u16 rd_cnt_max;
	const u8 *dev_id;
	size_t dev_id_len;
};

/**
 * struct rpmb_dev - device which can support RPMB partition
 *
 * @lock       : the device lock
 * @dev        : device
 * @id         : device id
 * @target     : RPMB target/region within the physical device
 * @ops        : operation exported by rpmb
 */
struct rpmb_dev {
	struct mutex lock; /* device serialization lock */
	struct device dev;
	int id;
	u8 target;
	const struct rpmb_ops *ops;
};

#define to_rpmb_dev(x) container_of((x), struct rpmb_dev, dev)

#if IS_ENABLED(CONFIG_RPMB)
struct rpmb_dev *rpmb_dev_get(struct rpmb_dev *rdev);
void rpmb_dev_put(struct rpmb_dev *rdev);
struct rpmb_dev *rpmb_dev_find_by_device(struct device *parent, u8 target);
struct rpmb_dev *rpmb_dev_get_by_type(u32 type);
struct rpmb_dev *rpmb_dev_register(struct device *dev, u8 target,
				   const struct rpmb_ops *ops);
void *rpmb_dev_get_drvdata(const struct rpmb_dev *rdev);
void rpmb_dev_set_drvdata(struct rpmb_dev *rdev, void *data);
int rpmb_dev_unregister(struct rpmb_dev *rdev);
int rpmb_dev_unregister_by_device(struct device *dev, u8 target);

int rpmb_program_key(struct rpmb_dev *rdev,
		     int klen, u8 *key, int rlen, u8 *resp);
int rpmb_get_capacity(struct rpmb_dev *rdev);
int rpmb_get_write_count(struct rpmb_dev *rdev,
			 int len, u8 *request, int rlen, u8 *resp);
int rpmb_write_blocks(struct rpmb_dev *rdev,
		      int len, u8 *request, int rlen, u8 *resp);
int rpmb_read_blocks(struct rpmb_dev *rdev, int addr, int count, int len, u8 *data);

#else
static inline struct rpmb_dev *rpmb_dev_get(struct rpmb_dev *rdev)
{
	return NULL;
}

static inline void rpmb_dev_put(struct rpmb_dev *rdev) { }

static inline struct rpmb_dev *rpmb_dev_find_by_device(struct device *parent,
						       u8 target)
{
	return NULL;
}

static inline
struct rpmb_dev *rpmb_dev_get_by_type(enum rpmb_type type)
{
	return NULL;
}

static inline void *rpmb_dev_get_drvdata(const struct rpmb_dev *rdev)
{
	return NULL;
}

static inline void rpmb_dev_set_drvdata(struct rpmb_dev *rdev, void *data)
{
}

static inline struct rpmb_dev *
rpmb_dev_register(struct device *dev, u8 target, const struct rpmb_ops *ops)
{
	return NULL;
}

static inline int rpmb_dev_unregister(struct rpmb_dev *dev)
{
	return 0;
}

static inline int rpmb_dev_unregister_by_device(struct device *dev, u8 target)
{
	return 0;
}

static inline int rpmb_program_key(struct rpmb_dev *rdev,
				   int klen, u8 *key,
				   int rlen, u8 *resp)
{
	return 0;
}

static inline rpmb_set_key(struct rpmb_dev *rdev, u8 *key, int keylen);
{
	return 0;
}

static inline int rpmb_get_capacity(struct rpmb_dev *rdev)
{
	return 0;
}

static inline int rpmb_get_write_count(struct rpmb_dev *rdev,
				       int len, u8 *request, int rlen, u8 *resp)
{
	return 0;
}

static inline int rpmb_write_blocks(struct rpmb_dev *rdev,
				    int len, u8 *request, int rlen, u8 *resp);
{
	return 0;
}

static inline int rpmb_read_blocks(struct rpmb_dev *rdev, int addr, int count,
				   int len, u8 *data)
{
	return 0;
}

#endif /* CONFIG_RPMB */

#endif /* __RPMB_H__ */
