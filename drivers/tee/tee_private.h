/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef TEE_PRIVATE_H
#define TEE_PRIVATE_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/kref.h>

struct tee_device;

struct tee_shm {
	struct list_head list_node;
	struct tee_device *teedev;
	phys_addr_t paddr;
	void *kaddr;
	size_t size;
	struct dma_buf *dmabuf;
	u32 flags;
};

struct tee_shm_pool_mgr;
struct tee_shm_pool_mgr_ops {
	int (*alloc)(struct tee_shm_pool_mgr *poolmgr, struct tee_shm *shm,
		     size_t size);
	void (*free)(struct tee_shm_pool_mgr *poolmgr, struct tee_shm *shm);
};

struct tee_shm_pool_mgr {
	const struct tee_shm_pool_mgr_ops *ops;
	void *private_data;
};

struct tee_shm_pool {
	struct tee_shm_pool_mgr private_mgr;
	struct tee_shm_pool_mgr dma_buf_mgr;
	void (*destroy)(struct tee_shm_pool *pool);
	void *private_data;
};

#define TEE_DEVICE_FLAG_REGISTERED	0x1
#define TEE_MAX_DEV_NAME_LEN		32

struct tee_device {
	char name[TEE_MAX_DEV_NAME_LEN];
	const struct tee_desc *desc;
	int id;
	unsigned flags;

	struct device dev;
	struct cdev cdev;

	size_t num_users;
	struct completion c_no_users;
	struct mutex mutex;

	struct list_head list_shm;
	struct tee_shm_pool *pool;
};

int tee_shm_init(void);

bool tee_device_get(struct tee_device *teedev);
void tee_device_put(struct tee_device *teedev);

#endif /*TEE_PRIVATE_H*/
