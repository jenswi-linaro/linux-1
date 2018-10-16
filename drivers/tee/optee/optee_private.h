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

#ifndef OPTEE_PRIVATE_H
#define OPTEE_PRIVATE_H

#include <linux/arm-smccc.h>
#include <linux/semaphore.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include "optee_msg.h"
#include "optee_spci.h"

#define OPTEE_MAX_ARG_SIZE	1024

/* Some Global Platform error codes used in this driver */
#define TEEC_SUCCESS			0x00000000
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C

#define TEEC_ORIGIN_COMMS		0x00000002

typedef void (optee_invoke_fn)(unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long,
				struct arm_smccc_res *);

struct optee_call_queue {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head waiters;
};

struct optee_wait_queue {
	/* Serializes access to this struct */
	struct mutex mu;
	struct list_head db;
};

/**
 * struct optee_supp - supplicant synchronization struct
 * @ctx			the context of current connected supplicant.
 *			if !NULL the supplicant device is available for use,
 *			else busy
 * @mutex:		held while accessing content of this struct
 * @req_id:		current request id if supplicant is doing synchronous
 *			communication, else -1
 * @reqs:		queued request not yet retrieved by supplicant
 * @idr:		IDR holding all requests currently being processed
 *			by supplicant
 * @reqs_c:		completion used by supplicant when waiting for a
 *			request to be queued.
 */
struct optee_supp {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct tee_context *ctx;

	int req_id;
	struct list_head reqs;
	struct idr idr;
	struct completion reqs_c;
};

struct optee_spci_data {
	int sp_handle;
	/* Serializes access to idr */
	struct mutex mutex;
	struct idr idr;
};

/**
 * struct optee - main service struct
 * @supp_teedev:	supplicant device
 * @teedev:		client device
 * @invoke_fn:		function to issue smc or hvc
 * @call_queue:		queue of threads waiting to call @invoke_fn
 * @wait_queue:		queue of threads from secure world waiting for a
 *			secure world sync object
 * @supp:		supplicant synchronization struct for RPC to supplicant
 * @pool:		shared memory pool
 * @memremaped_shm	virtual address of memory in shared memory pool
 * @sec_caps:		secure world capabilities defined by
 *			OPTEE_SMC_SEC_CAP_* in optee_smc.h
 */
struct optee {
	struct tee_device *supp_teedev;
	struct tee_device *teedev;
	optee_invoke_fn *invoke_fn;
	struct optee_call_queue call_queue;
	struct optee_wait_queue wait_queue;
	struct optee_supp supp;
	struct tee_shm_pool *pool;
	void *memremaped_shm;
	u32 sec_caps;
	struct optee_spci_data spci;
};

struct optee_session {
	struct list_head list_node;
	u32 session_id;
};

struct optee_context_data {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head sess_list;
};

struct optee_rpc_param {
	u32	a0;
	u32	a1;
	u32	a2;
	u32	a3;
	u32	a4;
	u32	a5;
	u32	a6;
	u32	a7;
};

/* Holds context that is preserved during one STD call */
struct optee_call_ctx {
	/* information about pages list used in last allocation */
	void *pages_list;
	size_t num_entries;
};

void optee_handle_rpc(struct tee_context *ctx, struct optee_rpc_param *param,
		      struct optee_call_ctx *call_ctx);
void optee_rpc_finalize_call(struct optee_call_ctx *call_ctx);

u32 optee_spci_handle_rpc(struct tee_context *ctx, u32 cmd, u_int num_params,
			  struct optee_spci_param *params);

void optee_wait_queue_init(struct optee_wait_queue *wq);
void optee_wait_queue_exit(struct optee_wait_queue *wq);

u32 optee_supp_thrd_req(struct tee_context *ctx, u32 func, size_t num_params,
			struct tee_param *param);

int optee_supp_read(struct tee_context *ctx, void __user *buf, size_t len);
int optee_supp_write(struct tee_context *ctx, void __user *buf, size_t len);
void optee_supp_init(struct optee_supp *supp);
void optee_supp_uninit(struct optee_supp *supp);
void optee_supp_release(struct optee_supp *supp);

u32 optee_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg);
int optee_close_session_helper(struct tee_context *ctx, u32 session);

void optee_enable_shm_cache(struct optee *optee);
void optee_disable_shm_cache(struct optee *optee);

int optee_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct optee_msg_param *msg_params);
int optee_to_msg_param(struct optee_msg_param *msg_params, size_t num_params,
		       const struct tee_param *params);

int optee_from_spci_param(struct tee_context *ctx, struct tee_param *params,
			  size_t num_params,
			  const struct optee_spci_param *spci_params);
int optee_to_spci_param(struct optee_spci_param *spci_params, size_t num_params,
			const struct tee_param *params);

u64 *optee_allocate_pages_list(size_t num_entries);
void optee_free_pages_list(void *array, size_t num_entries);
void optee_fill_pages_list(u64 *dst, struct page **pages, int num_pages,
			   size_t page_offset);

/*
 * Functions to use in the struct tee_driver_ops. There's one group of
 * functions for each set of ops:
 * - client + legacy
 * - supplicant + legacy
 * - client + spci
 * - supplicant + spci
 *
 * Where client is for devices that serves a client, supplicant for devices
 * that serves a supplicant (user space helper process).
 *
 * Legacy is the original way of communicating with OP-TEE. SPCI (security
 * partition client interface) is a way of communicating with OP-TEE for
 * ARMv8.
 */

/* client + legacy ops */
int optee_shm_register(struct tee_context *ctx, struct tee_shm *shm,
		       struct page **pages, size_t num_pages,
		       unsigned long start);
int optee_shm_unregister(struct tee_context *ctx, struct tee_shm *shm);
int optee_close_session(struct tee_context *ctx, u32 session);
int optee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param);
int optee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session);
int optee_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param);

/* supplicant + legacy ops */
int optee_shm_register_supp(struct tee_context *ctx, struct tee_shm *shm,
			    struct page **pages, size_t num_pages,
			    unsigned long start);
int optee_shm_unregister_supp(struct tee_context *ctx, struct tee_shm *shm);
int optee_supp_recv(struct tee_context *ctx, u32 *func, u32 *num_params,
		    struct tee_param *param);
int optee_supp_send(struct tee_context *ctx, u32 ret, u32 num_params,
		    struct tee_param *param);

/* client + spci ops */
int optee_spci_shm_register(struct tee_context *ctx, struct tee_shm *shm,
			    struct page **pages, size_t num_pages,
			    unsigned long start);
int optee_spci_shm_unregister(struct tee_context *ctx, struct tee_shm *shm);
int optee_spci_close_session(struct tee_context *ctx, u32 session);
int optee_spci_close_session_helper(struct tee_context *ctx, u32 session);
int optee_spci_invoke_func(struct tee_context *ctx,
			   struct tee_ioctl_invoke_arg *arg,
			   struct tee_param *param);
int optee_spci_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session);
int optee_spci_open_session(struct tee_context *ctx,
			    struct tee_ioctl_open_session_arg *arg,
			    struct tee_param *param);

struct tee_shm *optee_spci_find_from_handle(struct tee_context *ctx,
					    u_long spci_handle);

/* supplicant + spci ops */
int optee_spci_shm_register_supp(struct tee_context *ctx, struct tee_shm *shm,
				 struct page **pages, size_t num_pages,
				 unsigned long start);
int optee_spci_shm_unregister_supp(struct tee_context *ctx, struct tee_shm *shm);
int optee_supp_spci_recv(struct tee_context *ctx, u32 *func, u32 *num_params,
			 struct tee_param *param);
int optee_supp_spci_send(struct tee_context *ctx, u32 ret, u32 num_params,
			 struct tee_param *param);


/*
 * Small helpers
 */

static inline u64 reg_pair_to_64(u32 reg0, u32 reg1)
{
	return (((u64)reg0 << 32) | reg1);
}

static inline void *reg_pair_to_ptr(u32 reg0, u32 reg1)
{
	return (void *)(unsigned long)reg_pair_to_64(reg0, reg1);
}

static inline void reg_pair_from_64(u32 *reg0, u32 *reg1, u64 val)
{
	*reg0 = val >> 32;
	*reg1 = val;
}

#endif /*OPTEE_PRIVATE_H*/
