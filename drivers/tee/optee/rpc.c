// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2021, Linaro Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/rpmb.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include "optee_private.h"
#include "optee_rpc_cmd.h"

static void handle_rpc_func_cmd_get_time(struct optee_msg_arg *arg)
{
	struct timespec64 ts;

	if (arg->num_params != 1)
		goto bad;
	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT)
		goto bad;

	ktime_get_real_ts64(&ts);
	arg->params[0].u.value.a = ts.tv_sec;
	arg->params[0].u.value.b = ts.tv_nsec;

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

#if IS_REACHABLE(CONFIG_I2C)
static void handle_rpc_func_cmd_i2c_transfer(struct tee_context *ctx,
					     struct optee_msg_arg *arg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct tee_param *params;
	struct i2c_adapter *adapter;
	struct i2c_msg msg = { };
	size_t i;
	int ret = -EOPNOTSUPP;
	u8 attr[] = {
		TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT,
		TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT,
		TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT,
		TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT,
	};

	if (arg->num_params != ARRAY_SIZE(attr)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	params = kmalloc_array(arg->num_params, sizeof(struct tee_param),
			       GFP_KERNEL);
	if (!params) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	if (optee->ops->from_msg_param(optee, params, arg->num_params,
				       arg->params))
		goto bad;

	for (i = 0; i < arg->num_params; i++) {
		if (params[i].attr != attr[i])
			goto bad;
	}

	adapter = i2c_get_adapter(params[0].u.value.b);
	if (!adapter)
		goto bad;

	if (params[1].u.value.a & OPTEE_RPC_I2C_FLAGS_TEN_BIT) {
		if (!i2c_check_functionality(adapter,
					     I2C_FUNC_10BIT_ADDR)) {
			i2c_put_adapter(adapter);
			goto bad;
		}

		msg.flags = I2C_M_TEN;
	}

	msg.addr = params[0].u.value.c;
	msg.buf  = params[2].u.memref.shm->kaddr;
	msg.len  = params[2].u.memref.size;

	switch (params[0].u.value.a) {
	case OPTEE_RPC_I2C_TRANSFER_RD:
		msg.flags |= I2C_M_RD;
		break;
	case OPTEE_RPC_I2C_TRANSFER_WR:
		break;
	default:
		i2c_put_adapter(adapter);
		goto bad;
	}

	ret = i2c_transfer(adapter, &msg, 1);

	if (ret < 0) {
		arg->ret = TEEC_ERROR_COMMUNICATION;
	} else {
		params[3].u.value.a = msg.len;
		if (optee->ops->to_msg_param(optee, arg->params,
					     arg->num_params, params))
			arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		else
			arg->ret = TEEC_SUCCESS;
	}

	i2c_put_adapter(adapter);
	kfree(params);
	return;
bad:
	kfree(params);
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}
#else
static void handle_rpc_func_cmd_i2c_transfer(struct tee_context *ctx,
					     struct optee_msg_arg *arg)
{
	arg->ret = TEEC_ERROR_NOT_SUPPORTED;
}
#endif

static void handle_rpc_func_cmd_wq(struct optee *optee,
				   struct optee_msg_arg *arg)
{
	if (arg->num_params != 1)
		goto bad;

	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	switch (arg->params[0].u.value.a) {
	case OPTEE_RPC_NOTIFICATION_WAIT:
		if (optee_notif_wait(optee, arg->params[0].u.value.b))
			goto bad;
		break;
	case OPTEE_RPC_NOTIFICATION_SEND:
		if (optee_notif_send(optee, arg->params[0].u.value.b))
			goto bad;
		break;
	default:
		goto bad;
	}

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_wait(struct optee_msg_arg *arg)
{
	u32 msec_to_wait;

	if (arg->num_params != 1)
		goto bad;

	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	msec_to_wait = arg->params[0].u.value.a;

	/* Go to interruptible sleep */
	msleep_interruptible(msec_to_wait);

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_supp_cmd(struct tee_context *ctx, struct optee *optee,
				struct optee_msg_arg *arg)
{
	struct tee_param *params;

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	params = kmalloc_array(arg->num_params, sizeof(struct tee_param),
			       GFP_KERNEL);
	if (!params) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	if (optee->ops->from_msg_param(optee, params, arg->num_params,
				       arg->params)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	arg->ret = optee_supp_thrd_req(ctx, arg->cmd, arg->num_params, params);

	if (optee->ops->to_msg_param(optee, arg->params, arg->num_params,
				     params))
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
out:
	kfree(params);
}

struct tee_shm *optee_rpc_cmd_alloc_suppl(struct tee_context *ctx, size_t sz)
{
	u32 ret;
	struct tee_param param;
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct tee_shm *shm;

	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	param.u.value.a = OPTEE_RPC_SHM_TYPE_APPL;
	param.u.value.b = sz;
	param.u.value.c = 0;

	ret = optee_supp_thrd_req(ctx, OPTEE_RPC_CMD_SHM_ALLOC, 1, &param);
	if (ret)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&optee->supp.mutex);
	/* Increases count as secure world doesn't have a reference */
	shm = tee_shm_get_from_id(optee->supp.ctx, param.u.value.c);
	mutex_unlock(&optee->supp.mutex);
	return shm;
}

void optee_rpc_cmd_free_suppl(struct tee_context *ctx, struct tee_shm *shm)
{
	struct tee_param param;

	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	param.u.value.a = OPTEE_RPC_SHM_TYPE_APPL;
	param.u.value.b = tee_shm_get_id(shm);
	param.u.value.c = 0;

	/*
	 * Match the tee_shm_get_from_id() in cmd_alloc_suppl() as secure
	 * world has released its reference.
	 *
	 * It's better to do this before sending the request to supplicant
	 * as we'd like to let the process doing the initial allocation to
	 * do release the last reference too in order to avoid stacking
	 * many pending fput() on the client process. This could otherwise
	 * happen if secure world does many allocate and free in a single
	 * invoke.
	 */
	tee_shm_put(shm);

	optee_supp_thrd_req(ctx, OPTEE_RPC_CMD_SHM_FREE, 1, &param);
}

static void handle_rpc_func_rpmb_probe_reset(struct tee_context *ctx,
					     struct optee *optee,
					     struct optee_msg_arg *arg)
{
	struct tee_param params[1];

	if (!IS_ENABLED(CONFIG_RPMB)) {
		handle_rpc_supp_cmd(ctx, optee, arg);
		return;
	}

	if (arg->num_params != ARRAY_SIZE(params) ||
	    optee->ops->from_msg_param(optee, params, arg->num_params,
				       arg->params) ||
	    params[0].attr != TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	params[0].u.value.a = OPTEE_RPC_SHM_TYPE_KERNEL;
	params[0].u.value.b = 0;
	params[0].u.value.c = 0;
	if (optee->ops->to_msg_param(optee, arg->params,
				     arg->num_params, params)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	mutex_lock(&optee->rpmb_dev_mutex);
	rpmb_dev_put(optee->rpmb_dev);
	optee->rpmb_dev = NULL;
	mutex_unlock(&optee->rpmb_dev_mutex);

	arg->ret = TEEC_SUCCESS;
}

static int rpc_rpmb_match(struct device *dev, const void *data)
{
	return 1;
}

static void handle_rpc_func_rpmb_probe_next(struct tee_context *ctx,
					    struct optee *optee,
					    struct optee_msg_arg *arg)
{
	struct rpmb_dev *start_rdev;
	struct rpmb_dev *rdev;
	struct tee_param params[2];
	void *buf;

	if (!IS_ENABLED(CONFIG_RPMB)) {
		handle_rpc_supp_cmd(ctx, optee, arg);
		return;
	}

	if (arg->num_params != ARRAY_SIZE(params) ||
	    optee->ops->from_msg_param(optee, params, arg->num_params,
				       arg->params) ||
	    params[0].attr != TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT ||
	    params[1].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}
	buf = tee_shm_get_va(params[1].u.memref.shm,
			     params[1].u.memref.shm_offs);
	if (!buf) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	mutex_lock(&optee->rpmb_dev_mutex);
	start_rdev = optee->rpmb_dev;
	rdev = rpmb_dev_find_device(NULL, start_rdev, rpc_rpmb_match);
	rpmb_dev_put(start_rdev);
	optee->rpmb_dev = rdev;
	mutex_unlock(&optee->rpmb_dev_mutex);

	if (!rdev) {
		arg->ret = TEEC_ERROR_ITEM_NOT_FOUND;
		return;
	}

	if (params[1].u.memref.size < rdev->dev_id_len) {
		arg->ret = TEEC_ERROR_SHORT_BUFFER;
		return;
	}
	memcpy(buf, rdev->dev_id, rdev->dev_id_len);
	params[1].u.memref.size = rdev->dev_id_len;
	params[0].u.value.a = OPTEE_RPC_RPMB_EMMC;
	params[0].u.value.b = rdev->capacity;
	params[0].u.value.c = rdev->reliable_wr_count;
	if (optee->ops->to_msg_param(optee, arg->params,
				     arg->num_params, params)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	arg->ret = TEEC_SUCCESS;
}


/* Request */
struct rpmb_req { // TODO get rid of this
	uint16_t cmd;
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01
	uint16_t dev_id;
	uint16_t block_count;
	/* Optional data frames (rpmb_data_frame) follow */
};
#define RPMB_REQ_DATA(req) ((void *)((struct rpmb_req *)(req) + 1))

#define RPMB_CID_SZ 16

/* Response to device info request */
struct rpmb_dev_info {
	uint8_t cid[RPMB_CID_SZ];
	uint8_t rpmb_size_mult;	/* EXT CSD-slice 168: RPMB Size */
	uint8_t rel_wr_sec_c;	/* EXT CSD-slice 222: Reliable Write Sector */
				/*                    Count */
	uint8_t ret_code;
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01
};

static int get_dev_info(struct rpmb_dev *rdev, void *rsp, size_t rsp_size)
{
	struct rpmb_dev_info *dev_info;

	if (rsp_size != sizeof(*dev_info))
		return TEEC_ERROR_BAD_PARAMETERS;

	dev_info = rsp;
	memcpy(dev_info->cid, rdev->dev_id, sizeof(dev_info->cid));
	dev_info->rpmb_size_mult = rdev->capacity;
	dev_info->rel_wr_sec_c = rdev->reliable_wr_count;
	dev_info->ret_code = RPMB_CMD_GET_DEV_INFO_RET_OK;

	return TEEC_SUCCESS;
}

/*
 * req is one struct rpmb_req followed by one or more struct rpmb_data_frame
 * rsp is either one struct rpmb_dev_info or one or more struct rpmb_data_frame
 */
static u32 rpmb_process_request(struct optee *optee, struct rpmb_dev *rdev,
				void *req, size_t req_size,
				void *rsp, size_t rsp_size)
{
	struct rpmb_req *sreq = req;
	int rc;

	if (req_size < sizeof(*sreq))
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (sreq->cmd) {
	case RPMB_CMD_DATA_REQ:
		rc = rpmb_route_frames(rdev, RPMB_REQ_DATA(req),
				       req_size - sizeof(struct rpmb_req),
				       rsp, rsp_size);
		if (rc) // TODO translate error code
			return TEEC_ERROR_BAD_PARAMETERS;
		return TEEC_SUCCESS;
	case RPMB_CMD_GET_DEV_INFO:
		return get_dev_info(rdev, rsp, rsp_size);
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
}


static void handle_rpc_func_rpmb(struct tee_context *ctx, struct optee *optee,
				 struct optee_msg_arg *arg)
{
	struct tee_param params[2];
	struct rpmb_dev *rdev;
	void *p0, *p1;


	mutex_lock(&optee->rpmb_dev_mutex);
	rdev = rpmb_dev_get(optee->rpmb_dev);
	mutex_unlock(&optee->rpmb_dev_mutex);
	if (!rdev) {
		handle_rpc_supp_cmd(ctx, optee, arg);
		return;
	}

	if (arg->num_params != ARRAY_SIZE(params) ||
	    optee->ops->from_msg_param(optee, params, arg->num_params,
				       arg->params) ||
	    params[0].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    params[1].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	p0 = tee_shm_get_va(params[0].u.memref.shm,
			    params[0].u.memref.shm_offs);
	p1 = tee_shm_get_va(params[1].u.memref.shm,
			    params[1].u.memref.shm_offs);
	arg->ret = rpmb_process_request(optee, rdev, p0,
					params[0].u.memref.size,
					p1, params[1].u.memref.size);
	if (arg->ret)
		goto out;

	if (optee->ops->to_msg_param(optee, arg->params,
				     arg->num_params, params))
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
out:
	rpmb_dev_put(rdev);
}

void optee_rpc_cmd(struct tee_context *ctx, struct optee *optee,
		   struct optee_msg_arg *arg)
{
	switch (arg->cmd) {
	case OPTEE_RPC_CMD_GET_TIME:
		handle_rpc_func_cmd_get_time(arg);
		break;
	case OPTEE_RPC_CMD_NOTIFICATION:
		handle_rpc_func_cmd_wq(optee, arg);
		break;
	case OPTEE_RPC_CMD_SUSPEND:
		handle_rpc_func_cmd_wait(arg);
		break;
	case OPTEE_RPC_CMD_I2C_TRANSFER:
		handle_rpc_func_cmd_i2c_transfer(ctx, arg);
		break;
	case OPTEE_RPC_CMD_RPMB_PROBE_RESET:
		handle_rpc_func_rpmb_probe_reset(ctx, optee, arg);
		break;
	case OPTEE_RPC_CMD_RPMB_PROBE_NEXT:
		handle_rpc_func_rpmb_probe_next(ctx, optee, arg);
		break;
	case OPTEE_RPC_CMD_RPMB:
		handle_rpc_func_rpmb(ctx, optee, arg);
		break;
	default:
		handle_rpc_supp_cmd(ctx, optee, arg);
	}
}


