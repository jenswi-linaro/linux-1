// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio RPMB Front End Driver
 *
 * Copyright (c) 2018-2019 Intel Corporation.
 * Copyright (c) 2021-2022 Linaro Ltd.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/module.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_rpmb.h>
#include <linux/uaccess.h>
#include <linux/byteorder/generic.h>
#include <linux/rpmb.h>

#define RPMB_MAC_SIZE 32
#define VIRTIO_RPMB_FRAME_SZ 512

static const char id[] = "RPMB:VIRTIO";

struct virtio_rpmb_info {
	/* The virtio device we're associated with */
	struct virtio_device *vdev;

	/* The virtq we use */
	struct virtqueue *vq;

	struct mutex lock; /* info lock */
	wait_queue_head_t have_data;

	/* Underlying RPMB device */
	struct rpmb_dev *rdev;

	/* Config values */
	u8 max_wr, max_rd, capacity;
};

/**
 * virtio_rpmb_recv_done() - vq completion callback
 */
static void virtio_rpmb_recv_done(struct virtqueue *vq)
{
	struct virtio_rpmb_info *vi;
	struct virtio_device *vdev = vq->vdev;

	vi = vq->vdev->priv;
	if (!vi) {
		dev_err(&vdev->dev, "Error: no found vi data.\n");
		return;
	}

	wake_up(&vi->have_data);
}

/**
 * do_virtio_transaction() - send sg list and wait for result
 * @dev: linux device structure
 * @vi: the device info (where the lock is)
 * @sgs: array of scatterlists
 * @out: total outgoing scatter lists
 * @in: total returning scatter lists
 *
 * This is just a simple helper for processing the sg list. It will
 * block until the response arrives. Returns number of bytes written
 * back or negative if it failed.
 */
static int do_virtio_transaction(struct device *dev,
				 struct virtio_rpmb_info *vi,
				 struct scatterlist *sgs[],
				 int out, int in)
{
	int ret, len = 0;

	mutex_lock(&vi->lock);
	ret = virtqueue_add_sgs(vi->vq, sgs, out, in, vi, GFP_KERNEL);
	if (ret) {
		dev_err(dev, "failed to send %d, recv %d sgs (%d) to vq\n",
			out, in, ret);
		ret = -1;
	} else {
		virtqueue_kick(vi->vq);
		wait_event(vi->have_data, virtqueue_get_buf(vi->vq, &len));
	}
	mutex_unlock(&vi->lock);

	return len;
}

/**
 * rpmb_virtio_program_key(): program key into virtio device
 * @dev: device handle
 * @target: target region (unused for VirtIO devices)
 * @klen: length of key programming request
 * @key_frame: key programming frames
 * @rlen: length of response buffer
 * @resp_frame: pointer to optional response frame
 *
 * Handle programming of the key (VIRTIO_RPMB_REQ_PROGRAM_KEY)
 *
 * The mandatory first frame contains the programming sequence. An
 * optional second frame may ask for the result of the operation
 * (VIRTIO_RPMB_REQ_RESULT_READ) which would trigger a response frame.
 *
 * Returns success/fail with errno and optional response frame
 */
static int rpmb_virtio_program_key(struct device *dev, u8 target,
				   int klen, u8 *key_frame, int rlen, u8 *resp_frame)
{
	struct virtio_rpmb_info *vi = dev_get_drvdata(dev);
	struct virtio_rpmb_frame *pkey = (struct virtio_rpmb_frame *) key_frame;
	struct virtio_rpmb_frame *resp = NULL;
	struct scatterlist out_frame;
	struct scatterlist in_frame;
	struct scatterlist *sgs[2] = { };
	int len;

	if (!pkey)
		return -EINVAL;

	if (be16_to_cpu(pkey->req_resp) != VIRTIO_RPMB_REQ_PROGRAM_KEY)
		return -EINVAL;

	/* validate incoming frame */
	switch (klen) {
	case VIRTIO_RPMB_FRAME_SZ:
		if (rlen || resp_frame)
			return -EINVAL;
		break;
	case VIRTIO_RPMB_FRAME_SZ * 2:
		if (!rlen || !resp_frame)
			return -EINVAL;
		if (be16_to_cpu(pkey[1].req_resp) != VIRTIO_RPMB_REQ_RESULT_READ)
			return -EINVAL;
		if (rlen < VIRTIO_RPMB_FRAME_SZ)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	/* setup outgoing frame(s) */
	sg_init_one(&out_frame, pkey, klen);
	sgs[0] = &out_frame;

	/* optional incoming frame */
	if (rlen && resp_frame) {
		resp = (struct virtio_rpmb_frame *) resp_frame;
		sg_init_one(&in_frame, resp, sizeof(*resp));
		sgs[1] = &in_frame;
	}

	len = do_virtio_transaction(dev, vi, sgs, 1, resp ? 1 : 0);

	if (len > 0 && resp) {
		if (be16_to_cpu(resp->req_resp) != VIRTIO_RPMB_RESP_PROGRAM_KEY) {
			dev_err(dev, "Bad response from device (%x/%x)",
				be16_to_cpu(resp->req_resp), be16_to_cpu(resp->result));
			return -EPROTO;
		} else {
			/* map responses to better errors? */
			return be16_to_cpu(resp->result) == VIRTIO_RPMB_RES_OK ? 0 : -EIO;
		}
	}

	/* Something must have failed at this point. */
	return len < 0 ? -EIO : 0;
}

static int rpmb_virtio_get_capacity(struct device *dev, u8 target)
{
	struct virtio_rpmb_info *vi = dev_get_drvdata(dev);
	struct virtio_device *vdev = vi->vdev;

	u8 capacity;

	virtio_cread(vdev, struct virtio_rpmb_config, capacity, &capacity);

	if (capacity > 0x80) {
		dev_err(&vdev->dev, "Error: invalid capacity reported.\n");
		capacity = 0x80;
	}

	return capacity;
}

static int rpmb_virtio_get_write_count(struct device *dev, u8 target,
				       int len, u8 *req, int rlen, u8 *resp)

{
	struct virtio_rpmb_info *vi = dev_get_drvdata(dev);
	struct virtio_rpmb_frame *request = (struct virtio_rpmb_frame *) req;
	struct virtio_rpmb_frame *response = (struct virtio_rpmb_frame *) resp;
	struct scatterlist out_frame;
	struct scatterlist in_frame;
	struct scatterlist *sgs[2];
	unsigned int received;

	if (!len || len != VIRTIO_RPMB_FRAME_SZ || !request)
		return -EINVAL;

	if (!rlen || rlen != VIRTIO_RPMB_FRAME_SZ || !resp)
		return -EINVAL;

	if (be16_to_cpu(request->req_resp) != VIRTIO_RPMB_REQ_GET_WRITE_COUNTER)
		return -EINVAL;

	/* Wrap into SG array */
	sg_init_one(&out_frame, request, VIRTIO_RPMB_FRAME_SZ);
	sg_init_one(&in_frame, response, VIRTIO_RPMB_FRAME_SZ);
	sgs[0] = &out_frame;
	sgs[1] = &in_frame;

	/* Send it, blocks until response */
	received = do_virtio_transaction(dev, vi, sgs, 1, 1);

	if (received != VIRTIO_RPMB_FRAME_SZ)
		return -EPROTO;

	if (be16_to_cpu(response->req_resp) != VIRTIO_RPMB_RESP_GET_COUNTER) {
		dev_err(dev, "failed to get counter (%x/%x)",
			be16_to_cpu(response->req_resp), be16_to_cpu(response->result));
		return -EPROTO;
	}

	return be16_to_cpu(response->result) == VIRTIO_RPMB_RES_OK ?
		be32_to_cpu(response->write_counter) : -EIO;
}

static int rpmb_virtio_write_blocks(struct device *dev, u8 target,
				    int len, u8 *req, int rlen, u8 *resp)
{
	struct virtio_rpmb_info *vi = dev_get_drvdata(dev);
	struct virtio_rpmb_frame *request = (struct virtio_rpmb_frame *) req;
	struct virtio_rpmb_frame *response = (struct virtio_rpmb_frame *) resp;
	struct scatterlist out_frame;
	struct scatterlist in_frame;
	struct scatterlist *sgs[2];
	int blocks, data_len, received;

	if (!len || (len % VIRTIO_RPMB_FRAME_SZ) != 0 || !request)
		return -EINVAL;

	/* The first frame will contain the details of the request */
	if (be16_to_cpu(request->req_resp) != VIRTIO_RPMB_REQ_DATA_WRITE)
		return -EINVAL;

	blocks = be16_to_cpu(request->block_count);
	if (blocks > vi->max_wr)
		return -EINVAL;

	/*
	 * We either have exactly enough frames to write all the data
	 * or we have that plus a frame looking for a response.
	 */
	data_len = blocks * VIRTIO_RPMB_FRAME_SZ;

	if (len == data_len + VIRTIO_RPMB_FRAME_SZ) {
		struct virtio_rpmb_frame *reply = &request[blocks];

		if (be16_to_cpu(reply->req_resp) != VIRTIO_RPMB_REQ_RESULT_READ)
			return -EINVAL;

		if (!rlen || rlen != VIRTIO_RPMB_FRAME_SZ || !resp)
			return -EINVAL;
	} else if (len > data_len) {
		return -E2BIG;
	} else if (len < data_len) {
		return -ENOSPC;
	} else if (rlen || resp) {
		return -EINVAL;
	}

	/* time to do the transaction */
	sg_init_one(&out_frame, request, len);
	sgs[0] = &out_frame;

	/* optional incoming frame */
	if (rlen && resp) {
		sg_init_one(&in_frame, resp, VIRTIO_RPMB_FRAME_SZ);
		sgs[1] = &in_frame;
	}

	received = do_virtio_transaction(dev, vi, sgs, 1, resp ? 1 : 0);

	if (response && received != VIRTIO_RPMB_FRAME_SZ)
		return -EPROTO;

	if (response && be16_to_cpu(response->req_resp) != VIRTIO_RPMB_RESP_DATA_WRITE) {
		dev_err(dev, "didn't get a response result (%x/%x)",
			be16_to_cpu(response->req_resp), be16_to_cpu(response->result));
		return -EPROTO;
	}

	return be16_to_cpu(response->result) == VIRTIO_RPMB_RES_OK ? 0 : -EIO;
}

/**
 * rpmb_virtio_read_blocks(): read blocks of data
 * @dev: device handle
 * @target: target region (unused for VirtIO devices)
 * @addr: block address to start reading from
 * @count: number of blocks to read
 * @len: length of receiving buffer
 * @data: receiving buffer
 *
 * Read a number of blocks from RPMB device. As there is no
 * authentication required to read data we construct the outgoing
 * frame in this driver.
 *
 * Returns success/fail with errno and filling in the buffer pointed
 * to by @data.
 */
static int rpmb_virtio_read_blocks(struct device *dev, u8 target,
				   int addr, int count, int len, u8 *data)
{
	struct virtio_rpmb_info *vi = dev_get_drvdata(dev);
	struct virtio_rpmb_frame *request;
	struct virtio_rpmb_frame *response = (struct virtio_rpmb_frame *) data;
	struct scatterlist out_frame;
	struct scatterlist in_frame;
	struct scatterlist *sgs[2];
	int computed_len = count * VIRTIO_RPMB_FRAME_SZ;
	int received;

	if (!count || !data)
		return -EINVAL;

	if (addr + count > vi->capacity)
		return -ESPIPE;

	if (count > vi->max_rd)
		return -EINVAL;

	/* EMSGSIZE? */
	if (len < computed_len)
		return -EFBIG;

	/*
	 * With the basics done we can construct our request.
	 */
	request = kmalloc(VIRTIO_RPMB_FRAME_SZ, GFP_KERNEL);
	if (!request)
		return -ENOMEM;

	request->req_resp = cpu_to_be16(VIRTIO_RPMB_REQ_DATA_READ);
	request->block_count = cpu_to_be16(count);
	request->address = cpu_to_be16(addr);

	/* time to do the transaction */
	sg_init_one(&out_frame, request, sizeof(*request));
	sgs[0] = &out_frame;
	sg_init_one(&in_frame, data, len);
	sgs[1] = &in_frame;

	received = do_virtio_transaction(dev, vi, sgs, 1, 1);

	kfree(request);

	if (received != computed_len)
		return -EPROTO;

	if (be16_to_cpu(response->req_resp) != VIRTIO_RPMB_RESP_DATA_READ) {
		dev_err(dev, "didn't get a response result (%x/%x)",
			be16_to_cpu(response->req_resp), be16_to_cpu(response->result));
		return -EPROTO;
	}

	return be16_to_cpu(response->result) == VIRTIO_RPMB_RES_OK ? 0 : -EIO;
}

static struct rpmb_ops rpmb_virtio_ops = {
	.program_key = rpmb_virtio_program_key,
	.get_capacity = rpmb_virtio_get_capacity,
	.get_write_count = rpmb_virtio_get_write_count,
	.write_blocks = rpmb_virtio_write_blocks,
	.read_blocks = rpmb_virtio_read_blocks,
};

static int rpmb_virtio_dev_init(struct virtio_rpmb_info *vi)
{
	struct virtio_device *vdev = vi->vdev;
	/* XXX this seems very roundabout */
	struct device *dev = &vi->vq->vdev->dev;
	int ret = 0;

	virtio_cread(vdev, struct virtio_rpmb_config,
		     max_wr_cnt, &vi->max_wr);
	virtio_cread(vdev, struct virtio_rpmb_config,
		     max_rd_cnt, &vi->max_rd);
	virtio_cread(vdev, struct virtio_rpmb_config,
		     capacity, &vi->capacity);

	rpmb_virtio_ops.dev_id_len = strlen(id);
	rpmb_virtio_ops.dev_id = id;
	rpmb_virtio_ops.wr_cnt_max = vi->max_wr;
	rpmb_virtio_ops.rd_cnt_max = vi->max_rd;
	rpmb_virtio_ops.block_size = 1;

	vi->rdev = rpmb_dev_register(dev, 0, &rpmb_virtio_ops);
	if (IS_ERR(vi->rdev)) {
		ret = PTR_ERR(vi->rdev);
		goto err;
	}

	dev_set_drvdata(dev, vi);
err:
	return ret;
}

static int virtio_rpmb_init(struct virtio_device *vdev)
{
	int ret;
	struct virtio_rpmb_info *vi;

	vi = kzalloc(sizeof(*vi), GFP_KERNEL);
	if (!vi)
		return -ENOMEM;

	init_waitqueue_head(&vi->have_data);
	mutex_init(&vi->lock);

	/* link virtio_rpmb_info to virtio_device */
	vdev->priv = vi;
	vi->vdev = vdev;

	/* We expect a single virtqueue. */
	vi->vq = virtio_find_single_vq(vdev, virtio_rpmb_recv_done, "request");
	if (IS_ERR(vi->vq)) {
		dev_err(&vdev->dev, "get single vq failed!\n");
		ret = PTR_ERR(vi->vq);
		goto err;
	}

	/* create vrpmb device. */
	ret = rpmb_virtio_dev_init(vi);
	if (ret) {
		dev_err(&vdev->dev, "create vrpmb device failed.\n");
		goto err;
	}

	dev_info(&vdev->dev, "init done!\n");

	return 0;

err:
	kfree(vi);
	return ret;
}

static void virtio_rpmb_remove(struct virtio_device *vdev)
{
	struct virtio_rpmb_info *vi;

	vi = vdev->priv;
	if (!vi)
		return;

	if (wq_has_sleeper(&vi->have_data))
		wake_up(&vi->have_data);

	rpmb_dev_unregister(vi->rdev);

	if (vdev->config->reset)
		vdev->config->reset(vdev);

	if (vdev->config->del_vqs)
		vdev->config->del_vqs(vdev);

	kfree(vi);
}

static int virtio_rpmb_probe(struct virtio_device *vdev)
{
	return virtio_rpmb_init(vdev);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_rpmb_freeze(struct virtio_device *vdev)
{
	virtio_rpmb_remove(vdev);
	return 0;
}

static int virtio_rpmb_restore(struct virtio_device *vdev)
{
	return virtio_rpmb_init(vdev);
}
#endif

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RPMB, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_rpmb_driver = {
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtio_rpmb_probe,
	.remove =	virtio_rpmb_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze =	virtio_rpmb_freeze,
	.restore =	virtio_rpmb_restore,
#endif
};

module_virtio_driver(virtio_rpmb_driver);
MODULE_DEVICE_TABLE(virtio, id_table);

MODULE_DESCRIPTION("Virtio rpmb frontend driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("Dual BSD/GPL");
