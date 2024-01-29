// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2015 - 2019 Intel Corporation. All rights reserved.
 * Copyright(c) 2021 - 2022 Linaro Ltd.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/slab.h>

#include <linux/rpmb.h>

static DEFINE_IDA(rpmb_ida);

/**
 * rpmb_dev_get() - increase rpmb device ref counter
 * @rdev: rpmb device
 */
struct rpmb_dev *rpmb_dev_get(struct rpmb_dev *rdev)
{
	if (rdev)
		get_device(&rdev->dev);
	return rdev;
}
EXPORT_SYMBOL_GPL(rpmb_dev_get);

/**
 * rpmb_dev_put() - decrease rpmb device ref counter
 * @rdev: rpmb device
 */
void rpmb_dev_put(struct rpmb_dev *rdev)
{
	if (rdev)
		put_device(&rdev->dev);
}
EXPORT_SYMBOL_GPL(rpmb_dev_put);

/**
 * rpmb_route_frames() - route rpmb frames to rpmb device
 * @rdev:	rpmb device
 * @req:	rpmb request frames
 * @req_len:	length of rpmb request frames in bytes
 * @rsp:	rpmb response frames
 * @rsp_len:	length of rpmb response frames in bytes
 *
 * @return < 0 on failure
 */
int rpmb_route_frames(struct rpmb_dev *rdev, u8 *req,
		      unsigned int req_len, u8 *rsp, unsigned int rsp_len)
{
	struct rpmb_frame *frm = (struct rpmb_frame *)req;
	u16 req_type;
	bool write;

	if (!req || req_len < sizeof(*frm) || !rsp || !rsp_len)
		return -EINVAL;

	req_type = be16_to_cpu(frm->req_resp);
	switch (req_type) {
	case RPMB_PROGRAM_KEY:
		if (req_len != sizeof(struct rpmb_frame) ||
		    rsp_len != sizeof(struct rpmb_frame))
			return -EINVAL;
		write = true;
		break;
	case RPMB_GET_WRITE_COUNTER:
		if (req_len != sizeof(struct rpmb_frame) ||
		    rsp_len != sizeof(struct rpmb_frame))
			return -EINVAL;
		write = false;
		break;
	case RPMB_WRITE_DATA:
		if (req_len % sizeof(struct rpmb_frame) ||
		    rsp_len != sizeof(struct rpmb_frame))
			return -EINVAL;
		write = true;
		break;
	case RPMB_READ_DATA:
		if (req_len != sizeof(struct rpmb_frame) ||
		    rsp_len % sizeof(struct rpmb_frame))
			return -EINVAL;
		write = false;
		break;
	default:
		return -EINVAL;
	}

	return rdev->ops->route_frames(rdev->dev.parent, write,
				       req, req_len, rsp, rsp_len);
}
EXPORT_SYMBOL_GPL(rpmb_route_frames);

static void rpmb_dev_release(struct device *dev)
{
	struct rpmb_dev *rdev = to_rpmb_dev(dev);

	rdev->ops->put_resources(rdev->dev.parent);
	ida_simple_remove(&rpmb_ida, rdev->id);
	kfree(rdev->dev_id);
	kfree(rdev);
}

struct class rpmb_class = {
	.name = "rpmb",
	.dev_release = rpmb_dev_release,
};
EXPORT_SYMBOL(rpmb_class);

/**
 * rpmb_dev_find_device() - return first matching rpmb device
 * @data: data for the match function
 * @match: the matching function
 *
 * @returns a matching rpmb device or NULL on failure
 */
struct rpmb_dev *rpmb_dev_find_device(const void *data,
				      const struct rpmb_dev *start,
				      int (*match)(struct device *dev,
						   const void *data))
{
	struct device *dev;
	const struct device *start_dev = NULL;

	if (start)
		start_dev = &start->dev;
	dev = class_find_device(&rpmb_class, start_dev, data, match);

	return dev ? to_rpmb_dev(dev) : NULL;
}

/**
 * rpmb_dev_unregister() - unregister RPMB partition from the RPMB subsystem
 * @rdev: the rpmb device to unregister
 *
 * @returns < 0 on failure
 */
int rpmb_dev_unregister(struct rpmb_dev *rdev)
{
	if (!rdev)
		return -EINVAL;

	device_del(&rdev->dev);

	rpmb_dev_put(rdev);

	return 0;
}
EXPORT_SYMBOL_GPL(rpmb_dev_unregister);

/**
 * rpmb_dev_register - register RPMB partition with the RPMB subsystem
 * @dev: storage device of the rpmb device
 * @target: RPMB target/region within the physical device
 * @ops: device specific operations
 *
 * While registering the RPMB partition get references to needed resources
 * with the @ops->get_resources() callback and extracts needed devices
 * information while needed resources are available.
 *
 * @returns a pointer to a 'struct rpmb_dev' or an ERR_PTR on failure
 */
struct rpmb_dev *rpmb_dev_register(struct device *dev,
				   const struct rpmb_ops *ops)
{
	struct rpmb_dev *rdev;
	int id;
	int ret;

	if (!dev || !ops || !ops->get_resources ||
	    !ops->put_resources || !ops->route_frames ||
	    !ops->set_dev_info)
		return ERR_PTR(-EINVAL);

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return ERR_PTR(-ENOMEM);

	id = ida_simple_get(&rpmb_ida, 0, 0, GFP_KERNEL);
	if (id < 0) {
		ret = id;
		goto exit;
	}

	rdev->ops = ops;
	rdev->id = id;

	dev_set_name(&rdev->dev, "rpmb%d", id);
	rdev->dev.class = &rpmb_class;
	rdev->dev.parent = dev;

	ret = ops->set_dev_info(dev, rdev);
	if (ret)
		goto exit;

	ret = device_register(&rdev->dev);
	if (ret)
		goto exit;

	ops->get_resources(rdev->dev.parent);

	dev_dbg(&rdev->dev, "registered device\n");

	return rdev;

exit:
	if (id >= 0)
		ida_simple_remove(&rpmb_ida, id);
	kfree(rdev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(rpmb_dev_register);

static int __init rpmb_init(void)
{
	int rc;

	rc = class_register(&rpmb_class);
	if (rc) {
		pr_err("couldn't create class\n");
		return rc;
	}
	ida_init(&rpmb_ida);
	return 0;
}

static void __exit rpmb_exit(void)
{
	ida_destroy(&rpmb_ida);
	class_unregister(&rpmb_class);
}

subsys_initcall(rpmb_init);
module_exit(rpmb_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("RPMB class");
MODULE_LICENSE("GPL");
