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
#include "rpmb-cdev.h"

static DEFINE_IDA(rpmb_ida);

/**
 * rpmb_dev_get() - increase rpmb device ref counter
 * @rdev: rpmb device
 */
struct rpmb_dev *rpmb_dev_get(struct rpmb_dev *rdev)
{
	return get_device(&rdev->dev) ? rdev : NULL;
}
EXPORT_SYMBOL_GPL(rpmb_dev_get);

/**
 * rpmb_dev_put() - decrease rpmb device ref counter
 * @rdev: rpmb device
 */
void rpmb_dev_put(struct rpmb_dev *rdev)
{
	put_device(&rdev->dev);
}
EXPORT_SYMBOL_GPL(rpmb_dev_put);

/**
 * rpmb_program_key() - program the RPMB access key
 * @rdev: rpmb device
 * @keylen: length of key data
 * @key: key data
 *
 * A successful programming of the key implies it has been set by the
 * driver and can be used.
 *
 * Return:
 * *        0 on success
 * *        -EINVAL on wrong parameters
 * *        -EPERM key already programmed
 * *        -EOPNOTSUPP if device doesn't support the requested operation
 * *        < 0 if the operation fails
 */
int rpmb_program_key(struct rpmb_dev *rdev, int klen, u8 *key, int rlen, u8 *resp)
{
	int err;

	if (!rdev || !key)
		return -EINVAL;

	mutex_lock(&rdev->lock);
	err = -EOPNOTSUPP;
	if (rdev->ops && rdev->ops->program_key) {
		err = rdev->ops->program_key(rdev->dev.parent, rdev->target,
					     klen, key, rlen, resp);
	}
	mutex_unlock(&rdev->lock);

	return err;
}
EXPORT_SYMBOL_GPL(rpmb_program_key);

/**
 * rpmb_get_capacity() - returns the capacity of the rpmb device
 * @rdev: rpmb device
 *
 * Return:
 * *        capacity of the device in units of 128K, on success
 * *        -EINVAL on wrong parameters
 * *        -EOPNOTSUPP if device doesn't support the requested operation
 * *        < 0 if the operation fails
 */
int rpmb_get_capacity(struct rpmb_dev *rdev)
{
	int err;

	if (!rdev)
		return -EINVAL;

	mutex_lock(&rdev->lock);
	err = -EOPNOTSUPP;
	if (rdev->ops && rdev->ops->get_capacity)
		err = rdev->ops->get_capacity(rdev->dev.parent, rdev->target);
	mutex_unlock(&rdev->lock);

	return err;
}
EXPORT_SYMBOL_GPL(rpmb_get_capacity);

/**
 * rpmb_get_write_count() - returns the write counter of the rpmb device
 * @rdev: rpmb device
 * @len: size of request frame
 * @request: request frame
 * @rlen: size of response frame
 * @resp: response frame
 *
 * Return:
 * *        counter
 * *        -EINVAL on wrong parameters
 * *        -EOPNOTSUPP if device doesn't support the requested operation
 * *        < 0 if the operation fails
 */
int rpmb_get_write_count(struct rpmb_dev *rdev, int len, u8 *request, int rlen, u8 *resp)
{
	int err;

	if (!rdev)
		return -EINVAL;

	mutex_lock(&rdev->lock);
	err = -EOPNOTSUPP;
	if (rdev->ops && rdev->ops->get_write_count)
		err = rdev->ops->get_write_count(rdev->dev.parent, rdev->target,
						 len, request, rlen, resp);
	mutex_unlock(&rdev->lock);

	return err;
}
EXPORT_SYMBOL_GPL(rpmb_get_write_count);

/**
 * rpmb_write_blocks() - write data to RPMB device
 * @rdev: rpmb device
 * @addr: block address (index of first block - 256B blocks)
 * @count: number of 256B blosks
 * @data: pointer to data to program
 *
 * Write a series of blocks to the RPMB device.
 *
 * Return:
 * *        0 on success
 * *        -EINVAL on wrong parameters
 * *        -EACCESS no key set
 * *        -EOPNOTSUPP if device doesn't support the requested operation
 * *        < 0 if the operation fails
 */
int rpmb_write_blocks(struct rpmb_dev *rdev, int len, u8 *request,
		      int rlen, u8 *response)
{
	int err;

	if (!rdev || !len || !request)
		return -EINVAL;

	mutex_lock(&rdev->lock);
	err = -EOPNOTSUPP;
	if (rdev->ops && rdev->ops->write_blocks) {
		err = rdev->ops->write_blocks(rdev->dev.parent, rdev->target,
					      len, request, rlen, response);
	}
	mutex_unlock(&rdev->lock);

	return err;
}
EXPORT_SYMBOL_GPL(rpmb_write_blocks);

/**
 * rpmb_read_blocks() - read data from RPMB device
 * @rdev: rpmb device
 * @addr: block address (index of first block - 256B blocks)
 * @count: number of 256B blocks
 * @data: pointer to data to read
 *
 * Read a series of one or more blocks from the RPMB device.
 *
 * Return:
 * *        0 on success
 * *        -EINVAL on wrong parameters
 * *        -EACCESS no key set
 * *        -EOPNOTSUPP if device doesn't support the requested operation
 * *        < 0 if the operation fails
 */
int rpmb_read_blocks(struct rpmb_dev *rdev, int addr, int count, int len, u8 *data)
{
	int err;

	if (!rdev || !count || !data)
		return -EINVAL;

	mutex_lock(&rdev->lock);
	err = -EOPNOTSUPP;
	if (rdev->ops && rdev->ops->read_blocks) {
		err = rdev->ops->read_blocks(rdev->dev.parent, rdev->target,
					     addr, count, len, data);
	}
	mutex_unlock(&rdev->lock);

	return err;
}
EXPORT_SYMBOL_GPL(rpmb_read_blocks);


static void rpmb_dev_release(struct device *dev)
{
	struct rpmb_dev *rdev = to_rpmb_dev(dev);

	ida_simple_remove(&rpmb_ida, rdev->id);
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
 * Return: matching rpmb device or NULL on failure
 */
static
struct rpmb_dev *rpmb_dev_find_device(const void *data,
				      int (*match)(struct device *dev,
						   const void *data))
{
	struct device *dev;

	dev = class_find_device(&rpmb_class, NULL, data, match);

	return dev ? to_rpmb_dev(dev) : NULL;
}

struct device_with_target {
	const struct device *dev;
	u8 target;
};

static int match_by_parent(struct device *dev, const void *data)
{
	const struct device_with_target *d = data;
	struct rpmb_dev *rdev = to_rpmb_dev(dev);

	return (d->dev && dev->parent == d->dev && rdev->target == d->target);
}

/**
 * rpmb_dev_find_by_device() - retrieve rpmb device from the parent device
 * @parent: parent device of the rpmb device
 * @target: RPMB target/region within the physical device
 *
 * Return: NULL if there is no rpmb device associated with the parent device
 */
struct rpmb_dev *rpmb_dev_find_by_device(struct device *parent, u8 target)
{
	struct device_with_target t;

	if (!parent)
		return NULL;

	t.dev = parent;
	t.target = target;

	return rpmb_dev_find_device(&t, match_by_parent);
}
EXPORT_SYMBOL_GPL(rpmb_dev_find_by_device);

/**
 * rpmb_dev_unregister() - unregister RPMB partition from the RPMB subsystem
 * @rdev: the rpmb device to unregister
 * Return:
 * *        0 on success
 * *        -EINVAL on wrong parameters
 */
int rpmb_dev_unregister(struct rpmb_dev *rdev)
{
	if (!rdev)
		return -EINVAL;

	mutex_lock(&rdev->lock);
	rpmb_cdev_del(rdev);
	device_del(&rdev->dev);
	mutex_unlock(&rdev->lock);

	rpmb_dev_put(rdev);

	return 0;
}
EXPORT_SYMBOL_GPL(rpmb_dev_unregister);

/**
 * rpmb_dev_unregister_by_device() - unregister RPMB partition
 *     from the RPMB subsystem
 * @dev: the parent device of the rpmb device
 * @target: RPMB target/region within the physical device
 * Return:
 * *        0 on success
 * *        -EINVAL on wrong parameters
 * *        -ENODEV if a device cannot be find.
 */
int rpmb_dev_unregister_by_device(struct device *dev, u8 target)
{
	struct rpmb_dev *rdev;

	if (!dev)
		return -EINVAL;

	rdev = rpmb_dev_find_by_device(dev, target);
	if (!rdev) {
		dev_warn(dev, "no disk found %s\n", dev_name(dev->parent));
		return -ENODEV;
	}

	rpmb_dev_put(rdev);

	return rpmb_dev_unregister(rdev);
}
EXPORT_SYMBOL_GPL(rpmb_dev_unregister_by_device);

/**
 * rpmb_dev_get_drvdata() - driver data getter
 * @rdev: rpmb device
 *
 * Return: driver private data
 */
void *rpmb_dev_get_drvdata(const struct rpmb_dev *rdev)
{
	return dev_get_drvdata(&rdev->dev);
}
EXPORT_SYMBOL_GPL(rpmb_dev_get_drvdata);

/**
 * rpmb_dev_set_drvdata() - driver data setter
 * @rdev: rpmb device
 * @data: data to store
 */
void rpmb_dev_set_drvdata(struct rpmb_dev *rdev, void *data)
{
	dev_set_drvdata(&rdev->dev, data);
}
EXPORT_SYMBOL_GPL(rpmb_dev_set_drvdata);

/**
 * rpmb_dev_register - register RPMB partition with the RPMB subsystem
 * @dev: storage device of the rpmb device
 * @target: RPMB target/region within the physical device
 * @ops: device specific operations
 *
 * Return: a pointer to rpmb device
 */
struct rpmb_dev *rpmb_dev_register(struct device *dev, u8 target,
				   const struct rpmb_ops *ops)
{
	struct rpmb_dev *rdev;
	int id;
	int ret;

	if (!dev || !ops)
		return ERR_PTR(-EINVAL);

	if (!ops->program_key)
		return ERR_PTR(-EINVAL);

	if (!ops->get_capacity)
		return ERR_PTR(-EINVAL);

	if (!ops->get_write_count)
		return ERR_PTR(-EINVAL);

	if (!ops->write_blocks)
		return ERR_PTR(-EINVAL);

	if (!ops->read_blocks)
		return ERR_PTR(-EINVAL);

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return ERR_PTR(-ENOMEM);

	id = ida_simple_get(&rpmb_ida, 0, 0, GFP_KERNEL);
	if (id < 0) {
		ret = id;
		goto exit;
	}

	mutex_init(&rdev->lock);
	rdev->ops = ops;
	rdev->id = id;
	rdev->target = target;

	dev_set_name(&rdev->dev, "rpmb%d", id);
	rdev->dev.class = &rpmb_class;
	rdev->dev.parent = dev;

	rpmb_cdev_prepare(rdev);

	ret = device_register(&rdev->dev);
	if (ret)
		goto exit;

	rpmb_cdev_add(rdev);

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
	ida_init(&rpmb_ida);
	class_register(&rpmb_class);
	return rpmb_cdev_init();
}

static void __exit rpmb_exit(void)
{
	rpmb_cdev_exit();
	class_unregister(&rpmb_class);
	ida_destroy(&rpmb_ida);
}

subsys_initcall(rpmb_init);
module_exit(rpmb_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("RPMB class");
MODULE_LICENSE("GPL v2");
