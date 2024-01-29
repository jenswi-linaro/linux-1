// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2015 - 2019 Intel Corporation. All rights reserved.
 * Copyright(c) 2021 - 2024 Linaro Ltd.
 */
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rpmb.h>
#include <linux/slab.h>

static struct list_head rpmb_dev_list;
static DEFINE_MUTEX(rpmb_mutex);
static struct blocking_notifier_head rpmb_interface =
	BLOCKING_NOTIFIER_INIT(rpmb_interface);

/**
 * rpmb_dev_get() - increase rpmb device ref counter
 * @rdev: rpmb device
 */
struct rpmb_dev *rpmb_dev_get(struct rpmb_dev *rdev)
{
	if (rdev)
		get_device(rdev->parent_dev);
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
		put_device(rdev->parent_dev);
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
 * Returns: < 0 on failure
 */
int rpmb_route_frames(struct rpmb_dev *rdev, u8 *req,
		      unsigned int req_len, u8 *rsp, unsigned int rsp_len)
{
	if (!req || !req_len || !rsp || !rsp_len)
		return -EINVAL;

	return rdev->descr.route_frames(rdev->parent_dev, req, req_len,
					rsp, rsp_len);
}
EXPORT_SYMBOL_GPL(rpmb_route_frames);

/**
 * rpmb_dev_find_device() - return first matching rpmb device
 * @data: data for the match function
 * @match: the matching function
 *
 * Iterate over registered RPMB devices, and call @match() for each passing
 * it the RPMB device and @data.
 *
 * The return value of @match() is checked for each call. If it returns
 * anything other 0, break and return the found RPMB device.
 *
 * It's the callers responsibility to call rpmb_dev_put() on the returned
 * device, when it's done with it.
 *
 * Returns: a matching rpmb device or NULL on failure
 */
struct rpmb_dev *rpmb_dev_find_device(const void *data,
				      const struct rpmb_dev *start,
				      int (*match)(struct rpmb_dev *rdev,
						   const void *data))
{
	struct rpmb_dev *rdev;
	struct list_head *pos;

	mutex_lock(&rpmb_mutex);
	if (start)
		pos = start->list_node.next;
	else
		pos = rpmb_dev_list.next;

	while (pos != &rpmb_dev_list) {
		rdev = container_of(pos, struct rpmb_dev, list_node);
		if (match(rdev, data)) {
			rpmb_dev_get(rdev);
			goto out;
		}
		pos = pos->next;
	}
	rdev = NULL;

out:
	mutex_unlock(&rpmb_mutex);

	return rdev;
}
EXPORT_SYMBOL_GPL(rpmb_dev_find_device);

/**
 * rpmb_dev_unregister() - unregister RPMB partition from the RPMB subsystem
 * @rdev: the rpmb device to unregister
 *
 * This function should be called from the release function of the
 * underlying device used when the RPMB device was registered.
 *
 * Returns: < 0 on failure
 */
int rpmb_dev_unregister(struct rpmb_dev *rdev)
{
	if (!rdev)
		return -EINVAL;

	mutex_lock(&rpmb_mutex);
	list_del(&rdev->list_node);
	mutex_unlock(&rpmb_mutex);
	kfree(rdev->descr.dev_id);
	kfree(rdev);

	return 0;
}
EXPORT_SYMBOL_GPL(rpmb_dev_unregister);

/**
 * rpmb_dev_register - register RPMB partition with the RPMB subsystem
 * @dev: storage device of the rpmb device
 * @ops: device specific operations
 *
 * While registering the RPMB partition extract needed device information
 * while needed resources are available.
 *
 * Returns: a pointer to a 'struct rpmb_dev' or an ERR_PTR on failure
 */
struct rpmb_dev *rpmb_dev_register(struct device *dev,
				   struct rpmb_descr *descr)
{
	struct rpmb_dev *rdev;

	if (!dev || !descr || !descr->route_frames || !descr->dev_id ||
	    !descr->dev_id_len)
		return ERR_PTR(-EINVAL);

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return ERR_PTR(-ENOMEM);
	rdev->descr = *descr;
	rdev->descr.dev_id = kmemdup(descr->dev_id, descr->dev_id_len,
				     GFP_KERNEL);
	if (!rdev->descr.dev_id) {
		kfree(rdev);
		return ERR_PTR(-ENOMEM);
	}

	rdev->parent_dev = dev;

	dev_dbg(rdev->parent_dev, "registered device\n");

	mutex_lock(&rpmb_mutex);
	list_add_tail(&rdev->list_node, &rpmb_dev_list);
	blocking_notifier_call_chain(&rpmb_interface, RPMB_NOTIFY_ADD_DEVICE,
				     rdev);
	mutex_unlock(&rpmb_mutex);

	return rdev;
}
EXPORT_SYMBOL_GPL(rpmb_dev_register);

/**
 * rpmb_interface_register() - register for new device notifications
 *
 * @nb : New entry in notifier chain
 *
 * Returns: 0 on success  -EEXIST on error.
 */
int rpmb_interface_register(struct notifier_block *nb)
{
	struct rpmb_dev *rdev;
	int ret;

	ret = blocking_notifier_chain_register(&rpmb_interface, nb);
	if (ret)
		return ret;

	mutex_lock(&rpmb_mutex);
	list_for_each_entry(rdev, &rpmb_dev_list, list_node)
		nb->notifier_call(nb, RPMB_NOTIFY_ADD_DEVICE, rdev);
	mutex_unlock(&rpmb_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(rpmb_interface_register);

/**
 * rpmb_interface_unregister() - unregister from new device notifications
 *
 * @nb : Entry to remove from notifier chain
 *
 * Returns: 0 on success or -ENOENT on failure.
 */
int rpmb_interface_unregister(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&rpmb_interface, nb);
}
EXPORT_SYMBOL_GPL(rpmb_interface_unregister);

static int __init rpmb_init(void)
{
	INIT_LIST_HEAD(&rpmb_dev_list);
	return 0;
}

static void __exit rpmb_exit(void)
{
	mutex_destroy(&rpmb_mutex);
}

subsys_initcall(rpmb_init);
module_exit(rpmb_exit);

MODULE_AUTHOR("Jens Wiklander <jens.wiklander@linaro.org>");
MODULE_DESCRIPTION("RPMB class");
MODULE_LICENSE("GPL");
