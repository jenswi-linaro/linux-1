// SPDX-License-Identifier: GPL-2.0+
/*
 * Virtio message transport user API.
 *
 * Copyright (C) 2025 Google LLC and Linaro.
 * Viresh Kumar <viresh.kumar@linaro.org>
 */

#define pr_fmt(fmt) "virtio-msg: " fmt

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/minmax.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "virtio_msg_internal.h"

#define to_virtio_msg_user_device(_misc) \
	container_of(_misc, struct virtio_msg_user_device, misc)

static DEFINE_IDA(device_ids);

static ssize_t vmsg_miscdev_read(struct file *file, char __user *buf,
				 size_t count, loff_t *pos)
{
	struct miscdevice *misc = file->private_data;
	struct virtio_msg_user_device *vmudev = to_virtio_msg_user_device(misc);
	struct device *dev = vmudev->parent;
	int ret;

	if (count < VIRTIO_MSG_MIN_SIZE) {
		dev_err(dev, "Trying to read message of incorrect size: %zu\n",
			count);
		return -EINVAL;
	}

	/* read() must be done after poll() passes */
	if (!READ_ONCE(vmudev->vmsg))
		return -EIO;

	ret = min_t(size_t, count, le16_to_cpu(vmudev->vmsg->msg_size));

	/* The "vmsg" pointer is filled by the bus driver before waking up */
	if (copy_to_user(buf, vmudev->vmsg, ret))
		return -EFAULT;

	vmudev->vmsg = NULL;

	return ret;
}

static ssize_t vmsg_miscdev_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *pos)
{
	struct miscdevice *misc = file->private_data;
	struct virtio_msg_user_device *vmudev = to_virtio_msg_user_device(misc);
	int ret;

	if (count < sizeof(struct virtio_msg)) {
		dev_err(vmudev->parent, "Message too small: %zu\n", count);
		return -EINVAL;
	}

	struct virtio_msg *vmsg __free(kfree) = memdup_user(buf, count);
	if (IS_ERR(vmsg))
		return PTR_ERR(vmsg);

	ret = vmudev->ops->handle(vmudev, vmsg);
	if (ret)
		return ret;

	/* Wake up the handler only for responses */
	if (vmsg->type & VIRTIO_MSG_TYPE_RESPONSE)
		complete(&vmudev->completion);

	return count;
}

static __poll_t vmsg_miscdev_poll(struct file *file, poll_table *wait)
{
	struct miscdevice *misc = file->private_data;
	struct virtio_msg_user_device *vmudev = to_virtio_msg_user_device(misc);
	__poll_t mask = EPOLLOUT | EPOLLWRNORM;

	poll_wait(file, &vmudev->wait, wait);

	if (READ_ONCE(vmudev->vmsg))
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static const struct file_operations vmsg_miscdev_fops = {
	.owner = THIS_MODULE,
	.read = vmsg_miscdev_read,
	.write = vmsg_miscdev_write,
	.poll = vmsg_miscdev_poll,
};

/**
 * virtio_msg_user_register - Register a user-space accessible virtio message device
 * @vmudev: Pointer to the virtio message user device
 *
 * Initializes and registers a user-accessible virtio message device as a `misc`
 * character device. Upon successful registration, the device appears in
 * userspace as `/dev/virtio-msg-N` where `N` is a unique identifier assigned at
 * runtime.
 *
 * The resulting device node allows user-space interaction with the virtio
 * message transport.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int virtio_msg_user_register(struct virtio_msg_user_device *vmudev)
{
	int ret, id;

	if (!vmudev || !vmudev->ops)
		return -EINVAL;

	id = ida_alloc(&device_ids, GFP_KERNEL);
	if (id < 0)
		return id;

	init_completion(&vmudev->completion);
	init_waitqueue_head(&vmudev->wait);

	vmudev->id = id;
	vmudev->misc.parent = vmudev->parent;
	vmudev->misc.minor = MISC_DYNAMIC_MINOR;
	vmudev->misc.fops = &vmsg_miscdev_fops;
	vmudev->misc.name = vmudev->name;
	snprintf(vmudev->name, sizeof(vmudev->name), "virtio-msg-%d", id);

	ret = misc_register(&vmudev->misc);
	if (ret) {
		ida_free(&device_ids, id);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(virtio_msg_user_register);

/**
 * virtio_msg_user_unregister - Unregister a user-space virtio message device
 * @vmudev: Pointer to the virtio message user device
 *
 * Unregisters a previously registered virtio message device from the misc
 * subsystem. This removes its user-space interface (e.g., /dev/virtio-msg-N).
 */
void virtio_msg_user_unregister(struct virtio_msg_user_device *vmudev)
{
	misc_deregister(&vmudev->misc);
	ida_free(&device_ids, vmudev->id);
}
EXPORT_SYMBOL_GPL(virtio_msg_user_unregister);
