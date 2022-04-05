// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2015 - 2019 Intel Corporation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include <linux/capability.h>

#include <linux/rpmb.h>

#include "rpmb-cdev.h"

static dev_t rpmb_devt;
#define RPMB_MAX_DEVS  MINORMASK

#define RPMB_DEV_OPEN    0  /** single open bit (position) */

/**
 * rpmb_open - the open function
 *
 * @inode: pointer to inode structure
 * @fp: pointer to file structure
 *
 * Return: 0 on success, <0 on error
 */
static int rpmb_open(struct inode *inode, struct file *fp)
{
	struct rpmb_dev *rdev;

	rdev = container_of(inode->i_cdev, struct rpmb_dev, cdev);
	if (!rdev)
		return -ENODEV;

	/* the rpmb is single open! */
	if (test_and_set_bit(RPMB_DEV_OPEN, &rdev->status))
		return -EBUSY;

	mutex_lock(&rdev->lock);

	fp->private_data = rdev;

	mutex_unlock(&rdev->lock);

	return nonseekable_open(inode, fp);
}

/**
 * rpmb_release - the cdev release function
 *
 * @inode: pointer to inode structure
 * @fp: pointer to file structure
 *
 * Return: 0 always.
 */
static int rpmb_release(struct inode *inode, struct file *fp)
{
	struct rpmb_dev *rdev = fp->private_data;

	clear_bit(RPMB_DEV_OPEN, &rdev->status);

	return 0;
}

static long rpmb_ioctl_ver_cmd(struct rpmb_dev *rdev,
			       struct rpmb_ioc_ver_cmd __user *ptr)
{
	struct rpmb_ioc_ver_cmd ver = {
		.api_version = RPMB_API_VERSION,
	};

	return copy_to_user(ptr, &ver, sizeof(ver)) ? -EFAULT : 0;
}

static long rpmb_ioctl_cap_cmd(struct rpmb_dev *rdev,
			       struct rpmb_ioc_cap_cmd __user *ptr)
{
	struct rpmb_ioc_cap_cmd cap;

	cap.target      = rdev->target;
	cap.block_size  = rdev->ops->block_size;
	cap.wr_cnt_max  = rdev->ops->wr_cnt_max;
	cap.rd_cnt_max  = rdev->ops->rd_cnt_max;
	cap.capacity    = rpmb_get_capacity(rdev);
	cap.reserved    = 0;

	return copy_to_user(ptr, &cap, sizeof(cap)) ? -EFAULT : 0;
}

static long rpmb_ioctl_pkey_cmd(struct rpmb_dev *rdev, struct rpmb_ioc_reqresp_cmd __user *ptr)
{
	struct rpmb_ioc_reqresp_cmd cmd;
	u8 *request, *resp = NULL;
	long ret;

	if (copy_from_user(&cmd, ptr, sizeof(struct rpmb_ioc_reqresp_cmd)))
		return -EFAULT;

	request = kmalloc(cmd.len, GFP_KERNEL);

	if (!request)
		return -ENOMEM;

	if (cmd.rlen && cmd.response) {
		resp = kmalloc(cmd.rlen, GFP_KERNEL);
		if (!resp) {
			kfree(request);
			return -ENOMEM;
		}
	}

	if (copy_from_user(request, cmd.request, cmd.len))
		ret = -EFAULT;
	else
		ret = rpmb_program_key(rdev, cmd.len, request, cmd.rlen, resp);

	if (!ret)
		if (copy_to_user(cmd.response, resp, cmd.rlen))
			ret = -EFAULT;

	kfree(request);
	kfree(resp);

	return ret;
}

static long rpmb_ioctl_counter_cmd(struct rpmb_dev *rdev, struct rpmb_ioc_reqresp_cmd __user *ptr)
{
	struct rpmb_ioc_reqresp_cmd cmd;
	u8 *request, *resp = NULL;
	long count;

	if (copy_from_user(&cmd, ptr, sizeof(struct rpmb_ioc_reqresp_cmd)))
		return -EFAULT;

	request = kmalloc(cmd.len, GFP_KERNEL);

	if (!request)
		return -ENOMEM;

	if (cmd.rlen && cmd.response) {
		resp = kmalloc(cmd.rlen, GFP_KERNEL);
		if (!resp) {
			kfree(request);
			return -ENOMEM;
		}
	}

	if (copy_from_user(request, cmd.request, cmd.len)) {
		count = -EFAULT;
	} else {
		count = rpmb_get_write_count(rdev, cmd.len, request, cmd.rlen, resp);
		if (resp)
			if (copy_to_user(cmd.response, resp, cmd.rlen))
				count = -EFAULT;
	}

	kfree(request);
	kfree(resp);

	return count;
}

static long rpmb_ioctl_wblocks_cmd(struct rpmb_dev *rdev,
				   struct rpmb_ioc_reqresp_cmd __user *ptr)
{
	struct rpmb_ioc_reqresp_cmd cmd;
	u8 *data, *resp = NULL;

	long ret;

	if (copy_from_user(&cmd, ptr, sizeof(struct rpmb_ioc_reqresp_cmd)))
		return -EFAULT;

	data = kmalloc(cmd.len, GFP_KERNEL);

	if (!data)
		return -ENOMEM;

	if (cmd.rlen && cmd.response) {
		resp = kmalloc(cmd.rlen, GFP_KERNEL);
		if (!resp) {
			kfree(data);
			return -ENOMEM;
		}
	}

	if (copy_from_user(data, cmd.request, cmd.len))
		ret = -EFAULT;
	else
		ret = rpmb_write_blocks(rdev, cmd.len, data, cmd.rlen, resp);

	if (resp)
		if (copy_to_user(cmd.response, resp, cmd.rlen))
			ret = -EFAULT;

	kfree(data);
	kfree(resp);

	return ret;
}

static long rpmb_ioctl_rblocks_cmd(struct rpmb_dev *rdev,
				   struct rpmb_ioc_rblocks_cmd __user *ptr)
{
	struct rpmb_ioc_rblocks_cmd rblocks;
	long ret;
	u8 *data;

	if (copy_from_user(&rblocks, ptr, sizeof(struct rpmb_ioc_rblocks_cmd)))
		return -EFAULT;

	if (rblocks.count > rdev->ops->rd_cnt_max)
		return -EINVAL;

	if (!rblocks.len || !rblocks.data)
		return -EINVAL;

	data = kmalloc(rblocks.len, GFP_KERNEL);

	if (!data)
		return -ENOMEM;

	ret = rpmb_read_blocks(rdev, rblocks.addr, rblocks.count, rblocks.len, data);

	if (ret == 0)
		ret = copy_to_user(rblocks.data, data, rblocks.len);

	kfree(data);
	return ret;
}

/**
 * rpmb_ioctl - rpmb ioctl dispatcher
 *
 * @fp: a file pointer
 * @cmd: ioctl command RPMB_IOC_SEQ_CMD RPMB_IOC_VER_CMD RPMB_IOC_CAP_CMD
 * @arg: ioctl data: rpmb_ioc_ver_cmd rpmb_ioc_cap_cmd pmb_ioc_seq_cmd
 *
 * Return: 0 on success; < 0 on error
 */
static long rpmb_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct rpmb_dev *rdev = fp->private_data;
	void __user *ptr = (void __user *)arg;

	switch (cmd) {
	case RPMB_IOC_VER_CMD:
		return rpmb_ioctl_ver_cmd(rdev, ptr);
	case RPMB_IOC_CAP_CMD:
		return rpmb_ioctl_cap_cmd(rdev, ptr);
	case RPMB_IOC_PKEY_CMD:
		return rpmb_ioctl_pkey_cmd(rdev, ptr);
	case RPMB_IOC_COUNTER_CMD:
		return rpmb_ioctl_counter_cmd(rdev, ptr);
	case RPMB_IOC_WBLOCKS_CMD:
		return rpmb_ioctl_wblocks_cmd(rdev, ptr);
	case RPMB_IOC_RBLOCKS_CMD:
		return rpmb_ioctl_rblocks_cmd(rdev, ptr);
	default:
		dev_err(&rdev->dev, "unsupported ioctl 0x%x.\n", cmd);
		return -ENOIOCTLCMD;
	}
}

static const struct file_operations rpmb_fops = {
	.open           = rpmb_open,
	.release        = rpmb_release,
	.unlocked_ioctl = rpmb_ioctl,
	.owner          = THIS_MODULE,
	.llseek         = noop_llseek,
};

void rpmb_cdev_prepare(struct rpmb_dev *rdev)
{
	rdev->dev.devt = MKDEV(MAJOR(rpmb_devt), rdev->id);
	rdev->cdev.owner = THIS_MODULE;
	cdev_init(&rdev->cdev, &rpmb_fops);
}

void rpmb_cdev_add(struct rpmb_dev *rdev)
{
	cdev_add(&rdev->cdev, rdev->dev.devt, 1);
}

void rpmb_cdev_del(struct rpmb_dev *rdev)
{
	if (rdev->dev.devt)
		cdev_del(&rdev->cdev);
}

int __init rpmb_cdev_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&rpmb_devt, 0, RPMB_MAX_DEVS, "rpmb");
	if (ret < 0)
		pr_err("unable to allocate char dev region\n");

	return ret;
}

void __exit rpmb_cdev_exit(void)
{
	unregister_chrdev_region(rpmb_devt, RPMB_MAX_DEVS);
}
