// SPDX-License-Identifier: GPL-2.0-only
/*
 * Secure Partitions Communication Interface (SPCI) Protocol driver
 *
 * SPCI is a system message passing and memory sharing protocol allowing for
 * execution contexts to exchange information with other execution contexts
 * residing on other Secure Partitions or Virtual Machines managed by any SPCI
 * compliant firmware framework.
 *
 * Copyright (C) 2020 Arm Ltd.
 */

#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/arm_spci.h>
#include <linux/arm-smcccv1_2.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>

enum message_t
{
	/*
	 * w1[31:16] -- sender endpoint ID
	 * w3 -- message_t
	 * w4 -- handle
	 * w5 -- attributes
	 */
	FF_A_MEMORY_SHARE = 1,
	FF_A_UNDEFINED
};

long test_share_multi_fragment()
{
	/*
	 *  We intend to reserve memory that would require at least 2 fragments
	 *  each constituent occupies 16 bytes
	 *
	 *  4 fragmenst take at most 4096 * 2 = 8192
	 *  that equates to 16384/16 constituents = 512
	 *
	 *  Each constituent equates to a page 512 * 4096 = 2097152
	 *
	 *  To ensure that each constituent has a single page then only select the
	 *  even pages.
	 *
	 *  In total reserve 4 MB.
	 *
	 */
	const u32 mem_size = 4*1024*1024;
	const u32 page_entries = mem_size/4096/2;
	u32 index;
	u32 handle;
	int retVal;

	struct spci_partition_info *info_partitions;

	void *mem_region;
	struct page **pages;

	u32 dest_part_uuid[4] = {0x486178E0, 0xE7F811E3, 0xBC5E0002, 0xA5D5C51B};
	spci_sp_id_t dest_part_id;

	struct spci_mem_region_attributes attributes[1] = {
		[0] = {
			.receiver = 0x8001,
			.attrs = SPCI_MEM_RW << 5
		},
	};

	struct spci_ops *ops = get_spci_ops();
	if (IS_ERR_OR_NULL(ops))
	{
		pr_err("Failed to obtain SPCI ops %s:%d\n", __FILE__, __LINE__);
	}

	retVal = ops->partition_info_get(dest_part_uuid[0], dest_part_uuid[1],
							dest_part_uuid[2], dest_part_uuid[3],
							&info_partitions);

	/* XXX: Assumes that there is a single partition with the dest_aprt_uuid. */
	dest_part_id = info_partitions->id;

	if(retVal < 0)
	{
		pr_err("Failed to obtain destination partition info. %s:%d\n", __FILE__, __LINE__);
		return retVal;
	}

	mem_region = kzalloc(mem_size, GFP_KERNEL);
	if(IS_ERR_OR_NULL(mem_region))
	{
		pr_err("Out of memory. %s:%d\n", __FILE__, __LINE__);
		return -ENOMEM;
	}

	pages = kzalloc(page_entries * sizeof(void *), GFP_KERNEL);
	if(IS_ERR_OR_NULL(pages))
	{
		kfree(mem_region);
		pr_err("Out of memory. %s:%d\n", __FILE__, __LINE__);
		return -ENOMEM;
	}

	for(index = 0; index<page_entries; index++)
	{
		// We want to keep even pages. This ensures the constituents
		// have a single page and consume the maximum space possible in the
		// memory region descriptor.
		pages[index] = virt_to_page(mem_region + (index*4096*2));

		//sg_set_page(sg, cur_page, 4096, 0);
	}
	struct sg_table sgt;
	sg_alloc_table_from_pages(&sgt, pages,
			      page_entries, 0,
			      page_entries*4096, GFP_KERNEL);

	pr_info("Start mem share %s:%d\n", __FILE__, __LINE__);
	// tag, flags, *attrs, num_attrs, *pages[], num_pages, *global_handle
	retVal = ops->mem_share(0, 1, attributes, 1, sgt.sgl, &handle, NULL, 0);

	if(retVal)
	{
		pr_err("Failed to send the memory region %s:%d\n", __FILE__, __LINE__);

		return retVal;
	}

	/* TODO: Currently just transmitting the handle, must add remaining details (attr, etc.). */
	pr_info("sharing memory with SP %#X %s:%d\n", dest_part_id, __FILE__, __LINE__);
	ops->sync_msg_send(dest_part_id, FF_A_MEMORY_SHARE, handle, 0, 0, 0);

	return 0;
}

long ff_a_test_ioctl(struct file *fd, unsigned int cmd, unsigned long arg)
{
	long ret;

	ret = test_share_multi_fragment();

	return ret;
}

struct file_operations fops = {
	.unlocked_ioctl = ff_a_test_ioctl,
};

int ff_a_test_init()
{
	int returnVal;
	struct class *cl;

	pr_info("FF-A test module init\n");

	cl = class_create(THIS_MODULE, "ff_a_test");
	if (IS_ERR(cl))
		return PTR_ERR(cl);

	/* Create char device. */
	returnVal = register_chrdev(0, "FF_A_TEST", &fops);

	/* Create device file in the /dev directory. */
	device_create(cl, NULL, MKDEV(returnVal, 0),NULL, "FF_A_TEST_DEVICE");

	pr_info("FF-A test module init finalized\n");
	return 0;
}

module_init(ff_a_test_init);

MODULE_AUTHOR("Arm");
MODULE_DESCRIPTION("PSA-FF-A test module");
MODULE_LICENSE("GPL v2");
