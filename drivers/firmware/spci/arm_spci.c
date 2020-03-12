// SPDX-License-Identifier: GPL-2.0-only
/*
 * Secure Partitions Communication Interface (SPCI) Protocol driver
 *
 * SPCI is a system message passing and memory sharing protocol allowing for
 * execution contexts to exchange information with other execution contexts
 * residing on other Secure Partitions or Virtual Machines managed by any SPCI
 * compliant firmware framework.
 *
 * Copyright (C) 2019, 2020 Arm Ltd.
 */

#include <linux/platform_device.h>
#include <linux/arm_spci.h>
#include <linux/arm-smcccv1_2.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>


static DEFINE_MUTEX(rx_lock);
static DEFINE_MUTEX(tx_lock);

static spci_sp_id_t vm_id;

static struct page *rx_buffer;
static struct page *tx_buffer;

static struct arm_smcccv1_2_return
(*arm_spci_smccc)(u32 func, u64 arg1, u64 arg2, u64 arg3, u64 arg4,
		  u64 arg5, u64 arg6, u64 arg7);

#define SPCI_DEFINE_CALL(conduit)					\
static struct arm_smcccv1_2_return					\
arm_spci_##conduit(u32 func, u64 arg1, u64 arg2, u64 arg3, u64 arg4,	\
		   u64 arg5, u64 arg6, u64 arg7)			\
{									\
	struct arm_smcccv1_2_return smccc_ret;				\
									\
	__arm_smcccv1_2_##conduit(func, arg1, arg2, arg3, arg4, arg5,	\
				  arg6,	arg7, &smccc_ret);		\
									\
	return smccc_ret;						\
}

SPCI_DEFINE_CALL(smc)

SPCI_DEFINE_CALL(hvc)

static u32 sender_receiver_pack(u32 src_id, u32 dst_id)
{
	return (((src_id << 16) & 0xffff0000) | (dst_id & 0xffff));
}

int spci_msg_send(spci_sp_id_t dst_id, u32 len, u32 attributes)
{
	struct arm_smcccv1_2_return msg_send_return;

	/* w1[32:16] Sender endpoint ID, w1[15:0] destination endpoint id. */
	u32 sender_receiver = sender_receiver_pack(vm_id, dst_id);

	msg_send_return = arm_spci_smccc(SPCI_MSG_SEND_32, sender_receiver,
					 0, len, attributes, 0, 0, 0);

	if (msg_send_return.func  == SPCI_ERROR_32) {
		switch (msg_send_return.arg2) {
		case SPCI_INVALID_PARAMETERS:
			return -ENXIO;
		case SPCI_DENIED:
		case SPCI_BUSY:
			return -EAGAIN;
		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      msg_send_return.arg2);
		}
	}
	return 0;
}

struct arm_smcccv1_2_return
spci_msg_send_direct_req(spci_sp_id_t dst_id, u64 w3, u64 w4, u64 w5,
			 u64 w6, u64 w7)
{
	struct arm_smcccv1_2_return ret;

	/* w1[32:16] Sender endpoint ID, w1[15:0] destination endpoint id. */
	u32 sender_receiver = sender_receiver_pack(vm_id, dst_id);

	ret = arm_spci_smccc(SPCI_MSG_SEND_DIRECT_REQ_32, sender_receiver, 0,
			     w3, w4, w5, w6, w7);

	if (ret.func == SPCI_ERROR_32) {
		pr_err("%s: Error sending message %llu\n", __func__, ret.func);
		switch (ret.arg1) {
		case SPCI_INVALID_PARAMETERS:
			ret.func = -ENXIO;
			break;
		case SPCI_DENIED:
		case SPCI_NOT_SUPPORTED:
			ret.func = -EIO;
			break;
		case SPCI_BUSY:
			ret.func = -EAGAIN;
			break;
		}
	} else {
		ret.func = 0;
	}

	return ret;
}

static int spci_share_fragment_tx(u32 page_count,
	u32 fragment_len, u32 total_len, u32 cookie,
	struct arm_smcccv1_2_return *smccc_return)
{

	*smccc_return =
		arm_spci_smccc(SPCI_MEM_SHARE_64, 0, page_count, fragment_len,
			total_len, cookie, 0, 0);


	if (smccc_return->func == SPCI_ERROR_32) {
		switch (smccc_return->arg2) {
		case SPCI_INVALID_PARAMETERS:
			return -ENXIO;
		case SPCI_DENIED:
			return -EIO;
		case SPCI_NO_MEMORY:
			return -ENOMEM;
		case SPCI_RETRY:
			return -EAGAIN;
		default:
			pr_warn("%s: Unknown Error code %x\n", __func__,
				smccc_return->arg2);
			return -EIO;
		}
	}

	return 0;
}

static inline u16 set_mem_attributes(enum spci_mem_permission perm,
	enum spci_mem_type type)
{
	return perm << 5 | type << 4;
}

static inline u32 compute_constituent_offset(u32 num_attributes)
{
	u32 constituent_offset = offsetof(struct spci_mem_region,
		attributes[num_attributes]);

	/* ensure constituents are 8 byte aligned. */
	if (constituent_offset & 0x7)
		return (constituent_offset & (~(u32)0x7)) + 0x8;

	return constituent_offset;
}

static inline u32 compute_region_length(u32 num_constituents,
	u32 num_attributes)
{
	return compute_constituent_offset(num_attributes) +
		sizeof(struct spci_mem_region_constituent)*num_constituents;
}

static int spci_rx_release(void)
{
	struct arm_smcccv1_2_return rx_release_return;

	rx_release_return = arm_spci_smccc(SPCI_RX_RELEASE_32,
					      0, 0, 0, 0, 0, 0, 0);

	if (rx_release_return.func == SPCI_ERROR_32) {
		switch (rx_release_return.arg2) {
		case SPCI_DENIED:
			return -EAGAIN;
		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      rx_release_return.arg2);
		}
	}

	if (rx_release_return.func == SPCI_RX_RELEASE_32) {
		/*
		 * SPCI implementation returned SPCI_RX_RELEASE which signals
		 * the PVM that other VMs need to be scheduled.
		 */
		return 1;
	}

	return 0;
}

static u32 spci_count_total_constituents(struct scatterlist *sg)
{
	u32 num_constituents = 0;

	do {
		num_constituents += 1;
	} while((sg = sg_next(sg)));

	return num_constituents;
}


#define MAX_COOKIE 10
static bool cookie_tracker[MAX_COOKIE] = {0};

/** 
 * Obtain a unique cookie to be used in the spci_mem_share operations.
 * Must only be called with tx_lock acquired.
 *
 * A 0 return signals failure.
 */
static inline u32 get_mem_share_cookie()
{

	u32 index;

	for (index=0; index<MAX_COOKIE; index++)
	{
		if (cookie_tracker[index] == 0)	{
			cookie_tracker[index] = 1;
			return index+1;
		}
	}

	return 0;
}

/**
 * Put a unique cookie used for spci_mem_share operations.
 */ 
static inline bool put_mem_share_cookie(u32 cookie)
{

	if (cookie_tracker[cookie] == 1)
	{
		pr_err("Tried to erroneously put cookie %d\n", cookie);
		return false;
	}

	cookie_tracker[cookie] = 0;

	return true;
}

static uint32_t spci_get_num_pages_sg(struct scatterlist *sg)
{
	uint32_t num_pages = 0;
	do {
		num_pages += sg->length/PAGE_SIZE;
	} while ((sg = sg_next(sg)));

	return num_pages;
}

/*
 * Share a set of pages with a list of destination endpoints.
 * Returns a system-wide unique handle
 */
int spci_share_memory(u32 tag, enum mem_clear_t flags,
	struct spci_mem_region_attributes *attrs,
	u32 num_attrs, struct scatterlist *sg,
	spci_mem_handle_t *global_handle, void *buffer, u32 buffer_size)
{
	struct spci_mem_region *mem_region;
	u32 index;
	u32 num_constituents;
	struct spci_mem_region_constituent *constituents;
	struct arm_smcccv1_2_return smccc_return;
	u32 total_num_constituents;
	u32 region_len;
	u32 ephemeral_region_len;
	u32 fragment_len = sizeof(struct spci_mem_region);
	u32 local_num_pages = spci_get_num_pages_sg(sg);
	u32 cookie = 0;
	u32 max_fragment_size;
	int rc = 0;

	/* Lock access to the TX Buffer before populating. */
	mutex_lock(&tx_lock);
	if(buffer!=NULL) {
		mem_region = (struct spci_mem_region *)buffer;
		max_fragment_size = buffer_size;
		if (buffer_size % SPCI_BASE_GRANULE_SIZE)
		{
			pr_err("%s: buffer size must be a multiple of 4kiB", __func__);
			rc = -ENXIO;
		}
	} else {
		mem_region = (struct spci_mem_region *)page_address(tx_buffer);
		max_fragment_size = SPCI_BASE_GRANULE_SIZE;
	}

	mem_region->flags = flags;
	mem_region->tag = tag;

	mem_region->constituent_count = sg_nents(sg);

	mem_region->constituent_offset = compute_constituent_offset(num_attrs);
	fragment_len = mem_region->constituent_offset;

	/* Ensure attribute description fits withing the Tx buffer. */
	if (mem_region->constituent_offset >= max_fragment_size) {
		rc = -ENXIO;
		goto err;
	}

	constituents = (struct spci_mem_region_constituent *)
		(((void *)mem_region) + mem_region->constituent_offset);

	total_num_constituents = spci_count_total_constituents(sg);

	mem_region->constituent_count = total_num_constituents;
	region_len = compute_region_length(total_num_constituents, num_attrs);

	for (index = 0; index < num_attrs; index++) {
		mem_region->attributes[index].receiver = attrs[index].receiver;
		mem_region->attributes[index].attrs =
			attrs[index].attrs;
	}
	mem_region->attribute_count = num_attrs;

	num_constituents = 0;
	ephemeral_region_len = region_len;

	do {
		phys_addr_t address = sg_phys(sg);

		/*
		 * Detect if any part of the constituent region surpasses the Tx
		 * region.
		 */
		if (((void *) &constituents[num_constituents])
			- (void *)mem_region > max_fragment_size)
		{
			pr_err("%s: memory region fragment greater that the Tx buffer",
				 __func__);
			rc = -EFAULT;
			goto err;
		}

		pr_devel("arm_spci mem_share pa=%#X\n", address);

		constituents[num_constituents].address = address;
		constituents[num_constituents].page_count = sg->length/PAGE_SIZE;
		num_constituents++;
		fragment_len += sizeof(struct spci_mem_region_constituent);

		/*
		 * If current fragment size equal Tx size trigger fragment
		 * transfer.
		 */
		if (fragment_len == max_fragment_size) {

			/*
			 * XXX: Executing with tx_lock acquired until all fragments are
			 * transferred.
			 */
			if (ephemeral_region_len)
			{
				if(cookie!=0) {
					panic("initialized mem_share cookie");
				}

				cookie = get_mem_share_cookie();

				if(!cookie)
				{
					pr_err("%s: failed to get a valid mem_share cookie\n",
						__func__);

					return -ENXIO;
				}
			}

			/* Transmit fragment. */
			rc = spci_share_fragment_tx(local_num_pages,
				fragment_len, ephemeral_region_len, cookie,
				&smccc_return);

			/* Allow another thread to access the tx buffer. */
			mutex_unlock(&tx_lock);

			if (rc < 0)
			{
				return rc;
			}

			/* ephemeral_region_len MBZ after the first invocation. */
			ephemeral_region_len = 0;

			/* local_num_pages MBZ after the first invocation. */
			local_num_pages =0;
			constituents = (struct spci_mem_region_constituent *)mem_region;
			num_constituents = 0;
			fragment_len = 0;

			/* Regain exclusive access to the Tx buffer. */
			mutex_lock(&tx_lock);
		}
	} while((sg = sg_next(sg)));

	rc = spci_share_fragment_tx(local_num_pages,
		fragment_len, ephemeral_region_len, cookie,
		&smccc_return);

	/* If unique cookie was obtained, put it back. */
	if (cookie)
	{
		if(!put_mem_share_cookie(cookie))
		{
			panic("failed to put cookie %d\n", cookie);
		}
		cookie = 0;
	}

	*global_handle = smccc_return.arg2;
err:
	mutex_unlock(&tx_lock);
	return rc;
}

static int spci_memory_reclaim(spci_mem_handle_t global_handle,
	enum mem_clear_t flags) {

	struct arm_smcccv1_2_return smccc_return;

	smccc_return = arm_spci_smccc(SPCI_MEM_RECLAIM_32, global_handle, flags,
			     0, 0, 0, 0, 0);

	if (smccc_return.func == SPCI_ERROR_32) {
		pr_err("%s: Error sending message %llu\n", __func__,
			smccc_return.func);
		switch (smccc_return.arg2) {
		case SPCI_INVALID_PARAMETERS:
			return -ENXIO;
		case SPCI_DENIED:
		case SPCI_NOT_SUPPORTED:
			return -EIO;
		case SPCI_BUSY:
			return -EAGAIN;
		default:
			pr_warn("%s: Unknown Error code %x\n", __func__,
				smccc_return.arg2);
			return -EIO;
		}
	}

	return 0;
}

static spci_sp_id_t spci_id_get(void)
{
	struct  arm_smcccv1_2_return id_get_return =
		arm_spci_smccc(SPCI_ID_GET_32, 0, 0, 0, 0, 0, 0, 0);

	if (id_get_return.func == SPCI_ERROR_32)
		panic("%s: failed to obtain vm id\n", __func__);
	else
		return id_get_return.arg2 & 0xffff;
}

static int spci_partition_info_get(uint32_t uuid0, uint32_t uuid1,
				     uint32_t uuid2, uint32_t uuid3,
				     struct spci_partition_info **buffer)
{
	int rc = 0;
	uint32_t count;
	struct spci_partition_info *info =
		(struct spci_partition_info *) page_address(rx_buffer);
	struct arm_smcccv1_2_return partition_info_get_return;

	mutex_lock(&rx_lock);
	partition_info_get_return = arm_spci_smccc(SPCI_PARTITION_INFO_GET_32,
						   uuid0, uuid1, uuid2, uuid3,
						   0, 0, 0);

	if (partition_info_get_return.func == SPCI_ERROR_32) {
		switch (partition_info_get_return.arg2) {
		case SPCI_INVALID_PARAMETERS:
			rc = -ENXIO;
			goto err;
		case SPCI_NO_MEMORY:
			rc = -ENOMEM;
			goto err;
		case SPCI_NOT_SUPPORTED:
			rc = -ENODEV;
			goto err;
		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      partition_info_get_return.arg2);
		}
	}

	count = partition_info_get_return.arg2;

	/* Allocate and copy the info structs.
	 * Client is responsible for freeing.
	 */
	*buffer = kzalloc(sizeof(struct spci_partition_info) * count,
			  GFP_KERNEL);
	if (*buffer == NULL) {
		rc = -ENOMEM;
		goto err;
	}
	memcpy(*buffer, info, sizeof(struct spci_partition_info) * count);

	rc = spci_rx_release();
	if (rc)
		panic("%s: Unhandled return code (%lld)\n", __func__, rc);

	rc = count;
err:
	mutex_unlock(&rx_lock);

	return rc;
}

static struct spci_ops spci_ops = {
	.async_msg_send = spci_msg_send,
	.sync_msg_send = spci_msg_send_direct_req,
	.mem_share = spci_share_memory,
	.mem_reclaim = spci_memory_reclaim,
	.partition_info_get = spci_partition_info_get,
};

struct spci_ops *get_spci_ops(void)
{
	return &spci_ops;
}
EXPORT_SYMBOL_GPL(get_spci_ops);

static int spci_dt_init(struct device_node *np)
{
	const char *conduit;

	pr_info("SPCI: obtaining conduit from DT.\n");

	if (of_property_read_string(np, "conduit", &conduit)) {
		pr_warn("SPCI: cannot find conduit in DT\n");
		return -ENXIO;
	}

	if (!strcmp("smc", conduit))
		arm_spci_smccc = arm_spci_smc;
	else if (!strcmp("hvc", conduit))
		arm_spci_smccc = arm_spci_hvc;
	else
		panic("%s: unrecognized SPCI conduit\n", __func__);

	return 0;
}

static const struct of_device_id spci_of_match[] = {
	{.compatible = "arm,spci"},
	{},
};

static int spci_rxtx_map(uintptr_t tx_page, uintptr_t rx_page)
{
	struct arm_smcccv1_2_return map_return;

	map_return = arm_spci_smccc(SPCI_RXTX_MAP_32, tx_page,
					 rx_page, 1, 0, 0, 0, 0);

	if (map_return.func == SPCI_ERROR_32) {
		switch (map_return.arg2) {
		case SPCI_INVALID_PARAMETERS:
			return -ENXIO;
		case SPCI_DENIED:
			return -EAGAIN;
		case SPCI_NO_MEMORY:
			return -ENOMEM;
		case SPCI_NOT_SUPPORTED:
			return -ENODEV;

		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      map_return.arg2);
		}
	}

	return 0;
}

static int spci_probe(struct platform_device *pdev)
{
	int ret;

	spci_dt_init(pdev->dev.of_node);

	/* Initialize VM ID. */
	vm_id = spci_id_get();

	/* Allocate Rx buffer. */
	rx_buffer = alloc_page(GFP_KERNEL);

	/*
	 * Ensure buffer was correctly allocated and that the refcout was
	 * incremented.
	 */
	if (!rx_buffer || !try_get_page(rx_buffer)) {
		pr_err("%s: failed to allocate SPCI Rx buffer\n", __func__);
		return -ENOMEM;
	}

	/* Allocate Tx buffer. */
	tx_buffer = alloc_page(GFP_KERNEL);

	/*
	 * Ensure buffer was correctly allocated and that the refcout was
	 * incremented.
	 */
	if (!tx_buffer || !try_get_page(rx_buffer)) {
		put_page(rx_buffer);
		__free_page(rx_buffer);

		pr_err("%s: failed to allocate SPCI Tx buffer\n", __func__);
		return -ENOMEM;
	}

	/* Register the RxTx buffers with the SPCI supervisor implementation. */
	ret = spci_rxtx_map(page_to_phys(tx_buffer), page_to_phys(rx_buffer));
	if (ret) {
		put_page(rx_buffer);
		put_page(tx_buffer);
		__free_page(rx_buffer);
		__free_page(tx_buffer);

		pr_err("%s: failed to register SPCI RxTx buffers\n", __func__);
		return ret;
	}

	return 0;
}

static struct platform_driver spci_driver = {
	.driver = {
		.name = "spci_protocol",
		.of_match_table = spci_of_match,
	},
	.probe = spci_probe,
};
module_platform_driver(spci_driver);

MODULE_AUTHOR("Arm");
MODULE_DESCRIPTION("Arm SPCI transport driver");
MODULE_LICENSE("GPL v2");
