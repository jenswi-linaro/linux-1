// SPDX-License-Identifier: GPL-2.0-only
/*
 * Secure Partitions Communication Interface (FFA) Protocol driver
 *
 * FFA is a system message passing and memory sharing protocol allowing for
 * execution contexts to exchange information with other execution contexts
 * residing on other Secure Partitions or Virtual Machines managed by any FFA
 * compliant firmware framework.
 *
 * Copyright (C) 2019, 2020 Arm Ltd.
 */
#define DEBUG

#include <linux/platform_device.h>
#include <linux/arm_ffa.h>
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

static ffa_sp_id_t vm_id;

static struct page *rx_buffer;
static struct page *tx_buffer;

static struct arm_smcccv1_2_return
(*arm_ffa_smccc)(u32 func, u64 arg1, u64 arg2, u64 arg3, u64 arg4,
		  u64 arg5, u64 arg6, u64 arg7);

#define FFA_DEFINE_CALL(conduit)					\
static struct arm_smcccv1_2_return					\
arm_ffa_##conduit(u32 func, u64 arg1, u64 arg2, u64 arg3, u64 arg4,	\
		   u64 arg5, u64 arg6, u64 arg7)			\
{									\
	struct arm_smcccv1_2_return smccc_ret;				\
									\
	__arm_smcccv1_2_##conduit(func, arg1, arg2, arg3, arg4, arg5,	\
				  arg6,	arg7, &smccc_ret);		\
									\
	return smccc_ret;						\
}

FFA_DEFINE_CALL(smc)
FFA_DEFINE_CALL(hvc)

static u32 sender_receiver_pack(u32 src_id, u32 dst_id)
{
	return (((src_id << 16) & 0xffff0000) | (dst_id & 0xffff));
}

int ffa_msg_send(ffa_sp_id_t dst_id, u32 len, u32 attributes)
{
	struct arm_smcccv1_2_return msg_send_return;

	/* w1[32:16] Sender endpoint ID, w1[15:0] destination endpoint id. */
	u32 sender_receiver = sender_receiver_pack(vm_id, dst_id);

	msg_send_return = arm_ffa_smccc(FFA_MSG_SEND_32, sender_receiver,
					 0, len, attributes, 0, 0, 0);

	if (msg_send_return.arg0  == FFA_ERROR_32) {
		switch ((int)msg_send_return.arg2) {
		case FFA_INVALID_PARAMETERS:
			return -ENXIO;
		case FFA_DENIED:
		case FFA_BUSY:
			return -EAGAIN;
		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      msg_send_return.arg2);
		}
	}
	return 0;
}

struct arm_smcccv1_2_return
ffa_msg_send_direct_req(ffa_sp_id_t dst_id, u64 w3, u64 w4, u64 w5,
			 u64 w6, u64 w7)
{
	struct arm_smcccv1_2_return ret;

	/* w1[32:16] Sender endpoint ID, w1[15:0] destination endpoint id. */
	u32 sender_receiver = sender_receiver_pack(vm_id, dst_id);

	ret = arm_ffa_smccc(FFA_MSG_SEND_DIRECT_REQ_32, sender_receiver, 0,
			     w3, w4, w5, w6, w7);

	while (ret.arg0 != FFA_MSG_SEND_DIRECT_RESP_32 &&
		ret.arg0 != FFA_SUCCESS_32) {
		if (ret.arg0 == FFA_ERROR_32) {
			pr_err("%s: Error sending message %llu\n", __func__,
				ret.arg0);
			switch ((int)ret.arg1) {
			case FFA_INVALID_PARAMETERS:
				ret.arg0 = -ENXIO;
				goto out;

			case FFA_DENIED:
			case FFA_NOT_SUPPORTED:
				ret.arg0 = -EIO;
				goto out;

			case FFA_BUSY:
				ret.arg0 = -EAGAIN;
				goto out;
			}
		} else if (ret.arg0 == FFA_INTERRUPT_32) {
			ret = arm_ffa_smccc(FFA_RUN_32, ret.arg1,
				0, 0, 0, 0, 0, 0);
		}

	}

	ret.arg0 = 0;

out:
	return ret;
}

static int ffa_share_next_frag(u64 handle, u32 frag_len, u32 *tx_offset)
{

	struct arm_smcccv1_2_return smccc_return;
	u32 handle_high = (handle >> 32) & 0xffffffff;
	u32 handle_low = handle & 0xffffffff;

	smccc_return =
		arm_ffa_smccc(FFA_MEM_FRAG_TX_32, handle_low,
			handle_high, frag_len, 0, 0, 0, 0);

	while (smccc_return.arg0 != FFA_MEM_FRAG_RX_32) {

		if (smccc_return.arg0 == FFA_ERROR_32) {
			switch ((int)smccc_return.arg2) {
			case FFA_INVALID_PARAMETERS:
				return -ENXIO;
			case FFA_NOT_SUPPORTED:
				return -ENODEV;
			default:
				pr_warn("%s: Unknown Error code %x\n", __func__,
					smccc_return.arg2);
				return -EIO;
			}
		}

		if (smccc_return.arg0 == FFA_MEM_OP_PAUSE_32) {

			smccc_return = arm_ffa_smccc(FFA_MEM_OP_RESUME_32,
				smccc_return.arg1, smccc_return.arg2, 0, 0, 0,
				0, 0);
		}
	}

	*tx_offset = smccc_return.arg3;

	return 0;
}

static int ffa_share_init_frag(phys_addr_t buffer, u32 buffer_size,
	u32 fragment_len, u32 total_len, u64 *handle)
{

	struct arm_smcccv1_2_return smccc_return;

	smccc_return =
		arm_ffa_smccc(FFA_MEM_SHARE_64, total_len, fragment_len, buffer,
		buffer_size, 0, 0, 0);

	while (smccc_return.arg0 != FFA_SUCCESS_32) {

		if (smccc_return.arg0 == FFA_ERROR_32) {
			switch ((int)smccc_return.arg2) {
			case FFA_INVALID_PARAMETERS:
				return -ENXIO;
			case FFA_DENIED:
				return -EIO;
			case FFA_NO_MEMORY:
				return -ENOMEM;
			case FFA_ABORTED:
				return -EAGAIN;
			default:
				pr_warn("%s: Unknown Error code %x\n", __func__,
					smccc_return.arg2);
				return -EIO;
			}
		}

		if (smccc_return.arg0 == FFA_MEM_OP_PAUSE_32) {

			smccc_return = arm_ffa_smccc(FFA_MEM_OP_RESUME_32,
				smccc_return.arg1, smccc_return.arg2, 0, 0, 0,
				0, 0);
		}
	}

	*handle = (smccc_return.arg3 << 32) | smccc_return.arg2;

	return 0;
}

static inline u32 compute_composite_offset(u32 num_attributes)
{
	u32 composite_offset = offsetof(struct ffa_mem_region,
		endpoints[num_attributes]);

	/* ensure composite are 8 byte aligned. */
	if (composite_offset & 0x7)
		return (composite_offset & (~(u32)0x7)) + 0x8;

	return composite_offset;
}

static inline u32 compute_constituent_offset(u32 num_attributes)
{
	u32 constituent_offset = offsetof(struct ffa_mem_region,
		endpoints[num_attributes]) +
		offsetof(struct ffa_composite_memory_region, constituents[0]);

	/* ensure constituents are 8 byte aligned. */
	if (constituent_offset & 0x7)
		return (constituent_offset & (~(u32)0x7)) + 0x8;

	return constituent_offset;
}

static inline u32 compute_region_length(u32 num_constituents,
	u32 num_attributes)
{
	/* This assumes that there is a single ffa_composite_memory_region. */
	return compute_constituent_offset(num_attributes) +
		sizeof(struct ffa_mem_region_constituent)*num_constituents;
}

static int ffa_rx_release(void)
{
	struct arm_smcccv1_2_return rx_release_return;

	rx_release_return = arm_ffa_smccc(FFA_RX_RELEASE_32,
					      0, 0, 0, 0, 0, 0, 0);

	if (rx_release_return.arg0 == FFA_ERROR_32) {
		switch ((int)rx_release_return.arg2) {
		case FFA_DENIED:
			return -EAGAIN;
		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      rx_release_return.arg2);
		}
	}

	if (rx_release_return.arg0 == FFA_RX_RELEASE_32) {
		/*
		 * FFA implementation returned FFA_RX_RELEASE which signals
		 * the PVM that other VMs need to be scheduled.
		 */
		return 1;
	}

	return 0;
}

static uint32_t ffa_get_num_pages_sg(struct scatterlist *sg)
{
	uint32_t num_pages = 0;

	do {
		num_pages += sg->length/PAGE_SIZE;
	} while ((sg = sg_next(sg)));

	return num_pages;
}

static inline struct ffa_memory_region_attribute ffa_set_region_normal(
	enum ffa_mem_cacheability cacheability,
	enum ffa_mem_shareability shareability)
{
	struct ffa_memory_region_attribute attr = {0};

	attr.attribute = (FFA_MEM_NORMAL << FFA_MEMTYPE_OFFSET) |
		(cacheability << FFA_CACHEABILITY_OFFSET) | shareability;

	return attr;
}

static inline struct ffa_memory_region_attribute ffa_set_region_device(
	enum ffa_mem_device_type device_type)
{
	struct ffa_memory_region_attribute attr = {0};

	attr.attribute = (FFA_MEM_DEVICE << FFA_MEMTYPE_OFFSET) |
		(device_type << FFA_DEVICE_OFFSET);

	return attr;
}

static inline int ffa_transmit_fragment(u32 *tx_offset, phys_addr_t buffer,
	u32 buffer_size, u32 frag_len, u32 total_len, u64 *handle)
{
	int rc;

	if (*tx_offset == 0) {
		rc = ffa_share_init_frag(buffer, buffer_size,
			frag_len, total_len, handle);

		*tx_offset = frag_len;
	} else
		rc = ffa_share_next_frag(*handle, frag_len, tx_offset);


	return rc;
}

/*
 * Share a set of pages with a list of destination endpoints.
 * Returns a system-wide unique handle
 */
static int _ffa_share_memory(u32 tag, enum mem_clear_t flags,
	struct ffa_mem_region_attributes *attrs,
	u32 num_attrs, struct scatterlist *sg, u32 nents,
	ffa_mem_handle_t *handle, phys_addr_t buffer, uint32_t buffer_size)
{
	struct ffa_mem_region *mem_region;
	u32 index;
	u32 num_constituents;
	struct ffa_mem_region_constituent *constituents;
	u32 total_len;
	u32 fragment_len = sizeof(struct ffa_mem_region);
	u32 max_fragment_size;
	int rc = 0;
	u32 tx_offset = 0;
	struct ffa_composite_memory_region *composite = NULL;

	if (buffer) {

		BUG_ON(!buffer_size);
		max_fragment_size = buffer_size * FFA_BASE_GRANULE_SIZE;
		mem_region = phys_to_virt(buffer);

	} else {

		BUG_ON(buffer_size);
		mem_region = (struct ffa_mem_region *)page_address(tx_buffer);
		max_fragment_size = FFA_BASE_GRANULE_SIZE;

	}

	mem_region->flags = flags;
	mem_region->tag = tag;
	mem_region->sender_id = vm_id;
	mem_region->region_attr = ffa_set_region_normal(FFA_WRITE_BACK,
		FFA_INNER_SHAREABLE);
	composite = ffa_get_composite(mem_region, num_attrs);
	composite->total_page_count = ffa_get_num_pages_sg(sg);

	fragment_len = compute_constituent_offset(num_attrs);

	/* Ensure attribute description fits within the Tx buffer. */
	if (fragment_len > max_fragment_size)
		return -ENXIO;

	constituents = (struct ffa_mem_region_constituent *)
		(((void *)mem_region) + fragment_len);

	composite->constituent_count = nents;
	total_len = compute_region_length(nents, num_attrs);

	for (index = 0; index < num_attrs; index++) {
		mem_region->endpoints[index].receiver = attrs[index].receiver;
		mem_region->endpoints[index].attrs =
			attrs[index].attrs;

		mem_region->endpoints[index].composite_off =
			compute_composite_offset(num_attrs);
	}
	mem_region->endpoint_count = num_attrs;

	num_constituents = 0;

	do {
		phys_addr_t address;

		/*
		 * If current fragment size equal Tx size trigger fragment
		 * transfer.
		 */
		if (fragment_len == max_fragment_size) {

			/* Transmit fragment. */
			rc = ffa_transmit_fragment(&tx_offset, buffer,
				buffer_size, fragment_len, total_len, handle);

			if (rc < 0)
				return -ENXIO;


			constituents =
				(struct ffa_mem_region_constituent *)mem_region;

			num_constituents = 0;
			fragment_len = 0;
		}

		address = sg_phys(sg);

		/*
		 * Detect if any part of the constituent region surpasses the Tx
		 * region.
		 */
		if (((void *) &constituents[num_constituents])
			- (void *)mem_region > max_fragment_size) {
			pr_err("%s: memory region fragment greater that the Tx buffer",
				__func__);
			return -EFAULT;
		}

		pr_devel("arm_ffa mem_share pa=%#lX\n", address);

		constituents[num_constituents].address = address;
		constituents[num_constituents].page_count =
			sg->length/PAGE_SIZE;
		num_constituents++;
		fragment_len += sizeof(struct ffa_mem_region_constituent);


	} while ((sg = sg_next(sg)));

	rc = ffa_transmit_fragment(&tx_offset, buffer, buffer_size,
		fragment_len, total_len, handle);

	return rc;
}

/*
 * Share a set of pages with a list of destination endpoints.
 *
 * Returns a system-wide unique handle
 */
static int ffa_share_memory(u32 tag, enum mem_clear_t flags,
	struct ffa_mem_region_attributes *attrs,
	u32 num_attrs, struct scatterlist *sg, u32 nents,
	ffa_mem_handle_t *global_handle, bool use_tx)
{
	u32 buffer_size = 0;
	phys_addr_t buffer_pa = 0;
	int ret;
	struct page *buffer_page = NULL;

	if (!use_tx) {
		/* Allocate buffer for this mem_share operation. */
		buffer_page = alloc_page(GFP_KERNEL);
		if (IS_ERR_OR_NULL(buffer_page)) {
			/* print error. Return as tx lock is not held. */
			pr_err("%s: unable to allocate buffer", __func__);
			return -ENOMEM;
		}

		buffer_pa = page_to_phys(buffer_page);

		buffer_size = 1;
	}

	if (use_tx)
		mutex_lock(&tx_lock);

	ret = _ffa_share_memory(tag, flags, attrs, num_attrs, sg, nents,
		global_handle, buffer_pa, buffer_size);

	if (use_tx)
		mutex_unlock(&tx_lock);

	return ret;
}

static int ffa_memory_reclaim(ffa_mem_handle_t global_handle,
	enum mem_clear_t flags)
{

	struct arm_smcccv1_2_return smccc_return;
	u32 handle_high = (global_handle >> 32) & 0xffffffff;
	u32 handle_low = global_handle & 0xffffffff;

	smccc_return = arm_ffa_smccc(FFA_MEM_RECLAIM_32, handle_low,
		handle_high, flags, 0, 0, 0, 0);

	if (smccc_return.arg0 == FFA_ERROR_32) {
		pr_err("%s: Error sending message %llu\n", __func__,
			smccc_return.arg0);
		switch ((int)smccc_return.arg2) {
		case FFA_INVALID_PARAMETERS:
			return -ENXIO;
		case FFA_DENIED:
		case FFA_NOT_SUPPORTED:
			return -EIO;
		case FFA_BUSY:
			return -EAGAIN;
		default:
			pr_warn("%s: Unknown Error code %x\n", __func__,
				smccc_return.arg2);
			return -EIO;
		}
	}

	return 0;
}

/*
 * Returns a negative value if function not supported. Otherwise returns w2,
 * supplying optional feature parameter else 0.
 */

static int ffa_features(uint32_t function_id)
{
	struct arm_smcccv1_2_return features_return =
		arm_ffa_smccc(FFA_FEATURES_32, function_id, 0, 0, 0, 0, 0, 0);

	if (features_return.arg0 == FFA_ERROR_32) {
		switch ((int)features_return.arg2) {
		case FFA_NOT_SUPPORTED:
			return -ENODEV;
		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      features_return.arg2);
		}
	} else {
		return features_return.arg2;
	}
}

static ffa_sp_id_t ffa_id_get(ffa_sp_id_t *vm_id_p)
{
	struct  arm_smcccv1_2_return id_get_return =
		arm_ffa_smccc(FFA_ID_GET_32, 0, 0, 0, 0, 0, 0, 0);

	if (id_get_return.arg0 == FFA_ERROR_32) {
		pr_warn("%s: failed to obtain vm id\n", __func__);
		return -EIO;
	}

	*vm_id_p = id_get_return.arg2 & 0xffff;

	return 0;
}

static int ffa_partition_info_get(uint32_t uuid0, uint32_t uuid1,
				     uint32_t uuid2, uint32_t uuid3,
				     struct ffa_partition_info **buffer)
{
	int rc = 0;
	uint32_t count;
	struct ffa_partition_info *info =
		(struct ffa_partition_info *) page_address(rx_buffer);
	struct arm_smcccv1_2_return partition_info_get_return;

	mutex_lock(&rx_lock);
	partition_info_get_return = arm_ffa_smccc(FFA_PARTITION_INFO_GET_32,
						   uuid0, uuid1, uuid2, uuid3,
						   0, 0, 0);

	if (partition_info_get_return.arg0 == FFA_ERROR_32) {
		switch ((int)partition_info_get_return.arg2) {
		case FFA_INVALID_PARAMETERS:
			rc = -ENXIO;
			goto err;
		case FFA_NO_MEMORY:
			rc = -ENOMEM;
			goto err;
		case FFA_NOT_SUPPORTED:
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
	*buffer = kzalloc(sizeof(struct ffa_partition_info) * count,
			  GFP_KERNEL);
	if (*buffer == NULL) {
		rc = -ENOMEM;
		goto err;
	}
	memcpy(*buffer, info, sizeof(struct ffa_partition_info) * count);

	ffa_rx_release();

	rc = count;
err:
	mutex_unlock(&rx_lock);

	return rc;
}

static struct ffa_ops ffa_ops = {
	.async_msg_send = ffa_msg_send,
	.sync_msg_send = ffa_msg_send_direct_req,
	.mem_share = ffa_share_memory,
	.mem_reclaim = ffa_memory_reclaim,
	.partition_info_get = ffa_partition_info_get,
};

struct ffa_ops *get_ffa_ops(void)
{
	return &ffa_ops;
}
EXPORT_SYMBOL_GPL(get_ffa_ops);

static int ffa_dt_init(struct device_node *np)
{
	const char *conduit;
	const char *selected_buffer;

	pr_info("FFA: obtaining conduit from DT.\n");

	if (of_property_read_string(np, "conduit", &conduit)) {
		pr_warn("FFA: cannot find conduit in DT\n");
		return -ENXIO;
	}

	if (!strcmp("smc", conduit))
		arm_ffa_smccc = arm_ffa_smc;
	else if (!strcmp("hvc", conduit))
		arm_ffa_smccc = arm_ffa_hvc;
	else {
		pr_warn("%s: unrecognized FFA conduit\n", __func__);
		return -EIO;
	}

	return 0;
}

static const struct of_device_id ffa_of_match[] = {
	{.compatible = "arm,ffa"},
	{},
};

static int ffa_rxtx_map(uintptr_t tx_page, uintptr_t rx_page)
{
	struct arm_smcccv1_2_return map_return;

	map_return = arm_ffa_smccc(FFA_RXTX_MAP_32, tx_page,
					 rx_page, 1, 0, 0, 0, 0);

	if (map_return.arg0 == FFA_ERROR_32) {
		switch ((int)map_return.arg2) {
		case FFA_INVALID_PARAMETERS:
			return -ENXIO;
		case FFA_DENIED:
			return -EAGAIN;
		case FFA_NO_MEMORY:
			return -ENOMEM;
		case FFA_NOT_SUPPORTED:
			return -ENODEV;

		default:
			panic("%s: Unhandled return code (%lld)\n", __func__,
			      map_return.arg2);
		}
	}

	return 0;
}

static int ffa_version_check(void)
{
	struct arm_smcccv1_2_return version_return;
	u16 major = 1;
	u16 minor = 0;
	u32 hv_version;

	version_return = arm_ffa_smccc(FFA_VERSION_32, ((u32)major<<16)|minor,
		 0, 0, 0, 0, 0, 0);

	if ((int)version_return.arg0 == FFA_NOT_SUPPORTED) {
		pr_err("%s: FFA ABI is not supported at higher exception levels\n",
			__func__);
		return -ENODEV;
	}

	hv_version = version_return.arg0;

	if ((hv_version>>16) == major)
		if ((hv_version & 0xffff) >= minor)
			return 0;

	pr_err("%s: incompatible FFA ABI at higher exception level (%x)\n",
		__func__, hv_version);
	return -ENODEV;
}

static int ffa_probe(struct platform_device *pdev)
{
	int ret;

	ret = ffa_dt_init(pdev->dev.of_node);
	if (ret) {
		pr_warn("%s: FFA driver initialization failed\n", __func__);
		return ret;
	}

	ret = ffa_version_check();
	if (ret)
		return ret;

	/* Initialize VM ID. */
	ret = ffa_id_get(&vm_id);
	if (ret) {
		pr_warn("%s: failed to obtain own FFA endpoint ID\n", __func__);
		return ret;
	}

	if (ffa_features(FFA_MSG_SEND_DIRECT_REQ_32)) {
		pr_err("%s: FFA implementation at EL2 does not support FFA_MSG_SEND_DIRECT_REQ_32\n",
			__func__);
		return -ENXIO;
	}

	/* Allocate Rx buffer. */
	rx_buffer = alloc_page(GFP_KERNEL);

	/*
	 * Ensure buffer was correctly allocated and that the refcout was
	 * incremented.
	 */
	if (!rx_buffer || !try_get_page(rx_buffer)) {
		pr_err("%s: failed to allocate FFA Rx buffer\n", __func__);
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

		pr_err("%s: failed to allocate FFA Tx buffer\n", __func__);
		return -ENOMEM;
	}

	/* Register the RxTx buffers with the FFA supervisor implementation. */
	ret = ffa_rxtx_map(page_to_phys(tx_buffer), page_to_phys(rx_buffer));
	if (ret) {
		put_page(rx_buffer);
		put_page(tx_buffer);
		__free_page(rx_buffer);
		__free_page(tx_buffer);

		pr_err("%s: failed to register FFA RxTx buffers\n", __func__);
		return ret;
	}

	return 0;
}

static struct platform_driver ffa_driver = {
	.driver = {
		.name = "ffa_protocol",
		.of_match_table = ffa_of_match,
	},
	.probe = ffa_probe,
};
module_platform_driver(ffa_driver);

MODULE_AUTHOR("Arm");
MODULE_DESCRIPTION("Arm FFA transport driver");
MODULE_LICENSE("GPL v2");
