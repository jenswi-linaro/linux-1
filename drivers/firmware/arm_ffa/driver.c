// SPDX-License-Identifier: GPL-2.0-only
/*
 * Arm Firmware Framework for ARMv8-A(FFA) interface driver
 *
 * The Arm FFA specification[1] describes a software architecture to
 * leverages the virtualization extension to isolate software images
 * provided by an ecosystem of vendors from each other and describes
 * interfaces that standardize communication between the various software
 * images including communication between images in the Secure world and
 * Normal world. Any Hypervisor could use the FFA interfaces to enable
 * communication between VMs it manages.
 *
 * The Hypervisor a.k.a Partition managers in FFA terminology can assign
 * system resources(Memory regions, Devices, CPU cycles) to the partitions
 * and manage isolation amongst them.
 *
 * [1] https://developer.arm.com/docs/den0077/latest
 *
 * Copyright (C) 2021 ARM Ltd.
 */

#define DRIVER_NAME "ARM FF-A"
#define pr_fmt(fmt) DRIVER_NAME ": " fmt

#include <linux/arm_ffa.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>

#include "common.h"

#define FFA_DRIVER_VERSION	FFA_VERSION_1_0

#define FFA_SMC(calling_convention, func_num)				\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, (calling_convention),	\
			   ARM_SMCCC_OWNER_STANDARD, (func_num))

#define FFA_SMC_32(func_num)	FFA_SMC(ARM_SMCCC_SMC_32, (func_num))
#define FFA_SMC_64(func_num)	FFA_SMC(ARM_SMCCC_SMC_64, (func_num))

#define FFA_ERROR			FFA_SMC_32(0x60)
#define FFA_SUCCESS			FFA_SMC_32(0x61)
#define FFA_FN64_SUCCESS		FFA_SMC_64(0x61)
#define FFA_INTERRUPT			FFA_SMC_32(0x62)
#define FFA_VERSION			FFA_SMC_32(0x63)
#define FFA_FEATURES			FFA_SMC_32(0x64)
#define FFA_RX_RELEASE			FFA_SMC_32(0x65)
#define FFA_RXTX_MAP			FFA_SMC_32(0x66)
#define FFA_FN64_RXTX_MAP		FFA_SMC_64(0x66)
#define FFA_RXTX_UNMAP			FFA_SMC_32(0x67)
#define FFA_PARTITION_INFO_GET		FFA_SMC_32(0x68)
#define FFA_ID_GET			FFA_SMC_32(0x69)
#define FFA_MSG_POLL			FFA_SMC_32(0x6A)
#define FFA_MSG_WAIT			FFA_SMC_32(0x6B)
#define FFA_YIELD			FFA_SMC_32(0x6C)
#define FFA_RUN				FFA_SMC_32(0x6D)
#define FFA_MSG_SEND			FFA_SMC_32(0x6E)
#define FFA_MSG_SEND_DIRECT_REQ		FFA_SMC_32(0x6F)
#define FFA_FN64_MSG_SEND_DIRECT_REQ	FFA_SMC_64(0x6F)
#define FFA_MSG_SEND_DIRECT_RESP	FFA_SMC_32(0x70)
#define FFA_FN64_MSG_SEND_DIRECT_RESP	FFA_SMC_64(0x70)
#define FFA_MEM_DONATE			FFA_SMC_32(0x71)
#define FFA_FN64_MEM_DONATE		FFA_SMC_64(0x71)
#define FFA_MEM_LEND			FFA_SMC_32(0x72)
#define FFA_FN64_MEM_LEND		FFA_SMC_64(0x72)
#define FFA_MEM_SHARE			FFA_SMC_32(0x73)
#define FFA_FN64_MEM_SHARE		FFA_SMC_64(0x73)
#define FFA_MEM_RETRIEVE_REQ		FFA_SMC_32(0x74)
#define FFA_FN64_MEM_RETRIEVE_REQ	FFA_SMC_64(0x74)
#define FFA_MEM_RETRIEVE_RESP		FFA_SMC_32(0x75)
#define FFA_MEM_RELINQUISH		FFA_SMC_32(0x76)
#define FFA_MEM_RECLAIM			FFA_SMC_32(0x77)
#define FFA_MEM_OP_PAUSE		FFA_SMC_32(0x78)
#define FFA_MEM_OP_RESUME		FFA_SMC_32(0x79)
#define FFA_MEM_FRAG_RX			FFA_SMC_32(0x7A)
#define FFA_MEM_FRAG_TX			FFA_SMC_32(0x7B)
#define FFA_NORMAL_WORLD_RESUME		FFA_SMC_32(0x7C)
#define FFA_NOTIFICATION_BIND		FFA_SMC_32(0x7F)
#define FFA_NOTIFICATION_UNBIND		FFA_SMC_32(0x80)
#define FFA_NOTIFICATION_SET		FFA_SMC_32(0x81)
#define FFA_NOTIFICATION_GET		FFA_SMC_32(0x82)
#define FFA_NOTIFICATION_INFO_GET	FFA_SMC_32(0x83)

/*
 * For some calls it is necessary to use SMC64 to pass or return 64-bit values.
 * For such calls FFA_FN_NATIVE(name) will choose the appropriate
 * (native-width) function ID.
 */
#ifdef CONFIG_64BIT
#define FFA_FN_NATIVE(name)	FFA_FN64_##name
#else
#define FFA_FN_NATIVE(name)	FFA_##name
#endif

/* FFA error codes. */
#define FFA_RET_SUCCESS            (0)
#define FFA_RET_NOT_SUPPORTED      (-1)
#define FFA_RET_INVALID_PARAMETERS (-2)
#define FFA_RET_NO_MEMORY          (-3)
#define FFA_RET_BUSY               (-4)
#define FFA_RET_INTERRUPTED        (-5)
#define FFA_RET_DENIED             (-6)
#define FFA_RET_RETRY              (-7)
#define FFA_RET_ABORTED            (-8)
#define FFA_RET_NO_DATA            (-9)

#define MAJOR_VERSION_MASK	GENMASK(30, 16)
#define MINOR_VERSION_MASK	GENMASK(15, 0)
#define MAJOR_VERSION(x)	((u16)(FIELD_GET(MAJOR_VERSION_MASK, (x))))
#define MINOR_VERSION(x)	((u16)(FIELD_GET(MINOR_VERSION_MASK, (x))))
#define PACK_VERSION_INFO(major, minor)			\
	(FIELD_PREP(MAJOR_VERSION_MASK, (major)) |	\
	 FIELD_PREP(MINOR_VERSION_MASK, (minor)))
#define FFA_VERSION_1_0		PACK_VERSION_INFO(1, 0)
#define FFA_MIN_VERSION		FFA_VERSION_1_0

#define SENDER_ID_MASK		GENMASK(31, 16)
#define RECEIVER_ID_MASK	GENMASK(15, 0)
#define SENDER_ID(x)		((u16)(FIELD_GET(SENDER_ID_MASK, (x))))
#define RECEIVER_ID(x)		((u16)(FIELD_GET(RECEIVER_ID_MASK, (x))))

#define RECEIVER_vCPU_MASK	GENMASK(31, 16)
#define NOTIFICATIONS_LO_MASK	GENMASK(31, 0)
#define NOTIFICATIONS_HI_MASK	GENMASK(63, 32)

#define PACK_TARGET_INFO(s, r)		\
	(FIELD_PREP(SENDER_ID_MASK, (s)) | FIELD_PREP(RECEIVER_ID_MASK, (r)))
#define PACK_NOTIFICATION_GET_RECEIVER_INFO(c, e)		\
	(FIELD_PREP(RECEIVER_vCPU_MASK, (c)) | FIELD_PREP(RECEIVER_ID_MASK, (e)))
#define UNPACK_NOTIFICATION_BITMAPS(h, l)	\
	((h) << 32 | (l))
#define GET_NOTIFICATION_BITMAP_HI(x)	(u32)(FIELD_GET(NOTIFICATIONS_HI_MASK, (x)))
#define GET_NOTIFICATION_BITMAP_LO(x)	(u32)(FIELD_GET(NOTIFICATIONS_LO_MASK, (x)))

/*
 * FF-A specification mentions explicitly about '4K pages'. This should
 * not be confused with the kernel PAGE_SIZE, which is the translation
 * granule kernel is configured and may be one among 4K, 16K and 64K.
 */
#define FFA_PAGE_SIZE		SZ_4K
/*
 * Keeping RX TX buffer size as 4K for now
 * 64K may be preferred to keep it min a page in 64K PAGE_SIZE config
 */
#define RXTX_BUFFER_SIZE	SZ_4K


/* Notification Prototyping*/
/* FFA FEATURES Feature IDs*/
#define FFA_FEAT_NOTIFICATION_PENDING_INT 0x1
#define FFA_FEAT_SCHED_RECV_INT 0x2

#define PER_VCPU_NOTIFICATION_FLAG BIT(0)
#define ALL_NOTIFICATION_BITMAPS_FLAGS 0xF

/* Define Architected Notifications. */
#define FFA_SPM_RX_BUFFER_FULL_NOTIFICATION_ID 0
#define FFA_HYP_RX_BUFFER_FULL_NOTIFICATION_ID 32

/* Store Schedule Receiver IRQ ID */
static u32 ffa_sched_recv_int_id;

#define SECURE_WORLD_MASK BIT(15)

/* Store callbacks for notifications */
#define MAX_PARTITIONS 15

#define INVALID_VM_ID 0x7FFF

/* Allocate list of VM structs to store information pertaining to a given partition.
 * TODO: Allocate dynamically based on Partition Info Get instead of statically.
 */
struct vm vms[MAX_PARTITIONS];

/* Helper functions for VM struct related information. */
static struct vm *get_vm_struct(ffa_partition_id_t partition_id) {
	int i;
	for (i = 0; i < MAX_PARTITIONS; i++) {
		/* Found matching VM. */
		if (vms[i].vm_id == partition_id) {
			return &vms[i];
		}
	}
	return NULL;
}

static int allocate_vm_struct(ffa_partition_id_t partition_id) {
	int i;
	/* Check if an existing VM struct exists. */
	if (get_vm_struct(partition_id))
		return -EACCES;

	/* If not, find the first avaliable slot.*/
	for (i = 0; i < MAX_PARTITIONS; i++) {
		if (vms[i].vm_id == INVALID_VM_ID) {
			vms[i].vm_id = partition_id;
			return 0;
		}
	}
	return -ENOMEM;
}
#define MAX_NOTIFICATIONS 64
struct notification_callback_info {
	ffa_partition_id_t vm_id;
	ffa_notification_callback callback;
	void *dev_data;
	u32 flags;
};

struct notification_callbacks {
	struct notification_callback_info from_vm[MAX_NOTIFICATIONS];
	struct notification_callback_info from_sp[MAX_NOTIFICATIONS];
	struct notification_callback_info from_framework[MAX_NOTIFICATIONS];
} notification_callbacks;

static ffa_fn *invoke_ffa_fn;

static const int ffa_linux_errmap[] = {
	/* better than switch case as long as return value is continuous */
	0,		/* FFA_RET_SUCCESS */
	-EOPNOTSUPP,	/* FFA_RET_NOT_SUPPORTED */
	-EINVAL,	/* FFA_RET_INVALID_PARAMETERS */
	-ENOMEM,	/* FFA_RET_NO_MEMORY */
	-EBUSY,		/* FFA_RET_BUSY */
	-EINTR,		/* FFA_RET_INTERRUPTED */
	-EACCES,	/* FFA_RET_DENIED */
	-EAGAIN,	/* FFA_RET_RETRY */
	-ECANCELED,	/* FFA_RET_ABORTED */
};

static inline bool is_secure_world(ffa_partition_id_t vm_id)
{
	return vm_id & SECURE_WORLD_MASK;
}

static inline int ffa_to_linux_errno(int errno)
{
	int err_idx = -errno;

	if (err_idx >= 0 && err_idx < ARRAY_SIZE(ffa_linux_errmap))
		return ffa_linux_errmap[err_idx];
	return -EINVAL;
}

struct ffa_drv_info {
	u32 version;
	u16 vm_id;
	struct mutex rx_lock; /* lock to protect Rx buffer */
	struct mutex tx_lock; /* lock to protect Tx buffer */
	void *rx_buffer;
	void *tx_buffer;
	struct mutex notifications_lock; /* lock to protect notification binding. */
};

/* In-direct message header */
struct message_header {
	u32 flags;
	u32 reserved;
	u32 offset;
	u32 src_dst;
	u32 size;
};

/* One time array initalisation functions. */
static void initialise_vm_structs(struct vm *vm, int size)
{
	int i;
	for (i=0; i < size; i++) {
		vms[i].vm_id = INVALID_VM_ID;
		vms[i].sched_recv_callback = NULL;
		vms[i].sched_recv_callback_data = NULL;
		rwlock_init(&vms[i].sched_recv_lock);
	}
}

/* One time array initalisation functions. */
static void initialise_notification_callback_struct(struct notification_callback_info *callback_struct,
						    int size)
{
	int i;
	for (i=0; i < size; i++) {
		callback_struct[i].callback = NULL;
		callback_struct[i].vm_id = INVALID_VM_ID;
	}
}

/* Helper Function to get corresponding notification callback list. */
static struct notification_callback_info *get_notification_callbacks(ffa_partition_id_t partition_id)
{
	struct notification_callback_info *callbacks;

	if (is_secure_world(partition_id)) {
		callbacks = notification_callbacks.from_sp;
	}
	else {
		callbacks = notification_callbacks.from_vm;
	}
	return callbacks;
}

static struct ffa_drv_info *drv_info;

/*
 * The driver must be able to support all the versions from the earliest
 * supported FFA_MIN_VERSION to the latest supported FFA_DRIVER_VERSION.
 * The specification states that if firmware supports a FFA implementation
 * that is incompatible with and at a greater version number than specified
 * by the caller(FFA_DRIVER_VERSION passed as parameter to FFA_VERSION),
 * it must return the NOT_SUPPORTED error code.
 */
static u32 ffa_compatible_version_find(u32 version)
{
	u16 major = MAJOR_VERSION(version), minor = MINOR_VERSION(version);
	u16 drv_major = MAJOR_VERSION(FFA_DRIVER_VERSION);
	u16 drv_minor = MINOR_VERSION(FFA_DRIVER_VERSION);

	if ((major < drv_major) || (major == drv_major && minor <= drv_minor))
		return version;

	pr_info("Firmware version higher than driver version, downgrading\n");
	return FFA_DRIVER_VERSION;
}

static int ffa_version_check(u32 *version)
{
	ffa_value_t ver;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_VERSION, .a1 = FFA_DRIVER_VERSION,
		      }, &ver);

	if (ver.a0 == FFA_RET_NOT_SUPPORTED) {
		pr_info("FFA_VERSION returned not supported\n");
		return -EOPNOTSUPP;
	}

	if (ver.a0 < FFA_MIN_VERSION) {
		pr_err("Incompatible v%d.%d! Earliest supported v%d.%d\n",
		       MAJOR_VERSION(ver.a0), MINOR_VERSION(ver.a0),
		       MAJOR_VERSION(FFA_MIN_VERSION),
		       MINOR_VERSION(FFA_MIN_VERSION));
		return -EINVAL;
	}

	pr_info("Driver version %d.%d\n", MAJOR_VERSION(FFA_DRIVER_VERSION),
		MINOR_VERSION(FFA_DRIVER_VERSION));
	pr_info("Firmware version %d.%d found\n", MAJOR_VERSION(ver.a0),
		MINOR_VERSION(ver.a0));
	*version = ffa_compatible_version_find(ver.a0);

	return 0;
}

static int ffa_rx_release(void)
{
	ffa_value_t ret;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_RX_RELEASE,
		      }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	/* check for ret.a0 == FFA_RX_RELEASE ? */

	return 0;
}

static int ffa_rxtx_map(phys_addr_t tx_buf, phys_addr_t rx_buf, u32 pg_cnt)
{
	ffa_value_t ret;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_FN_NATIVE(RXTX_MAP),
		      .a1 = tx_buf, .a2 = rx_buf, .a3 = pg_cnt,
		      }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	return 0;
}

static int ffa_rxtx_unmap(u16 vm_id)
{
	ffa_value_t ret;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_RXTX_UNMAP, .a1 = PACK_TARGET_INFO(vm_id, 0),
		      }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	return 0;
}

static void __do_schedule_receiver_callback(ffa_partition_id_t partition_id, ffa_vcpu_id_t vcpu, bool is_per_vcpu)
{
	struct vm *vm = get_vm_struct(partition_id);
	read_lock(&vm->sched_recv_lock);

	if (vm->sched_recv_callback == NULL){
		pr_err("Callback for partition 0x%x failed.\n", partition_id);
		return;
	}
	vm->sched_recv_callback(partition_id, vcpu, is_per_vcpu, vm->sched_recv_callback_data);
	read_unlock(&vm->sched_recv_lock);
}

/* buffer must be sizeof(struct ffa_partition_info) * num_partitions */
static int
__ffa_partition_info_get(u32 uuid0, u32 uuid1, u32 uuid2, u32 uuid3,
			 struct ffa_partition_info *buffer, int num_partitions)
{
	int count;
	ffa_value_t partition_info;

	mutex_lock(&drv_info->rx_lock);
	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_PARTITION_INFO_GET,
		      .a1 = uuid0, .a2 = uuid1, .a3 = uuid2, .a4 = uuid3,
		      }, &partition_info);

	if (partition_info.a0 == FFA_ERROR) {
		mutex_unlock(&drv_info->rx_lock);
		return ffa_to_linux_errno((int)partition_info.a2);
	}

	count = partition_info.a2;

	if (buffer && count <= num_partitions)
		memcpy(buffer, drv_info->rx_buffer, sizeof(*buffer) * count);

	ffa_rx_release();

	mutex_unlock(&drv_info->rx_lock);

	return count;
}

/* buffer is allocated and caller must free the same if returned count > 0 */
static int
ffa_partition_probe(const uuid_t *uuid, struct ffa_partition_info **buffer)
{
	int count;
	u32 uuid0_4[4];
	struct ffa_partition_info *pbuf;

	export_uuid((u8 *)uuid0_4, uuid);
	count = __ffa_partition_info_get(uuid0_4[0], uuid0_4[1], uuid0_4[2],
					 uuid0_4[3], NULL, 0);
	if (count <= 0)
		return count;

	pbuf = kcalloc(count, sizeof(*pbuf), GFP_KERNEL);
	if (!pbuf)
		return -ENOMEM;

	count = __ffa_partition_info_get(uuid0_4[0], uuid0_4[1], uuid0_4[2],
					 uuid0_4[3], pbuf, count);
	if (count <= 0)
		kfree(pbuf);
	else
		*buffer = pbuf;

	return count;
}

#define VM_ID_MASK	GENMASK(15, 0)
static int ffa_id_get(u16 *vm_id)
{
	ffa_value_t id;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_ID_GET,
		      }, &id);

	if (id.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)id.a2);

	*vm_id = FIELD_GET(VM_ID_MASK, (id.a2));

	return 0;
}

/* Notification Info Get Related */
#define NOTIFICATION_INFO_GET_PARTITION_ID_MASK GENMASK(15, 0)
#define NOTIFICATION_INFO_GET_MORE_PENDING	GENMASK(1, 0)
#define NOTIFICATION_INFO_GET_ID_COUNT		GENMASK(11, 7)
#define PARTITION_ID_SIZE 16

#define MAX_IDS_64 20
#define ID_LIST_MASK_64 GENMASK(63, 12)

/* Allow indexing into the IDs returned by a notification info get call. */
static u16 __unpack_info_get_id(ffa_value_t *ret, u32 idx)
{
	u16 *packed_id_list;
	/* Ensure we can only index into valid IDs.*/
	if (idx >= MAX_IDS_64) {
		pr_err("Attempting to access invalid ID\n");
		return 0;
	}
	/* The response from a partition info get call is a packed list of
	 * partition and vcpu IDs. Therfore we can cast the field containing
	 * the first ID into an array of 16 bit IDs and index accordingly. */
	packed_id_list = (u16*) &ret->a3;
	/* Return the partiion ID return at the corresponding index. */
	return packed_id_list[idx];
}

static void ffa_notification_info_get64(void)
{
	ffa_value_t ret;
	bool call_again;
	u8 count_of_lists;

	u8 ids_processed;
	u8 total_ids = 0;
	u16 ids_count[MAX_IDS_64];
	u32 idx, list;
	u64 id_list;

	pr_debug("Calling Notification Info Get handling on cpu %d\n", smp_processor_id());

	do {
		invoke_ffa_fn((ffa_value_t){
			/* Note: We currently only support the 64 bit version of this interface. */
			  .a0 = FFA_SMC_64(FFA_NOTIFICATION_INFO_GET)
			  }, &ret);

		if (ret.a0 == FFA_ERROR) {
			if (ret.a2 == FFA_RET_NO_DATA) {
				pr_debug("No data available for Notification Info Get\n");
				return;
			}
			pr_err("Notification Info Get Failed: 0x%lx(0x%lx)", ret.a0, ret.a2);
			return;
		}
		else if (ret.a0 == FFA_SUCCESS) {
			pr_err("Received a 32bit response to a 64bit call.");
			return; /* Something else went wrong. */
		}

		ids_processed = 0;
		call_again = FIELD_GET(NOTIFICATION_INFO_GET_MORE_PENDING, (ret.a2));
		count_of_lists = FIELD_GET(NOTIFICATION_INFO_GET_ID_COUNT, (ret.a2));
		id_list =  FIELD_GET(ID_LIST_MASK_64, (ret.a2));

		/* Process ID list and count how many ids we have to process */
		for (idx=0; idx < count_of_lists; idx++) {
			/* Note ID count begins at 0. */
			ids_count[idx] = (id_list & 0x3);
			total_ids += ids_count[idx];
			id_list = id_list >> 2;
		}

		/* Process IDs */
		/* For each notification make our call back */
		for (list = 0; list < count_of_lists; list++) {
			u16 partition_id;

			if (ids_processed >= MAX_IDS_64){
				pr_err("Maximum IDs Exceeded!\n");
				break;
			}

			/* The next ID to unpack is a partition ID, retrieve and increment processed ID count. */
			partition_id = __unpack_info_get_id(&ret, ids_processed++);

			/* Global Notification, no vcpu IDs to process. */
			if (ids_count[list] == 0) {
				pr_debug("Calling global schedule receiver callback for 0x%x\n", partition_id);
				__do_schedule_receiver_callback(partition_id, 0, false);
			}
			/* Per vCPU Notification, process X IDs based on length of list specified. */
			else {
				/* Use IDs count (count from 0) as vcpu count. */
				for (idx = 0; idx < ids_count[list]; idx++) {
					/* The next ID to unpack is a vcpu ID, retrieve and increment count. */
					u16 vcpu_id = __unpack_info_get_id(&ret, ids_processed++);
					pr_debug("Calling schedule receiver callback for 0x%x for vcpu: %d\n",
						partition_id, vcpu_id);
					__do_schedule_receiver_callback(partition_id, vcpu_id, true);
				}
			}
		}
	} while(call_again);
}

static int __ffa_notification_bind_common(ffa_partition_id_t dst_id, u32 flags,
					  u64 notifications_bitmap, bool is_bind)
{
	u32 func;
	ffa_value_t ret;
	ffa_partition_id_t src_id = drv_info->vm_id;
	u32 not_lo, not_hi, send_rec_ids = PACK_TARGET_INFO(dst_id, src_id);

	not_lo = GET_NOTIFICATION_BITMAP_LO(notifications_bitmap);
	not_hi = GET_NOTIFICATION_BITMAP_HI(notifications_bitmap);

	func = is_bind ? FFA_NOTIFICATION_BIND : FFA_NOTIFICATION_UNBIND;

	invoke_ffa_fn((ffa_value_t){
		  .a0 = func, .a1 = send_rec_ids, .a2 = flags,
		  .a3 = not_lo, .a4 = not_hi,
		  }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);
	else if (ret.a0 != FFA_SUCCESS)
		return -EINVAL; /* Something else went wrong. */

	return 0;
}

static int ffa_notification_bind(ffa_partition_id_t dst_id, u32 flags, u64 notifications_bitmap)
{
	return __ffa_notification_bind_common(dst_id, flags, notifications_bitmap, true);
}

static int ffa_notification_unbind(ffa_partition_id_t dst_id, u64 notifications_bitmap)
{
	return __ffa_notification_bind_common(dst_id, 0, notifications_bitmap, false);
}

static int ffa_notification_set(ffa_partition_id_t src_id, ffa_partition_id_t dst_id,
				u32 flags, u64 notifications_bitmap)
{
	ffa_value_t ret;
	u32 not_lo, not_hi, src_dst_ids = PACK_TARGET_INFO(dst_id, src_id);

	not_hi = GET_NOTIFICATION_BITMAP_HI(notifications_bitmap);
	not_lo = GET_NOTIFICATION_BITMAP_LO(notifications_bitmap);

	invoke_ffa_fn((ffa_value_t) {
		  .a0 = FFA_NOTIFICATION_SET, .a1 = src_dst_ids, .a2 = flags,
		  .a3 = not_lo, .a4 = not_hi,
		  }, &ret);


	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);
	else if (ret.a0 != FFA_SUCCESS)
		return -EINVAL; /* Something else went wrong. */

	return 0;
}

static int ffa_notification_get(u32 flags, struct ffa_notification_bitmaps *notifications)
{
	ffa_value_t ret;
	ffa_partition_id_t src_id = drv_info->vm_id;
	u16 cpu_id = smp_processor_id();
	u32 rec_vcpu_ids = PACK_NOTIFICATION_GET_RECEIVER_INFO(cpu_id, src_id);

 	invoke_ffa_fn((ffa_value_t){
		  .a0 = FFA_NOTIFICATION_GET, .a1 = rec_vcpu_ids, .a2 = flags,
		  }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);
	else if (ret.a0 != FFA_SUCCESS)
		return -EINVAL; /* Something else went wrong. */

	notifications->sp_notifications = UNPACK_NOTIFICATION_BITMAPS(ret.a3, ret.a2);
	notifications->vm_notifications = UNPACK_NOTIFICATION_BITMAPS(ret.a5, ret.a4);
	notifications->architected_notifications = UNPACK_NOTIFICATION_BITMAPS(ret.a7, ret.a6);

	return 0;
}

static int ffa_run(struct ffa_device *dev, ffa_vcpu_id_t vcpu)
{
	ffa_value_t ret;
	u32 target_info = dev->vm_id << 16 | vcpu;
	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_RUN, .a1 = target_info,
		      }, &ret);
	while (ret.a0 == FFA_INTERRUPT)
		invoke_ffa_fn((ffa_value_t){ .a0 = FFA_RUN, .a1 = ret.a1, }, &ret);
	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	return 0;
}

static int ffa_msg_send_direct_req(ffa_partition_id_t src_id, ffa_partition_id_t dst_id, bool mode_32bit,
				   struct ffa_send_direct_data *data)
{
	u32 req_id, resp_id, src_dst_ids = PACK_TARGET_INFO(src_id, dst_id);
	ffa_value_t ret;

	if (mode_32bit) {
		req_id = FFA_MSG_SEND_DIRECT_REQ;
		resp_id = FFA_MSG_SEND_DIRECT_RESP;
	} else {
		req_id = FFA_FN_NATIVE(MSG_SEND_DIRECT_REQ);
		resp_id = FFA_FN_NATIVE(MSG_SEND_DIRECT_RESP);
	}

	invoke_ffa_fn((ffa_value_t){
		      .a0 = req_id, .a1 = src_dst_ids, .a2 = 0,
		      .a3 = data->data0, .a4 = data->data1, .a5 = data->data2,
		      .a6 = data->data3, .a7 = data->data4,
		      }, &ret);

	while (ret.a0 == FFA_INTERRUPT)
		invoke_ffa_fn((ffa_value_t){
			      .a0 = FFA_RUN, .a1 = ret.a1,
			      }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	if (ret.a0 == resp_id) {
		data->data0 = ret.a3;
		data->data1 = ret.a4;
		data->data2 = ret.a5;
		data->data3 = ret.a6;
		data->data4 = ret.a7;
		return 0;
	}

	return -EINVAL;
}

static int ffa_mem_first_frag(u32 func_id, phys_addr_t buf, u32 buf_sz,
			      u32 frag_len, u32 len, u64 *handle)
{
	ffa_value_t ret;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = func_id, .a1 = len, .a2 = frag_len,
		      .a3 = buf, .a4 = buf_sz,
		      }, &ret);

	while (ret.a0 == FFA_MEM_OP_PAUSE)
		invoke_ffa_fn((ffa_value_t){
			      .a0 = FFA_MEM_OP_RESUME,
			      .a1 = ret.a1, .a2 = ret.a2,
			      }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	if (ret.a0 != FFA_SUCCESS)
		return -EOPNOTSUPP;

	if (handle)
		*handle = PACK_HANDLE(ret.a2, ret.a3);

	return frag_len;
}

static int ffa_mem_next_frag(u64 handle, u32 frag_len)
{
	ffa_value_t ret;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_MEM_FRAG_TX,
		      .a1 = HANDLE_LOW(handle), .a2 = HANDLE_HIGH(handle),
		      .a3 = frag_len,
		      }, &ret);

	while (ret.a0 == FFA_MEM_OP_PAUSE)
		invoke_ffa_fn((ffa_value_t){
			      .a0 = FFA_MEM_OP_RESUME,
			      .a1 = ret.a1, .a2 = ret.a2,
			      }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	if (ret.a0 != FFA_MEM_FRAG_RX)
		return -EOPNOTSUPP;

	return ret.a3;
}

static int
ffa_transmit_fragment(u32 func_id, phys_addr_t buf, u32 buf_sz, u32 frag_len,
		      u32 len, u64 *handle, bool first)
{
	if (!first)
		return ffa_mem_next_frag(*handle, frag_len);

	return ffa_mem_first_frag(func_id, buf, buf_sz, frag_len, len, handle);
}

static u32 ffa_get_num_pages_sg(struct scatterlist *sg)
{
	u32 num_pages = 0;

	do {
		num_pages += sg->length / FFA_PAGE_SIZE;
	} while ((sg = sg_next(sg)));

	return num_pages;
}

static int
ffa_setup_and_transmit(u32 func_id, void *buffer, u32 max_fragsize,
		       struct ffa_mem_ops_args *args)
{
	int rc = 0;
	bool first = true;
	phys_addr_t addr = 0;
	struct ffa_composite_mem_region *composite;
	struct ffa_mem_region_addr_range *constituents;
	struct ffa_mem_region_attributes *ep_mem_access;
	struct ffa_mem_region *mem_region = buffer;
	u32 idx, frag_len, length, buf_sz = 0, num_entries = sg_nents(args->sg);

	mem_region->tag = args->tag;
	mem_region->flags = args->flags;
	mem_region->sender_id = drv_info->vm_id;
	mem_region->attributes = FFA_MEM_NORMAL | FFA_MEM_WRITE_BACK |
				 FFA_MEM_INNER_SHAREABLE;
	ep_mem_access = &mem_region->ep_mem_access[0];

	for (idx = 0; idx < args->nattrs; idx++, ep_mem_access++) {
		ep_mem_access->receiver = args->attrs[idx].receiver;
		ep_mem_access->attrs = args->attrs[idx].attrs;
		ep_mem_access->composite_off = COMPOSITE_OFFSET(args->nattrs);
	}
	mem_region->ep_count = args->nattrs;

	composite = buffer + COMPOSITE_OFFSET(args->nattrs);
	composite->total_pg_cnt = ffa_get_num_pages_sg(args->sg);
	composite->addr_range_cnt = num_entries;

	length = COMPOSITE_CONSTITUENTS_OFFSET(args->nattrs, num_entries);
	frag_len = COMPOSITE_CONSTITUENTS_OFFSET(args->nattrs, 0);
	if (frag_len > max_fragsize)
		return -ENXIO;

	if (!args->use_txbuf) {
		addr = virt_to_phys(buffer);
		buf_sz = max_fragsize / FFA_PAGE_SIZE;
	}

	constituents = buffer + frag_len;
	idx = 0;
	do {
		if (frag_len == max_fragsize) {
			rc = ffa_transmit_fragment(func_id, addr, buf_sz,
						   frag_len, length,
						   &args->g_handle, first);
			if (rc < 0)
				return -ENXIO;

			first = false;
			idx = 0;
			frag_len = 0;
			constituents = buffer;
		}

		if ((void *)constituents - buffer > max_fragsize) {
			pr_err("Memory Region Fragment > Tx Buffer size\n");
			return -EFAULT;
		}

		constituents->address = sg_phys(args->sg);
		constituents->pg_cnt = args->sg->length / FFA_PAGE_SIZE;
		constituents++;
		frag_len += sizeof(struct ffa_mem_region_addr_range);
	} while ((args->sg = sg_next(args->sg)));

	return ffa_transmit_fragment(func_id, addr, buf_sz, frag_len,
				     length, &args->g_handle, first);
}

static int ffa_memory_ops(u32 func_id, struct ffa_mem_ops_args *args)
{
	int ret;
	void *buffer;

	if (!args->use_txbuf) {
		buffer = alloc_pages_exact(RXTX_BUFFER_SIZE, GFP_KERNEL);
		if (!buffer)
			return -ENOMEM;
	} else {
		buffer = drv_info->tx_buffer;
		mutex_lock(&drv_info->tx_lock);
	}

	ret = ffa_setup_and_transmit(func_id, buffer, RXTX_BUFFER_SIZE, args);

	if (args->use_txbuf)
		mutex_unlock(&drv_info->tx_lock);
	else
		free_pages_exact(buffer, RXTX_BUFFER_SIZE);

	return ret < 0 ? ret : 0;
}

static int ffa_memory_reclaim(u64 g_handle, u32 flags)
{
	ffa_value_t ret;

	invoke_ffa_fn((ffa_value_t){
		      .a0 = FFA_MEM_RECLAIM,
		      .a1 = HANDLE_LOW(g_handle), .a2 = HANDLE_HIGH(g_handle),
		      .a3 = flags,
		      }, &ret);

	if (ret.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)ret.a2);

	return 0;
}

static u32 ffa_api_version_get(void)
{
	return drv_info->version;
}

static int ffa_partition_info_get(const char *uuid_str,
				  struct ffa_partition_info *buffer)
{
	int count;
	uuid_t uuid;
	struct ffa_partition_info *pbuf;

	if (uuid_parse(uuid_str, &uuid)) {
		pr_err("invalid uuid (%s)\n", uuid_str);
		return -ENODEV;
	}

	count = ffa_partition_probe(&uuid_null, &pbuf);
	if (count <= 0)
		return -ENOENT;

	memcpy(buffer, pbuf, sizeof(*pbuf) * count);
	kfree(pbuf);
	return 0;
}

static void ffa_mode_32bit_set(struct ffa_device *dev)
{
	dev->mode_32bit = true;
}

static int ffa_sync_send_receive(struct ffa_device *dev,
				 struct ffa_send_direct_data *data)
{
	return ffa_msg_send_direct_req(drv_info->vm_id, dev->vm_id,
				       dev->mode_32bit, data);
}

static int
ffa_memory_share(struct ffa_device *dev, struct ffa_mem_ops_args *args)
{
	if (dev->mode_32bit)
		return ffa_memory_ops(FFA_MEM_SHARE, args);

	return ffa_memory_ops(FFA_FN_NATIVE(MEM_SHARE), args);
}

static int
ffa_send_notification(struct ffa_device *dev, ffa_notification_id_t notification_id,
		      bool is_per_vcpu, ffa_vcpu_id_t vcpu)
{
	u64 bitmap = 0;
	u32 flags = 0;


	/* Set the flags accordinly. */
	if (is_per_vcpu) {
		flags |= PER_VCPU_NOTIFICATION_FLAG;
		flags |= vcpu << 16;
	}
	else {
		/* If we are, ensure vcpu has not also been set. */
		if (vcpu){
			return -EINVAL;
		}
	}

	bitmap = (u64) 1 << notification_id;
	return ffa_notification_set(dev->vm_id, drv_info->vm_id, flags, bitmap);
}

/* Schedule Receiver Registration functions */
static int
update_schedule_receiver_callback(ffa_partition_id_t partition_id, ffa_sched_recv_callback callback,
					void *callback_data, bool is_registration)
{
	int ret = 0;
	struct vm *vm = get_vm_struct(partition_id);
	write_lock(&vm->sched_recv_lock);

	if (is_registration){
		if (vm->sched_recv_callback != NULL) {
			pr_err("Notification callback already registered for partition: 0x%x\n",  partition_id);
			ret = -EINVAL;
			goto out;
		}
	}
	else {
		if (vm->sched_recv_callback == NULL) {
			pr_err("Notification callback was not registered for partition: 0x%x\n",  partition_id);
			ret = -EINVAL;
			goto out;
		}
	}

	vm->sched_recv_callback = callback;
	vm->sched_recv_callback_data = callback_data;

	pr_debug("Notification callback updated for partition: 0x%x\n", partition_id);

out:
	write_unlock(&vm->sched_recv_lock);
	return ret;
}

static int
ffa_register_schedule_receiver_callback(struct ffa_device *dev, ffa_sched_recv_callback callback,
					void *callback_data)
{
	return update_schedule_receiver_callback(dev->vm_id, callback, callback_data, true);
}

static int
ffa_unregister_schedule_receiver_callback(struct ffa_device *dev)
{
	return update_schedule_receiver_callback(dev->vm_id, NULL, NULL, false);
}

static int
update_notification_callback(ffa_partition_id_t partition_id, ffa_notification_id_t notification_id,
			     ffa_notification_callback callback, void *dev_data, bool is_registration)
{
	struct notification_callback_info *callbacks = get_notification_callbacks(partition_id);
	ffa_partition_id_t id = is_registration ? partition_id : INVALID_VM_ID;

	if (notification_id >= MAX_NOTIFICATIONS) {
		return -EINVAL;
	}

	if (is_registration) {
		if (callbacks[notification_id].callback != NULL) {
			pr_err("Callback already registered for notification id: %d!\n", notification_id);
			return -EPERM;
		}
	}
	else {
		if (callbacks[notification_id].vm_id != partition_id) {
			pr_err("Attempting to relinquish notification for another partition ID!\n");
			return -EPERM;
		}
	}

	callbacks[notification_id].vm_id = id;
	callbacks[notification_id].callback = callback;
	callbacks[notification_id].dev_data = dev_data;

	return 0;
}

static int configure_architected_notification(int notification_id, ffa_notification_callback callback)
{
	struct notification_callback_info *notification;

	if (notification_id < 0 || notification_id >= MAX_NOTIFICATIONS)
		return -EINVAL;

	notification = &notification_callbacks.from_framework[notification_id];
	if (notification->callback != NULL)
		return -EPERM;

	notification->callback = callback;

	return 0;
}

static int
ffa_relinquish_notification(struct ffa_device *dev, ffa_notification_id_t notification_id){

	int rc;
	u64 bitmap = 0;

	if (notification_id >= MAX_NOTIFICATIONS) {
		return -EINVAL;
	}

	mutex_lock(&drv_info->notifications_lock);
	/* Attempt to unregister callback. */
	rc = update_notification_callback(dev->vm_id, notification_id, NULL, NULL, false);

	if (rc) {
		pr_err("Could not unregister notifcation callback\n");
		mutex_unlock(&drv_info->notifications_lock);
		return rc;
	}

	bitmap = 0x1 << notification_id;

	rc = ffa_notification_unbind(dev->vm_id, bitmap);

	mutex_unlock(&drv_info->notifications_lock);

	return rc;
}

static int
ffa_request_notification(struct ffa_device *dev, bool is_per_vcpu,
			 ffa_notification_callback callback, void *dev_data)
{
	int i, rc;
	u32 flags = 0;
	u64 bitmap = 0;
	int notification_id = -1;
	struct notification_callback_info *callbacks = get_notification_callbacks(dev->vm_id);

	mutex_lock(&drv_info->notifications_lock);

	/* Find the first non allocated notification ID */
	for (i = 0; i < MAX_NOTIFICATIONS; i++) {
		if (callbacks[i].callback == NULL) {
			notification_id = i;
			break;
		}
	}
	if (notification_id < 0) {
		mutex_unlock(&drv_info->notifications_lock);
		return -ENOMEM;
	}

	if (is_per_vcpu) {
		flags |= PER_VCPU_NOTIFICATION_FLAG;
	}

	bitmap = (u64) 0x1 << notification_id;

	rc = ffa_notification_bind(dev->vm_id, flags, bitmap);

	mutex_unlock(&drv_info->notifications_lock);

	if (rc) {
		pr_err("Failed to bind notification: %d\n", rc);
		return rc;
	}

	/* Success, store the partition ID and register callback */
	callbacks[notification_id].flags = flags;

	rc = update_notification_callback(dev->vm_id, notification_id, callback, dev_data, true);

	/* Something went wrong, attempt to relinquish notification ID. */
	if (rc) {
		pr_err("Failed to register callback for %d - %d\n", notification_id, rc);
		ffa_relinquish_notification(dev, notification_id);
		return -rc;
	}

	return notification_id;
}

static void
handle_notification_bitmap(u64 *bitmap,
			  struct notification_callback_info *callbacks)
{
	int i;
	for (i = 0; i < MAX_NOTIFICATIONS; i++){
		if (((u64) 1 << i) & *bitmap){
			struct notification_callback_info *cb_info = &callbacks[i];
			if (cb_info->callback == NULL){
				pr_err("No Handler for Notification %d!; Ignoring\n", i);
			}
			else {
				cb_info->callback(cb_info->vm_id, i, cb_info->dev_data);
			}
		}
	}
	return;
}

static void handle_notifications(struct work_struct *unused)
{
	int rc;
	u32 flags = 0;
	struct ffa_notification_bitmaps bitmaps;

	pr_debug("Handling Notifications on cpu: %d\n", smp_processor_id());

	/* Get all notification bitmaps */
	flags |= ALL_NOTIFICATION_BITMAPS_FLAGS;

	rc = ffa_notification_get(flags, &bitmaps);

	if (rc) {
		pr_err("Failed to retreive notifications with %d!\n", rc);
		return;
	}

	/* Handle VM and SP Partition Notifications */
	pr_debug("Handling VM Notifications...\n");
	handle_notification_bitmap(&bitmaps.vm_notifications,
			           notification_callbacks.from_vm);
	pr_debug("Handling SP Notification...\n");
	handle_notification_bitmap(&bitmaps.sp_notifications,
			           notification_callbacks.from_sp);
	pr_debug("Handling Architected Notification...\n");
	handle_notification_bitmap(&bitmaps.architected_notifications,
			           notification_callbacks.from_framework);

	return;
}
DECLARE_WORK(handle_notifications_work, handle_notifications);

static void handle_self_notification(ffa_partition_id_t partition_id,
		                    ffa_vcpu_id_t vcpu_target, bool is_per_vcpu, void *callback_data)
{
	/* If it is a global notification, schedule the handling on any cpu. */
	if (!is_per_vcpu) {
		pr_debug("Scheduleing notification handling from cpu: %d\n", smp_processor_id());
		schedule_work(&handle_notifications_work);
	}
	/* Otherwise ensure the work is scheduled on the target vcpu. */
	else {
		pr_debug("Requesting handeling of notification on cpu: %d - from cpu: %d\n",
			 vcpu_target, smp_processor_id());
		schedule_work_on(vcpu_target, &handle_notifications_work);
	}
	return;
}

/* Handle the RX buffer full architected notification. */
static void handle_rx_full_notification(ffa_partition_id_t partition_id,
					ffa_notification_id_t notification_id, void *dev_data)
{
	void *rx_buffer = drv_info->rx_buffer;
	struct message_header *header = rx_buffer;
	ffa_partition_id_t sender = SENDER_ID(header->src_dst);
	char *message =  rx_buffer + header->offset;

	pr_info("Indirect Message Received!\n");
	pr_info("Sender: 0x%x, Size: %d Flags: 0x%x Body: \"%s\"\n", sender, header->size, header->flags, message);

	ffa_rx_release();
}

static const struct ffa_dev_ops ffa_ops = {
	.api_version_get = ffa_api_version_get,
	.partition_info_get = ffa_partition_info_get,
	.mode_32bit_set = ffa_mode_32bit_set,
	.sync_send_receive = ffa_sync_send_receive,
	.memory_reclaim = ffa_memory_reclaim,
	.memory_share = ffa_memory_share,
	.register_schedule_receiver_callback = ffa_register_schedule_receiver_callback,
	.unregister_schedule_receiver_callback = ffa_unregister_schedule_receiver_callback,
	.request_notification = ffa_request_notification,
	.relinquish_notification = ffa_relinquish_notification,
	.send_notification = ffa_send_notification,
	.run = ffa_run,
};

const struct ffa_dev_ops *ffa_dev_ops_get(struct ffa_device *dev)
{
	if (ffa_device_is_valid(dev))
		return &ffa_ops;

	return NULL;
}
EXPORT_SYMBOL_GPL(ffa_dev_ops_get);

void ffa_device_match_uuid(struct ffa_device *ffa_dev, const uuid_t *uuid)
{
	int count, idx;
	struct ffa_partition_info *pbuf, *tpbuf;

	count = ffa_partition_probe(uuid, &pbuf);
	if (count <= 0)
		return;

	for (idx = 0, tpbuf = pbuf; idx < count; idx++, tpbuf++)
		if (tpbuf->id == ffa_dev->vm_id)
			uuid_copy(&ffa_dev->uuid, uuid);
	kfree(pbuf);
}

static void ffa_setup_partitions(void)
{
	int count, idx;
	struct ffa_device *ffa_dev;
	struct ffa_partition_info *pbuf, *tpbuf;

	count = ffa_partition_probe(&uuid_null, &pbuf);
	if (count <= 0) {
		pr_info("%s: No partitions found, error %d\n", __func__, count);
		return;
	}

	for (idx = 0, tpbuf = pbuf; idx < count; idx++, tpbuf++) {
		/* Note that the &uuid_null parameter will require
		 * ffa_device_match() to find the UUID of this partition id
		 * with help of ffa_device_match_uuid(). Once the FF-A spec
		 * is updated to provide correct UUID here for each partition
		 * as part of the discovery API, we need to pass the
		 * discovered UUID here instead.
		 */
		ffa_dev = ffa_device_register(&uuid_null, tpbuf->id);
		if (!ffa_dev) {
			pr_err("%s: failed to register partition ID 0x%x\n",
			       __func__, tpbuf->id);
			continue;
		}

		ffa_dev_set_drvdata(ffa_dev, drv_info);

		if (allocate_vm_struct(tpbuf->id)) {
			pr_err("%s: failed to assign partition struct for partition ID 0x%x\n",
			       __func__, tpbuf->id);
		}
	}
	kfree(pbuf);
}


static int ffa_features(u32 function_id, u32 feature_id)
{
	ffa_value_t  id;

	if (feature_id && function_id << 31){
		pr_err("Invalid Parameters: %x, %x", function_id, feature_id);
		return ffa_to_linux_errno(-2);
	}

	invoke_ffa_fn((ffa_value_t){
              .a0 = FFA_FEATURES, .a1 = function_id, .a2 = feature_id,
              }, &id);

	if (id.a0 == FFA_ERROR)
		return ffa_to_linux_errno((int)id.a2);

	return id.a2;
}


/* Handle an SGI */
static irqreturn_t irq_handler(int irq, void *dev)
{
	ffa_notification_info_get64();
	return IRQ_HANDLED;
}


/* Helper function to register on all CPUS. */
static void __enable_schedule_receiver_interrupt(void* unused) {
	enable_percpu_irq(ffa_sched_recv_int_id, IRQ_TYPE_EDGE_RISING);
	pr_info("Enabled Scheduler Receiver IRQ %d on cpu: %d\n",
			ffa_sched_recv_int_id, smp_processor_id());
}

/* Registers for the notification avaliable interrupt. */
static int ffa_int_driver_probe(struct platform_device *pdev)
{
	int sr_intid;
	int irq;
	int ret;
	struct of_phandle_args oirq = {};
	struct device_node *gic;

	/* Call FFA Features to get ID to be used for Scheduler Receiver */
	sr_intid = ffa_features(0x0, FFA_FEAT_SCHED_RECV_INT);
	if (sr_intid < 0) {
		pr_err("Failed to retrieve Scheduler Receiver Interrupt ID\n");
		return sr_intid;
	}

	pr_info("Attempting to register hwID: %d on %d\n", sr_intid, smp_processor_id());

	/* Create Mappings for IRQ */
	gic = of_irq_find_parent(pdev->dev.of_node);
	if (!gic)
		return -ENXIO;

	oirq.np = gic;
	oirq.args_count = 1;
	oirq.args[0] = sr_intid;
	irq = irq_create_of_mapping(&oirq);
	of_node_put(gic);

	if (!irq) {
		pr_err("Failed to create mapping!\n");
		return -ENODATA;
	}

	/* Store schedule receiver interrupt ID globally*/
	ffa_sched_recv_int_id = irq;

	pr_info("Attempting to register ID: %d\n", ffa_sched_recv_int_id);
	ret = request_percpu_irq(ffa_sched_recv_int_id, irq_handler, "ARM-FFA",
				 pdev);

	if (ret != 0) {
		pr_err("Error registering notification IRQ %d: %d\n",
		       sr_intid, ret);
		return ENODATA;
	}

	/* Enable handler on all cpus. */
	on_each_cpu(__enable_schedule_receiver_interrupt, NULL, 1);
	pr_info("FFA Driver registered for ID: %d IRQ: %d\n", sr_intid, irq);

	/* Ensure callbacks are initialised to NULL */
	initialise_notification_callback_struct(notification_callbacks.from_vm, MAX_NOTIFICATIONS);
	initialise_notification_callback_struct(notification_callbacks.from_sp, MAX_NOTIFICATIONS);
	initialise_notification_callback_struct(notification_callbacks.from_framework, MAX_NOTIFICATIONS);

	/* Register internal scheduling callback for handling self targeted notifications. */
	update_schedule_receiver_callback(drv_info->vm_id, handle_self_notification, NULL, true);

	/* Register internal architected notification handlers for SPM and Hyp. */
	configure_architected_notification(FFA_SPM_RX_BUFFER_FULL_NOTIFICATION_ID, handle_rx_full_notification);
	configure_architected_notification(FFA_HYP_RX_BUFFER_FULL_NOTIFICATION_ID, handle_rx_full_notification);

	return 0;
}

static const struct of_device_id int_driver_id[] = {
	{ .compatible = "arm,ffa-1.0" },
	{},
};

static struct platform_driver ffa_int_driver = {
	.driver = {
		.name = "ffa_protocol",
		.owner = THIS_MODULE,
		.of_match_table = int_driver_id,
	},
	.probe = ffa_int_driver_probe,
};

static int __init ffa_init(void)
{
	int ret;

	ret = ffa_transport_init(&invoke_ffa_fn);
	if (ret)
		return ret;

	ret = arm_ffa_bus_init();
	if (ret)
		return ret;

	drv_info = kzalloc(sizeof(*drv_info), GFP_KERNEL);
	if (!drv_info) {
		ret = -ENOMEM;
		goto ffa_bus_exit;
	}

	ret = ffa_version_check(&drv_info->version);
	if (ret)
		goto free_drv_info;

	if (ffa_id_get(&drv_info->vm_id)) {
		pr_err("failed to obtain VM id for self\n");
		ret = -ENODEV;
		goto free_drv_info;
	}

	drv_info->rx_buffer = alloc_pages_exact(RXTX_BUFFER_SIZE, GFP_KERNEL);
	if (!drv_info->rx_buffer) {
		ret = -ENOMEM;
		goto free_pages;
	}

	drv_info->tx_buffer = alloc_pages_exact(RXTX_BUFFER_SIZE, GFP_KERNEL);
	if (!drv_info->tx_buffer) {
		ret = -ENOMEM;
		goto free_pages;
	}

	ret = ffa_rxtx_map(virt_to_phys(drv_info->tx_buffer),
			   virt_to_phys(drv_info->rx_buffer),
			   RXTX_BUFFER_SIZE / FFA_PAGE_SIZE);
	if (ret) {
		pr_err("failed to register FFA RxTx buffers\n");
		goto free_pages;
	}

	mutex_init(&drv_info->rx_lock);
	mutex_init(&drv_info->tx_lock);

	initialise_vm_structs(vms, MAX_PARTITIONS);

	ffa_setup_partitions();

	/*
	 * Register as platform driver so we can register a
	 * handler for the Scheduler Receiver IRQ.
	 */
	ret = platform_driver_register(&ffa_int_driver);
	if (ret != 0) {
		pr_err("Error registering as platform driver driver %d\n", ret);
	}

	return 0;
free_pages:
	if (drv_info->tx_buffer)
		free_pages_exact(drv_info->tx_buffer, RXTX_BUFFER_SIZE);
	free_pages_exact(drv_info->rx_buffer, RXTX_BUFFER_SIZE);
free_drv_info:
	kfree(drv_info);
ffa_bus_exit:
	arm_ffa_bus_exit();
	return ret;
}
subsys_initcall(ffa_init);

static void __exit ffa_exit(void)
{
	ffa_rxtx_unmap(drv_info->vm_id);
	free_pages_exact(drv_info->tx_buffer, RXTX_BUFFER_SIZE);
	free_pages_exact(drv_info->rx_buffer, RXTX_BUFFER_SIZE);
	kfree(drv_info);
	arm_ffa_bus_exit();
}
module_exit(ffa_exit);

MODULE_ALIAS("arm-ffa");
MODULE_AUTHOR("Sudeep Holla <sudeep.holla@arm.com>");
MODULE_DESCRIPTION("Arm FF-A interface driver");
MODULE_LICENSE("GPL v2");
