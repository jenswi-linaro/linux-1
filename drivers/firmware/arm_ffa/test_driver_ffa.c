// SPDX-License-Identifier: GPL-2.0-only
/*
 * Secure Partitions Communication Interface (FFA) Protocol test driver
 *
 * Copyright (C) 2021 Arm Ltd.
 */

#include <linux/arm_ffa.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>

#define MAX_PARTITIONS 15
#define SECURE_WORLD_PARTITION_MASK 0x8000

#define FFA_ERROR 0x84000060
#define FFA_RET_BUSY (-4)
#define FFA_BUSY

static bool ERROR_OCCURRED;

struct partition_struct {
	struct ffa_device *ffa_dev;
	struct mutex lock;
	u16 id;
};

struct partition_struct vm_structs[MAX_PARTITIONS];
struct partition_struct sp_structs[MAX_PARTITIONS];

ffa_partition_id_t VM_ID[MAX_PARTITIONS];
ffa_partition_id_t SP_ID[MAX_PARTITIONS];

const struct ffa_dev_ops *ffa_ops;
ffa_partition_id_t dest_part_id;

static int vm_count, sp_count;

/* Ensure we only initialise the device driver once. */
static bool device_driver_initalized;

/* Keep in Sync with Bare Metal Partition */
enum message_t {
	/* Partition Only Messages. */
	FF_A_INIT_SP = 0,
	FF_A_ECHO_MESSAGE,
	FF_A_NOTIFICATION_GET,
	FF_A_NOTIFICATION_SEND,
	FF_A_NOTIFICATION_SEND_PARTITION,
	FF_A_P_P_NOTIFICATION_TEST,

	/* Basic Functionality. */
	FF_A_RELAY_MESSAGE = 7,

	/* Global Notification Tests. */
	FF_A_SETUP_NOTIFICATIONS = 11,
	FF_A_SP_SP_NOTIFICATION_TEST,
	FF_A_PVM_SP_NOTIFICATION_TEST,
	FF_A_SP_PVM_NOTIFICATION_TEST,
	FF_A_PVM_SVM_NOTIFICATION_TEST,
	FF_A_SVM_PVM_NOTIFICATION_TEST,
	FF_A_SP_SVM_NOTIFICATION_TEST,
	FF_A_SVM_SP_NOTIFICATION_TEST,

	/* Per vCPU Notification Tests. */
	FF_A_VCPU_SP_PVM_NOTIFICATION = 30,
	FF_A_VCPU_SVM_PVM_NOTIFICATION,
	FF_A_VCPU_PVM_SP_NOTIFICATION,
	FF_A_VCPU_SP_SP_NOTIFICATION,

	/* Delayed Notification Tests. */
	FF_A_SP_SVM_NOTIFICATION_TEST_DELAYED,

	LAST,
	FF_A_RUN_ALL = 255,
	FF_A_OP_MAX = 256
};

/* Helper function to get partition struct for VM or SP. */
static struct partition_struct *get_partition_struct(ffa_partition_id_t id)
{
	if ((SECURE_WORLD_PARTITION_MASK & id))
		return &sp_structs[id & 0xf];

	return &vm_structs[id & 0xf];
}

/* Helper function to get ffa device for VM or SP. */
static struct ffa_device *get_ffa_dev(ffa_partition_id_t id)
{
	return get_partition_struct(id)->ffa_dev;
}

static int check_status(int status, int test_id)
{
	if (status) {
		pr_err("\n\nTEST CASE (%d) FAILED with: %d!!\n\n", test_id,
		       status);
		ERROR_OCCURRED = true;
	} else {
		pr_info("Test Executed Successfully\n");
	}
	return status;
}

/* Partition Driver Related Function. */

/*
 * Callback to handle Scheduler Receiver Interrupt. Run the partition and ask
 * it to retrieve its notifications.
 */
static void schedule_receiver_handler(ffa_partition_id_t partition_id,
				      ffa_vcpu_id_t vcpu, bool is_per_vcpu,
				      void *dev_data)
{
	int ret;
	struct ffa_send_direct_data data = { FF_A_NOTIFICATION_GET };
	/*
	 * Send a direct request to partition to indicate that partition
	 * should retrieve it's notifications.
	 * Use the pointer we provided when registering the callback to run
	 * the partition directly.
	 */
	ret = ffa_ops->sync_send_receive(dev_data, &data);
	while (ret == -EBUSY) {
		pr_debug("SRC: Busy - Retrying...\n");
		ret = ffa_ops->sync_send_receive(dev_data, &data);
	}
}

/* Callback for handling notification registered to this driver. Just print a message for now. */
static void handle_notification_callbacks(ffa_partition_id_t partition_id,
					  ffa_notification_id_t notification_id,
					  void *dev_data)
{
	pr_info("Handling notification %d from partition %x on cpu: %d\n",
		notification_id, partition_id, smp_processor_id());
}

/* Test basic request of requesting notifications and providing dummy callback function. */
static int setup_notifications(ffa_partition_id_t id,
			       struct partition_struct *partition)
{
	int rc;
	int global_notification = -1;
	int per_vcpu_notification = -1;
	bool is_per_vcpu = false;

	if (!partition->ffa_dev)
		return -1;

	/* Request a global notification. */
	rc = ffa_ops->request_notification(partition->ffa_dev, is_per_vcpu,
					   handle_notification_callbacks, NULL);
	if (rc < 0) {
		pr_err("Failed to request global notification: %d\n", rc);
		return rc;
	}

	global_notification = rc;
	pr_debug("Global Notification %d assigned.\n", global_notification);

	/* Request per vcpu notification. */
	is_per_vcpu = true;
	rc = ffa_ops->request_notification(partition->ffa_dev, is_per_vcpu,
					   handle_notification_callbacks, NULL);
	if (rc < 0) {
		pr_err("Failed to request per vcpu notification: %d\n", rc);
		return rc;
	}
	per_vcpu_notification = rc;
	pr_debug("Per VCPU Notification %d assigned.\n", per_vcpu_notification);
	return !((global_notification >= 0) && (per_vcpu_notification >= 0));
}

/* Test basic communication. Relay message PVM -> SVM -> SP and back. */
static int relay_message(u32 message, struct partition_struct *partition,
			 ffa_partition_id_t target)
{
	int rc;
	struct ffa_send_direct_data data = {
		FF_A_RELAY_MESSAGE, message, target,
		};

	if (!partition->ffa_dev)
		return -1;

	rc = ffa_ops->sync_send_receive(partition->ffa_dev, &data);
	while (rc == -EBUSY) {
		pr_debug("DIR_REQ: Busy - Retrying...\n");
		rc = ffa_ops->sync_send_receive(partition->ffa_dev, &data);
	}

	pr_debug("Echoed data: 0x%lx 0x%lx 0x%lx\n", data.data0, data.data1,
		 data.data2);
	if (data.data0 != message) {
		pr_err("ERROR: Relay Test Case Failed!: %lx\n", data.data0);
		return -1;
	}
	return 0;
}

/* Test basic communication. Echo message back. */
static int echo_message(u32 message, struct partition_struct *partition)
{
	int rc;
	struct ffa_send_direct_data data = { FF_A_ECHO_MESSAGE, message };

	if (!partition->ffa_dev)
		return -1;

	rc = ffa_ops->sync_send_receive(partition->ffa_dev, &data);
	while (rc == -EBUSY) {
		pr_debug("DIR_REQ: Busy - Retrying...\n");
		rc = ffa_ops->sync_send_receive(partition->ffa_dev, &data);
	}

	pr_debug("Echoed data: 0x%lx 0x%lx 0x%lx\n", data.data0, data.data1,
		 data.data2);
	if (message != data.data0) {
		pr_err("ERROR: Echo Test Case to %x Failed!: %lx\n",
		       partition->ffa_dev->vm_id, data.data0);
		return -1;
	}
	return 0;
}

/* Request a partition to setup and send a notification to another partition-> */
static int p_p_notification(struct partition_struct *from,
			    struct partition_struct *to, bool is_per_vcpu,
			    bool delay)
{
	int rc;
	u32 src_dst_ids;
	u32 flags = 0;
	struct ffa_send_direct_data data;

	flags |= is_per_vcpu << 0;
	flags |= delay << 1;

	if (!from->ffa_dev || !to->ffa_dev)
		return -1;

	src_dst_ids =
	    (to->ffa_dev->vm_id & 0xFFFF) | from->ffa_dev->vm_id << 16;
	data =
	    (struct ffa_send_direct_data) { FF_A_P_P_NOTIFICATION_TEST,
		 src_dst_ids, flags };

	rc = ffa_ops->sync_send_receive(from->ffa_dev, &data);
	while (rc == -EBUSY) {
		pr_debug("DIR_REQ: Busy - Retrying...\n");
		rc = ffa_ops->sync_send_receive(from->ffa_dev, &data);
	}

	pr_debug("Requesting Partition 0x%x [to Bind to SP] 0x%x\n",
		 from->ffa_dev->vm_id, to->ffa_dev->vm_id);

	return data.data0;
}

/* Test sending a notification from a partiion to the PVM. */
static int partition_pvm_notification(struct partition_struct *partition,
				      bool is_per_vcpu, bool delay)
{
	int rc, notification_id;
	struct ffa_send_direct_data data;
	u32 flags = 0;

	if (!partition->ffa_dev)
		return -1;

	/* Request a notification for the partition to signal. */
	rc = ffa_ops->request_notification(partition->ffa_dev, is_per_vcpu,
					   handle_notification_callbacks, NULL);
	if (rc < 0) {
		pr_err("Failed to request is_per_vcpu notification: %d\n", rc);
		return rc;
	}

	notification_id = rc;
	pr_debug("Per vcpu ?:%d Notification %d assigned for %x.\n",
		 is_per_vcpu, notification_id, partition->ffa_dev->vm_id);

	flags |= is_per_vcpu << 0;
	flags |= delay << 1;

	/* Request partition to send notification back to PVM. */
	data =
	    (struct ffa_send_direct_data) { FF_A_NOTIFICATION_SEND,
		 notification_id, flags };

	pr_debug("Requesting partition %x to send notification to PVM\n",
		 partition->ffa_dev->vm_id);
	rc = ffa_ops->sync_send_receive(partition->ffa_dev, &data);
	while (rc == -EBUSY) {
		pr_debug("DIR_REQ: Busy - Retrying...\n");
		rc = ffa_ops->sync_send_receive(partition->ffa_dev, &data);
	}

	return data.data0;
}

static int setup_and_trigger_partition_notifications(struct partition_struct
						     *partition,
						     bool is_per_vcpu)
{
	int rc, notification_id;
	u32 src_dst_ids;
	struct ffa_send_direct_data data;

	/* Bail if ffa_dev not initialised. */
	if (!partition->ffa_dev)
		return -1;

	src_dst_ids = (0x1 << 16) | partition->ffa_dev->vm_id;
	data =
	    (struct ffa_send_direct_data) { FF_A_SETUP_NOTIFICATIONS,
		 src_dst_ids, is_per_vcpu };

	/* Request partition to setup notifications and return ids. */
	rc = ffa_ops->sync_send_receive(partition->ffa_dev, &data);

	if (rc < 0) {
		pr_err("Failed to request partition notification err:%d\n", rc);
		return rc;
	}

	notification_id = data.data0;
	pr_debug("Returned notification ID: 0x%lx 0x%lx 0x%lx\n",
		 data.data0, data.data1, data.data2);

	rc = ffa_ops->send_notification(partition->ffa_dev, notification_id,
					is_per_vcpu, 0);

	return rc;
}

static int sp_svm_notification(struct partition_struct *src,
			       struct partition_struct *dst, bool is_per_vcpu,
			       bool delay)
{
	int rc, notification_id;
	struct ffa_send_direct_data data;
	u32 src_dst_ids, flags = 0;

	flags |= is_per_vcpu << 0;
	flags |= delay << 1;

	/* Bail if ffa_dev not initialised. */
	if (!src->ffa_dev || !dst->ffa_dev)
		return -1;

	src_dst_ids = src->ffa_dev->vm_id << 16 | dst->ffa_dev->vm_id;
	data =
	    (struct ffa_send_direct_data) { FF_A_SETUP_NOTIFICATIONS,
		 src_dst_ids, flags };

	/* Request partition to setup notifications and return ids. */
	rc = ffa_ops->sync_send_receive(dst->ffa_dev, &data);
	while (rc == -EBUSY) {
		pr_debug("DIR_REQ: Busy - Retrying...\n");
		rc = ffa_ops->sync_send_receive(dst->ffa_dev, &data);
	}

	if (rc < 0) {
		pr_err("Failed to request partition notification err:%d\n", rc);
		return rc;
	}

	notification_id = data.data0;
	pr_debug("Returned notification ID: 0x%lx 0x%lx 0x%lx\n",
		 data.data0, data.data1, data.data2);

	src_dst_ids = dst->ffa_dev->vm_id << 16 | src->ffa_dev->vm_id;

	data = (struct ffa_send_direct_data) {.data0 =
		    FF_A_NOTIFICATION_SEND_PARTITION,
		.data1 = src_dst_ids,
		.data2 = notification_id,
		.data3 = flags
	};

	rc = ffa_ops->sync_send_receive(src->ffa_dev, &data);
	while (rc == -EBUSY) {
		pr_debug("DIR_REQ: Busy - Retrying...\n");
		rc = ffa_ops->sync_send_receive(src->ffa_dev, &data);
	}

	return rc;
}

static long run_test(int test_id)
{
	long ret = -3;

	switch (test_id) {
	case FF_A_SETUP_NOTIFICATIONS:
		ret = setup_notifications(get_ffa_dev(SP_ID[2])->vm_id,
					  get_partition_struct(SP_ID[2]));
		break;
	case FF_A_SP_PVM_NOTIFICATION_TEST:
		pr_info("Triggering Global Notification to PVM from SP 0x%x\n",
			get_ffa_dev(SP_ID[2])->vm_id);
		ret =
		    partition_pvm_notification(get_partition_struct(SP_ID[2]),
					       false, false);
		break;
	case FF_A_PVM_SP_NOTIFICATION_TEST:
		pr_info("Triggering Global Notification for 0x%x\n",
			get_ffa_dev(SP_ID[2])->vm_id);
		ret =
		    setup_and_trigger_partition_notifications
		    (get_partition_struct(SP_ID[2]), false);
		break;
	case FF_A_SVM_PVM_NOTIFICATION_TEST:
		pr_info("Triggering Global Notification for PVM from SVM\n");
		ret =
		    partition_pvm_notification(get_partition_struct(VM_ID[2]),
					       false, false);
		break;
	case FF_A_SP_SP_NOTIFICATION_TEST:
		pr_info("Triggering Global SP -> SP Notification Test\n");
		ret = p_p_notification(get_partition_struct(SP_ID[2]),
				       get_partition_struct(SP_ID[3]), false,
				       false);
		break;
	case FF_A_SVM_SP_NOTIFICATION_TEST:
		pr_info("Triggering Global SVM -> SP Notification Test\n");
		ret = p_p_notification(get_partition_struct(VM_ID[2]),
				       get_partition_struct(SP_ID[2]), false,
				       false);
		break;
	case FF_A_SP_SVM_NOTIFICATION_TEST:
		pr_info
		    ("Triggering Global SP 0x%x -> VM Notification Test 0x%x\n",
		     get_ffa_dev(SP_ID[2])->vm_id,
		     get_ffa_dev(VM_ID[2])->vm_id);
		ret =
		    sp_svm_notification(get_partition_struct(SP_ID[2]),
					get_partition_struct(VM_ID[2]), false,
					false);
		break;
	case FF_A_SP_SVM_NOTIFICATION_TEST_DELAYED:
		pr_info
		    ("Triggering Global SP 0x%x -> VM Notification Test 0x%x\n",
		     get_ffa_dev(SP_ID[2])->vm_id,
		     get_ffa_dev(VM_ID[2])->vm_id);
		ret =
		    sp_svm_notification(get_partition_struct(SP_ID[2]),
					get_partition_struct(VM_ID[2]), false,
					true);
		break;
	case FF_A_PVM_SVM_NOTIFICATION_TEST:
		pr_info("Triggering Global Notification from VM to PVM\n");
		ret =
		    partition_pvm_notification(get_partition_struct(VM_ID[3]),
					       false, false);
		break;
	case FF_A_VCPU_SP_PVM_NOTIFICATION:
		pr_info
		    ("Triggering Per vCPU Notification to PVM from SP 0x%x\n",
		     get_ffa_dev(SP_ID[2])->vm_id);
		ret =
		    partition_pvm_notification(get_partition_struct(SP_ID[2]),
					       true, false);
		break;
	case FF_A_VCPU_SVM_PVM_NOTIFICATION:
		pr_info("Triggering Per vCPU Notification to PVM from VM\n");
		ret =
		    partition_pvm_notification(get_partition_struct(VM_ID[2]),
					       true, false);
		break;
	case FF_A_VCPU_PVM_SP_NOTIFICATION:
		pr_info("Triggering Per vCPU Notification for 0x%x\n",
			get_ffa_dev(SP_ID[2])->vm_id);
		ret =
		    setup_and_trigger_partition_notifications
		    (get_partition_struct(SP_ID[2]), true);
		break;
	case FF_A_VCPU_SP_SP_NOTIFICATION:
		pr_info("Triggering Per vCPU SP -> SP Notification Test\n");
		ret = p_p_notification(get_partition_struct(SP_ID[2]),
				       get_partition_struct(SP_ID[3]), true,
				       false);
		break;
	case FF_A_RELAY_MESSAGE:
		ret = relay_message(0xDEADBEEF, get_partition_struct(SP_ID[2]),
				    get_ffa_dev(SP_ID[3])->vm_id);
		break;
	case FF_A_ECHO_MESSAGE:
		ret = echo_message(0xDEADBEEF, get_partition_struct(SP_ID[2]));
		break;
	default:
		ret = -2;
		break;
	}
	return ret;
}

static long ff_a_test_ioctl(struct file *fd, unsigned int cmd,
			    unsigned long arg)
{
	long ret;
	int i, user_cmd = 0;
	int failed = 0;

	ret = copy_from_user(&user_cmd, (void *)arg, 1);
	if (ret != 0) {
		pr_err("Failed to obtain data from userspaced\n");
		return -1;
	}

	if (ERROR_OCCURRED) {
		pr_err("Previous Testcase did not complete correctly!\n");
		return -1;
	}

	/* Run individual test cases. */
	if (user_cmd != FF_A_RUN_ALL) {
		ret = run_test(user_cmd);
		if (ret == -2) {
			pr_err("Invalid Test ID: %ld\n", ret);
			return 0;
		}
		check_status(ret, user_cmd);
	} else {
		/* Run all tests at once. */
		for (i = 0; i < LAST; i++) {
			pr_info("\n\n Starting Test Case: %d\n", i);
			ret = run_test(i);
			if (ret == -2) {
				// Ignore invalid test IDs.
				continue;
			} else {
				ret = check_status(ret, i);
				if (ret) {
					failed++;
					break;
				}
			}
		}
		pr_info("\n\n\n%d Tests Failed\n\n\n", failed);

		/* Ensure all VM's are in the expected state by echoing message . */
		for (i = 2; i < 9; i++) {
			if (check_status
			    (echo_message
			     (0xDEADBEEF, get_partition_struct(VM_ID[i])),
			     i + 100)) {
				failed++;
			}
		}
		for (i = 2; i < 4; i++) {
			if (check_status
			    (echo_message
			     (0xDEADBEEF, get_partition_struct(SP_ID[i])),
			     i + 8000)) {
				failed++;
			}
		}
	}

	if (failed)
		ERROR_OCCURRED = true;

	pr_info("Exiting Test Application -  Total Failures: %d\n", failed);
	return 0;
}

const struct file_operations fops = {
	.unlocked_ioctl = ff_a_test_ioctl,
};

static int device_driver_init(void)
{
	struct class *cl;
	int rc;

	cl = class_create(THIS_MODULE, "ff_a_test");
	if (IS_ERR(cl))
		return PTR_ERR(cl);

	/* Create char device. */
	rc = register_chrdev(0, "FF_A_TEST", &fops);

	/* Create device file in the /dev directory. */
	device_create(cl, NULL, MKDEV(rc, 0), NULL, "FF_A_TEST_DEVICE");

	return rc;
}

static int ffa_test_driver_probe(struct ffa_device *ffa_dev)
{
	int rc;
	struct partition_struct *p;
	/* Hack: use partition ID as index for storing VM structs for each world. */
	int partition_index = ffa_dev->vm_id & 0xFF;

	if (partition_index > MAX_PARTITIONS) {
		pr_err("Attempting to initialise out of range partiion! %x\n",
		       ffa_dev->vm_id);
		return -1;
	}

	p = get_partition_struct(ffa_dev->vm_id);

	p->ffa_dev = ffa_dev;
	p->id = ffa_dev->vm_id;

	/* Handle SP's. */
	if ((SECURE_WORLD_PARTITION_MASK & ffa_dev->vm_id)) {
		sp_structs[partition_index].ffa_dev = ffa_dev;
		sp_structs[partition_index].id = ffa_dev->vm_id;
		SP_ID[partition_index] = ffa_dev->vm_id;
		sp_count++;
		/* Handle VM's. */
	} else {
		vm_structs[partition_index].ffa_dev = ffa_dev;
		vm_structs[partition_index].id = ffa_dev->vm_id;
		VM_ID[partition_index] = ffa_dev->vm_id;
		vm_count++;
	}

	pr_debug("Initialising driver for Partition: 0x%x at %d\n",
		 ffa_dev->vm_id, partition_index);

	ffa_ops = ffa_dev_ops_get(ffa_dev);
	if (IS_ERR_OR_NULL(ffa_ops)) {
		pr_err("Failed to obtain FFA ops %s:%d\n", __FILE__, __LINE__);
		return -1;
	}
	/* Set that we're using 32 bit mode for compatibility. */
	ffa_ops->mode_32bit_set(ffa_dev);

	/* Only do this setup once */
	if (!device_driver_initalized) {
		device_driver_init();
		device_driver_initalized = true;
	}

	/*
	 * Run the partition to perform initial setup only if it is located
	 * in the normal world, the SPMC will take care of this for SP's.
	 */
	if (!(ffa_dev->vm_id & SECURE_WORLD_PARTITION_MASK)) {
		pr_debug("Initialising Partition: 0x%x\n", ffa_dev->vm_id);
		rc = ffa_ops->run(ffa_dev, 0);
		pr_debug("Partition 0x%x initialised - %d\n", ffa_dev->vm_id,
			 rc);
		if (rc) {
			pr_err("Unexpected error %d\n", rc);
			return false;
		}
	}

	/* Register partition driver for handling schedule receiver callbacks. */
	rc = ffa_ops->register_schedule_receiver_callback(ffa_dev,
							  &schedule_receiver_handler,
							  ffa_dev);
	if (rc) {
		pr_err("Failed to register Schedule Receiver callback %d\n",
		       rc);
		return false;
	}

	pr_debug("FF-A test module init finalized\n");
	return 0;
}

static const struct ffa_device_id test_ffa_device_id[] = {
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x0, 0x0, 0x0) },
	{ UUID_INIT(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12, 0x0, 0x0, 0x0) },
	{ }
};

static struct ffa_driver test_ffa_driver = {
	.name = "test_ffa",
	.probe = ffa_test_driver_probe,
	.id_table = test_ffa_device_id,
};

module_ffa_driver(test_ffa_driver);

MODULE_AUTHOR("Arm");
MODULE_DESCRIPTION("PSA-FF-A test module");
MODULE_LICENSE("GPL v2");
