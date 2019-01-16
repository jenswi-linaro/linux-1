/*
 * Secure Partition Client Interface (SPCI) driver
 *
 * Copyright (C) 2019 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bitmap.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/printk.h>
#include <linux/pm_opp.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/spci_protocol.h>

struct spci_drvinfo {
	uint32_t version;
	uint32_t features;
	struct spci_ops *spci_ops;
};

static struct spci_drvinfo *spci_info;

/*
 * get_version() enables the caller to determine whether the right SPCI version
 * is supported to meet its expectations.
 */
static uint32_t spci_get_version(void)
{
	return spci_info->version;
}

/*
 * get_features() enables the caller to determine whether specific featuress for
 * the supported SPCI versions are implemented. For example, the supported
 * scheduling models. For now, Model B is assumed.
 *
 * TODO: Currently unimplemented.
 */
static uint32_t spci_get_features(void)
{
	return spci_info->features;
}

static struct spci_msg_buf_desc buf_desc[SPCI_MAX_BUFS];
static DECLARE_COMPLETION(tx_not_busy);
static DEFINE_SPINLOCK(tx_not_busy_comp_lock);

static unsigned int spci_msg_buf_stat_get(unsigned int buf_type)
{
	spci_buf_t *buf;

	if ((buf_type != SPCI_BUF_TX) && (buf_type != SPCI_BUF_RX))
		panic("Invalid msg buff type (%u)\n", buf_type);

	buf = (spci_buf_t *) buf_desc[buf_type].va;
	return buf->hdr.state;
}

static int spci_msg_recv(struct spci_msg_imp_def *out,
			  uint32_t *out_len,
			  uint32_t attrs)
{
	uint32_t msg_type;
	spci_buf_t *rx_buf;
	spci_msg_hdr_t *msg_hdr;
	void *tmp;

	/* TODO: Actually receive the message from the producer */
	// arm_smccc_smc(SPCI_MSG_RECV, attrs, a2, a3, a4, a5, a6, a7, &res);

	rx_buf = (spci_buf_t *) buf_desc[SPCI_BUF_RX].va;

	/* Check if SPM has filled the RX buffer */
	if (spci_msg_buf_stat_get(SPCI_BUF_RX) == SPCI_BUF_STATE_EMPTY)
		panic("Invalid RX buffer state after SPCI_MSG_RECV \n");

	/*
         * Get the common message header.
         * TODO: Assuming there is a single sender and receiver. Hence, sender
         * and receiver information is not parsed.
         */
	tmp = (void *) rx_buf->buf;
	msg_hdr = (spci_msg_hdr_t *) tmp;

	/* Get the message payload */
	msg_type = msg_hdr->flags >> SPCI_MSG_TYPE_SHIFT;
	msg_type &= SPCI_MSG_TYPE_MASK;

	/* Not expecting any architectural messages for now. */
	if (msg_type == SPCI_MSG_TYPE_ARCH) {
		pr_err("Received architectural message\n");
		return -EIO;
	}

	pr_devel("%s: addr 0x%llx: len %u bytes:\n", __FUNCTION__,
		 (uint64_t) msg_hdr->payload,
		 msg_hdr->length);

	if (*out_len < msg_hdr->length) {
		pr_err("Message length mismatch.");
		pr_err(" Passed %u bytes, Returned %u bytes\n", *out_len,
		       msg_hdr->length);
		return -EIO;
	}

	/* Copy the message */
	memcpy(out, (void *) msg_hdr->payload, msg_hdr->length);

	/* Save the message length */
	*out_len = msg_hdr->length;

	/* Release the copied message */
	rx_buf->hdr.state = SPCI_BUF_STATE_EMPTY;

	/*
	 * Preemption was disabled in spci_run() so that the RX buffer could be
	 * freed safely on this CPU. Enable it now that we are done. Also,
	 * request scheduler to not preempt this thread immediately.
	 */
	preempt_enable_no_resched();

	return 0;
}

static int spci_msg_send_try(struct spci_msg_imp_def *in,
			     uint32_t in_len,
			     uint32_t attrs)
{
	uint32_t msg_type;
	spci_msg_hdr_t *msg_hdr;
	spci_buf_t *tx_buf;
	void *tmp;
	struct arm_smccc_res res = {0};

	/*
	 * TX buffer is protected by a global mutex. Only a single thread across
	 * all CPUs can access this buffer.

	 * TODO: The critical section could be shortened to before the SMC
	 * i.e. once the state is set to FULL, the lock could be released. Other
	 * threads will not write to the TX until it is empty even if they
	 * acquire the lock. So, releasing it seems a bit redundant. However, it
	 * is possible that the callee sends a interrupt back to indicate
	 * availability of the TX buffer if the completion of MSG_SEND will take
	 * long. In this case, other threads do not have to wait for the SMC to
	 * complete and can acquire the lock and write to the buffer.
	 */
	mutex_lock(&buf_desc[SPCI_BUF_TX].buf_mutex);

	/* Get the virtual address of the buffer */
	tx_buf = (spci_buf_t *) buf_desc[SPCI_BUF_TX].va;

	/* TODO: Assuming UP. Use spinlocks to protect buffer later */
	if (tx_buf->hdr.state != SPCI_BUF_STATE_EMPTY)
		panic("Invalid TX buffer state (%d)\n", tx_buf->hdr.state);

	/*
         * Get the common message header.
         * TODO: Assuming there is a single sender and receiver. Hence, sender
         * and receiver information is not parsed.
         */
	tmp = (void *) tx_buf->buf;
	msg_hdr = (spci_msg_hdr_t *) tmp;
	memset(msg_hdr, 0, sizeof(*msg_hdr));

	/* Set the message type. Not expecting architectural messages for now */
	msg_type = SPCI_MSG_TYPE_IMP & SPCI_MSG_TYPE_MASK;
	msg_type <<= SPCI_MSG_TYPE_SHIFT;
	msg_hdr->flags |= msg_type;

	/* Zero the message payload memory */
	memset((void *) msg_hdr->payload, 0, in_len);

	/* Copy the message */
	memcpy((void *) msg_hdr->payload, in, in_len);

	/* Set the message length */
	msg_hdr->length = in_len;

	/* Mark the buffer as full */
	tx_buf->hdr.state = SPCI_BUF_STATE_FULL;

	/* Send the message. TODO: Assume source and target ids are 0 */
	arm_smccc_smc(SPCI_MSG_SEND, attrs, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != SPCI_SUCCESS && res.a0 != SPCI_BUSY) {
		pr_err("SPCI_MSG_SEND error %d\n", (int32_t) res.a0);
		return -EIO;
	}

	if (res.a0 == SPCI_BUSY) {
		/*
		 * Consumer could not transmit the message. Free up the buffer
		 * and wait.
		 */
		tx_buf->hdr.state = SPCI_BUF_STATE_EMPTY;
		memset((void *) msg_hdr, 0, sizeof(*msg_hdr) + msg_hdr->length);
	} else {
		/* Check if SPM has relinquished the TX buffer */
		if (tx_buf->hdr.state != SPCI_BUF_STATE_EMPTY)
			panic("Invalid TX buffer state after SPCI_MSG_SEND \n");

		pr_devel("%s: addr 0x%llx: len %u bytes:\n", __FUNCTION__,
			 (uint64_t) msg_hdr->payload,
			 in_len);
	}

	/*
	 * Unlock access to the TX buffer. As described above, the critical
	 * section could be shortened.
	 */
	mutex_unlock(&buf_desc[SPCI_BUF_TX].buf_mutex);

	return (int) res.a0;
}

static int spci_msg_send(struct spci_msg_imp_def *in,
			 uint32_t in_len,
			 uint32_t attrs)
{
	int ret;

	do {
		ret = spci_msg_send_try(in, in_len, attrs);

		/* TODO: Replace this with timeout based wait */
		if (ret == SPCI_BUSY)
			wait_for_completion(&tx_not_busy);
	} while (ret == SPCI_BUSY);

	return ret;
}

/*
 * TODO: It must be possible to specify the SPCI_RUN behaviour expected by the
 * caller e.g. run until interrupted or until callee finishes work. At the
 * moment, it runs until the callee does not call SPCI_MSG_SEND_RECV.
 */
static int spci_run(uint32_t target)
{
	unsigned int comp_reason;
	unsigned long flags;
	struct arm_smccc_res res = {0};

	/*
	 * Disable preemption before exiting this EL. This prevents a "deadlock"
	 * where a message is available in the RX but this thread is preempted
	 * after completion of SPCI_RUN and before the RX buffer is read and its
	 * state updated. Another thread could send a separate message to a
	 * callee e.g. a Trusted OS who then could want to send a message to us
	 * but cannot since the RX is full. The "deadlock" could be broken if a
	 * normal world interrupt preempts the callee and results in a
	 * scheduling decision that resumes this thread. However, this is a long
	 * shot especially if the callee is running with interrupts disabled
	 * e.g. in a Trusted OS kernel. So the better approach is to ensure that
	 * the completion of SPCI_RUN and read from the RX (if required) happens
	 * without interference from other tasks.
	 *
	 * TODO: We are assuming that interrupt handlers will not send SPCI
	 * messages. Otherwise, interrupt must be disabled instead.
	 *
	 * TODO: This mechanism only avoids the "deadlock" on this CPU. On
	 * another CPU, a callee could still get stuck as long as the RX buffer
	 * has not been freed. However, there is no deadlock since this thread
	 * will soon release the buffer. Another mitigation to this problem
	 * could be to use per-CPU buffers. This needs a revisit.
	 */
	preempt_disable();

	/*
	 * Allocate CPU cycles to the target.
	 */
	arm_smccc_smc(SPCI_RUN, target, 0, 0, 0, 0, 0, 0, &res);

	/*
	 * The SPCI components determines the parameters for
	 * SPCI_RUN. If they are invalid then panic is the only
	 * option. The caller has no clue in this version of the driver
	 * about what it going on underneath.
	 */
	if (res.a0 == SPCI_INVALID_PARAMETER)
		panic("SPCI_RUN error %lu\n", res.a0);

	/*
	 * In case of the success return status, this is the only opportunity to
	 * wake up any threads that got SPCI_BUSY while trying to send a message
	 * to the SP we have just returned from since it had not yet got the CPU
	 * cycles to free up its RX buffer. So signal completion.
	 *
	 * TODO: The consumer of SPCI_MSG_SEND should notify the producer when a
	 * target RX becomes available.
	 */
	spin_lock_irqsave(&tx_not_busy_comp_lock, flags);
	complete(&tx_not_busy);
	spin_unlock_irqrestore(&tx_not_busy_comp_lock, flags);

	comp_reason = res.a0 >> SPCI_RUN_COMP_REASON_SHIFT;
	comp_reason &= SPCI_RUN_COMP_REASON_MASK;

	/*
	 * OP-TEE execution was interrupted and SPM took care of it.  TODO: This
	 * condition is invalid in the absence of virtualization in the secure
	 * world since the Trusted OS will always perform a controlled exit and
	 * send an imp.def. message to indicate this.
	 *
	 * TODO: Hide this from caller once there are multiple to preserve
	 * blocking semantics.
	 */
	if (comp_reason == SPCI_RUN_COMP_REASON_INTR)
		panic("SPCI_RUN error %lu\n", res.a0);

	/*
	 * OP-TEE finished work and handed back control.
	 * TODO: This condition is invalid in the absence of a separate
	 * scheduler component in the normal world. OP-TEE is expected
	 * to always call SPCI_MSG_SEND_RECV in response to any work
	 * requested by the Normal world.
	 */
	if ((comp_reason == SPCI_RUN_COMP_REASON_DONE) ||
	    (comp_reason == SPCI_RUN_COMP_REASON_MSG))
		panic("SPCI_RUN error %lu\n", res.a0);

	/*
	 * OP-TEE yielded control to wait for a internal event.
	 * TODO: This condition is invalid in the absence of an
	 * implementation of the SPCI_YIELD interface.
	 */
	if (comp_reason == SPCI_RUN_COMP_REASON_YLD)
		panic("SPCI_RUN error %lu\n", res.a0);

	/*
	 * OP-TEE called SPCI_MSG_SEND_RECV.
	 * Call SPCI_MSG_RECV to obtain the message and return to the
	 * caller.
	 */
	if (comp_reason != SPCI_RUN_COMP_REASON_DONE_MSG)
		panic("SPCI_RUN unknown error %lu\n", res.a0);

	return 0;
}

/*
 * msg_send_recv() enables the caller to send a message, get this driver to
 * allocate the CPU cycles to the target and return when the target is done. If
 * the target has sent a message back, then that is returned to the caller. From
 * the SPCI perspective, control will be returned to the caller only when:
 *
 * 1. The completion reason of SPCI_RUN is 0x0 or 0x4 i.e. the target finished
 *    work and optionally returned a message. TODO: SP does not return 0x0 at
 *    the moment.
 *
 * 2. The completion reason of SPCI_RUN is 0x3 i.e. the target cannot progress
 *    for an imp. def. reason. TODO: SP does not return 0x3 at the moment.
 *
 * All other completion reasons will be consumed and dealt with by the SPCI
 * driver as described below.
 *
 * 1. 0x1: Execution of the target was interrupted. It will be resumed once the
 *         interrupt has been handled.
 *
 *         TODO: Without S-EL2, a SP will be interrupted by a physical interrupt
 *               instead of a virtual interrupt. In this case, it will return an
 *               imp. def. code which cannot be understood by the SPCI
 *               driver. Hence, this scenario is not handled within the driver
 *               right now. This is not taking into account partitions (P) in
 *               the normal world that will be virtualized.
 *
 * 2. 0x2: Target sent a message to the caller or another SP. With scheduling
 *         model B, this will be treated as an invalid completion reason. This
 *         because the target is dependent upon the caller for CPU cycles
 *         allocation. With model A, a separate thread could allocate the cycles
 *         indepedently of the caller. Hence, with model B, the target cannot
 *         asynchronously send a message and resume execution. It must wait for
 *         the caller to allocate cycles. In which case, it must use
 *         SPCI_MSG_SEND_RECV instead of SPCI_MSG_SEND. The target must inform
 *         the caller if the message is targeted for another SP instead of
 *         letting the SPCI driver handle it implicitly.
 *
 *         TODO: Revisit the rationale above.
 */
static int spci_msg_send_recv(struct spci_msg_imp_def *in, uint32_t in_len,
			      struct spci_msg_imp_def *out, uint32_t *out_len,
			      uint32_t flags)
{
	int ret;
	uint32_t attrs, msg_loc;

	if (!in || !out || !out_len)
		return -EINVAL;

	if (in_len > sizeof(struct spci_msg_imp_def))
		return -EINVAL;

	/*
         * Populate Attributes parameter. TODO: Assume blocking behaviour
         * without notifications.
         */
	msg_loc = SPCI_MSG_SEND_ATTRS_MSGLOC_NSEC;
	msg_loc &= SPCI_MSG_SEND_ATTRS_MSGLOC_MASK;
	attrs = msg_loc << SPCI_MSG_SEND_ATTRS_MSGLOC_SHIFT;

	/*
	 * The logic to send a message to the callee, allocate CPU cycles to it
	 * and obtain a response is not as trivial as just invoking a SMC with
	 * parameters. A traditional SMC invocation combines all these
	 * elements. The message passing approach provides more flexibility
	 * instead by dealing with each element separately. However, this means
	 * that care needs to be taken to protect the buffers from concurrency
	 * related issues while maximising their availability. Comments in each
	 * function attempt to explain the current rationale.
	 */

	/* Send the message to SP */
	ret = spci_msg_send(in, in_len, attrs);
	if (ret)
		return ret;

	/*
	 * Run OP-TEE until it sends a message back
	 * TODO: Assuming source and target id are 0 for now.
	 */
	ret = spci_run(0);
	if (ret)
		return ret;

	/*
	 * TODO: A return from spci_run() indicates that a message is available
	 * in the RX buffer. Fetch it directly instead of calling SPCI_MESG_RECV
	 * which would be redundant for the moment. If there were multiple RX
	 * and TX buffers then calling SPCI_MESG_RECV would make sense since it
	 * would indicate which RX the message was received in.
	 */
	return spci_msg_recv(out, out_len, 0);
}

static struct spci_ops spci_ops = {
	.get_version = spci_get_version,
	.get_features = spci_get_features,
	.msg_send_recv = spci_msg_send_recv,
};

struct spci_ops *get_spci_ops(void)
{
	return spci_info ? spci_info->spci_ops : NULL;
}
EXPORT_SYMBOL_GPL(get_spci_ops);

static int spci_init_version(struct spci_drvinfo *info, struct device_node *np)
{
	union {
		struct arm_smccc_res smccc;
		struct spci_smc_call_get_version_result result;
	} res = {
		.result = {0}
	};

	/* Obtain the SPCI imp. version */
	arm_smccc_smc(SPCI_VERSION,  0, 0, 0, 0, 0, 0, 0, &res.smccc);
	if (res.result.major != SPCI_VERSION_MAJOR &&
	    res.result.minor != SPCI_VERSION_MINOR) {
		pr_err("Incompatible SPCI revision %u.%u \n",
		       res.result.major, res.result.minor);
		return -EIO;
	}

	info->version = SPCI_VERSION_FORM(res.result.major, res.result.minor);
	pr_info("SPCI revision  %u.%u \n", res.result.major, res.result.minor);

	return 0;
}

static int spci_msg_buf_exchange(struct device_node *np)
{
	unsigned int cnt, len, ctr;
	spci_buf_info_table_t *buf_info_tbl;
	phys_addr_t buf_info_tbl_pa;

	union {
		struct arm_smccc_res smccc;
		struct spci_smc_call_generic_result result;
	} res = {
		.result = {0}
	};

	/* Calculate length of message buffer information table */
	cnt = sizeof(spci_buf_info_table_t);
	cnt += SPCI_MAX_BUFS * sizeof(spci_buf_info_desc_t);
	len = cnt;
	cnt = 1 << PAGE_COUNT(cnt);

	/* Allocate space for message buffer information table */
	buf_info_tbl =
		(spci_buf_info_table_t *) __get_free_pages(GFP_KERNEL, cnt);
	if (!buf_info_tbl) {
		pr_err("SPCI buffer info table alloc of %d pages failed\n",
		       cnt);
		return -ENOMEM;
	}

	/* Zero allocated memory */
	memset((void *) buf_info_tbl, 0, cnt * PAGE_SIZE);

	/* Populate the message buffer information table header */
	memcpy(buf_info_tbl->signature,
	       SPCI_BUF_TABLE_SIGNATURE,
	       MAX_SIG_LENGTH);
	buf_info_tbl->version = 0; 	/* TODO: ignored for now */
	buf_info_tbl->length = len;
	buf_info_tbl->attributes =
		SPCI_BUF_TABLE_ATTR(1, SPCI_BUF_TABLE_ATTR_GRAN_4K);
	buf_info_tbl->buf_cnt =	SPCI_MAX_BUFS;

	/* Populate the message buffer information descriptors */
	for (ctr = 0; ctr < SPCI_MAX_BUFS; ctr++) {
		buf_info_tbl->payload[ctr].flags = SPCI_BUF_DESC_FLAG_TYPE(ctr);
		buf_info_tbl->payload[ctr].address = buf_desc[ctr].pa;

		/* TODO: ignored for now */
		buf_info_tbl->payload[ctr].id = 0;
		memset((void *) &buf_info_tbl->payload[ctr].uuid, 0, UUID_SIZE);
	}

	/* Stash the pa of this table */
	buf_info_tbl_pa = virt_to_phys((void *) buf_info_tbl);

	/* Double check the SPCI imp. version */
	arm_smccc_smc(SPCI_MSG_BUF_LIST_EXCHANGE,
		      buf_info_tbl_pa,
		      cnt * PAGE_SIZE, 0, 0, 0, 0, 0, &res.smccc);
	if (res.result.status) {
		pr_err("Unable to describe SPCI msg bufs (%d) \n",
		       res.result.status);
		return -EIO;
	}

	/* Free pages used by SPCI buffer information table */
	free_pages((unsigned long) buf_info_tbl, cnt);

	return 0;
}

static int spci_msg_buf_setup(struct device_node *np)
{
	unsigned ctr;
	unsigned long va;
	spci_buf_t *buf;
	spci_buf_hdr_t *buf_hdr;

	/*
	 * Allocate RX/TX buffers
	 *
	 * TODO: Assume for the time being that the buffer will not be described
	 * in a DT.
	 */
	for (ctr = 0; ctr < SPCI_MAX_BUFS; ctr++) {
		va = get_zeroed_page(GFP_KERNEL);
		if (!va) {
			pr_err("SPCI buffer alloc failed (%d)\n", ctr);
			return -ENOMEM;
		}

		/* Initialise buffer descriptor */
		buf_desc[ctr].va = va;
		buf_desc[ctr].pa = virt_to_phys((void *) va);

		/*
		 * Initialise the mutex for the allocated buffer.
		 * TODO: Management of these buffers is aligned with scheduling
		 * model B in the SPCI Alpha2 spec.
		 */
		mutex_init(&buf_desc[ctr].buf_mutex);

		pr_devel("SPCI %s buffer description\n", (ctr ? "TX": "RX"));
		pr_devel("va = 0x%lx  \n", buf_desc[ctr].va);
		pr_devel("pa = 0x%llx \n", buf_desc[ctr].pa);

		/* Initialise RX/TX buffers */
		buf = (spci_buf_t *) va;
		buf_hdr = &buf->hdr;
		buf_hdr->state = SPCI_BUF_STATE_EMPTY;
		buf_hdr->page_count = 1;
		memcpy((void *) buf_hdr->signature,
		       SPCI_BUF_SIGNATURE,
		       MAX_SIG_LENGTH);

		pr_devel("pg = 0x%x  \n", buf_hdr->page_count);
	}

	/*
	 * Describe RX/TX buffers to SPM.
	 *
	 * TODO: There would be no need to do this if the buffers had been
	 * described in the first place. This information will appear in the DT
	 * in future.
	 */
	return spci_msg_buf_exchange(np);
}

/*
 * TODO: This functions implements the basic ability to discover and parse the
 * SPCI node in a DT. The node itself will be populated with more information
 * later.
 */
static int spci_probe(struct platform_device *pdev)
{
	int rc = 0;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;

	spci_info = devm_kzalloc(dev, sizeof(*spci_info), GFP_KERNEL);
	if (!spci_info)
		return -ENOMEM;

	/* Check SPCI version */
	rc = spci_init_version(spci_info, np);
	if (rc)
		return rc;

	spci_info->spci_ops = &spci_ops;

	/* Setup SPCI message buffers */
	return spci_msg_buf_setup(np);
}

static const struct of_device_id spci_of_match[] = {
	{.compatible = "arm,spci-alpha2"},
	{},
};

MODULE_DEVICE_TABLE(of, scpi_of_match);

static struct platform_driver spci_driver = {
	.driver = {
		.name = "spci_protocol",
		.of_match_table = spci_of_match,
	},
	.probe = spci_probe,
};
module_platform_driver(spci_driver);

MODULE_AUTHOR("Achin Gupta <achin.gupta@arm.com>");
MODULE_DESCRIPTION("ARM SPCI message passing driver");
MODULE_LICENSE("GPL v2");
