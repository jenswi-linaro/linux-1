// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include "optee_private.h"
#include "optee_smc.h"
#include "optee_ffa.h"

struct optee_call_waiter {
	struct list_head list_node;
	struct completion c;
};

static void optee_cq_wait_init(struct optee_call_queue *cq,
			       struct optee_call_waiter *w)
{
	/*
	 * We're preparing to make a call to secure world. In case we can't
	 * allocate a thread in secure world we'll end up waiting in
	 * optee_cq_wait_for_completion().
	 *
	 * Normally if there's no contention in secure world the call will
	 * complete and we can cleanup directly with optee_cq_wait_final().
	 */
	mutex_lock(&cq->mutex);

	/*
	 * We add ourselves to the queue, but we don't wait. This
	 * guarantees that we don't lose a completion if secure world
	 * returns busy and another thread just exited and try to complete
	 * someone.
	 */
	init_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);

	mutex_unlock(&cq->mutex);
}

static void optee_cq_wait_for_completion(struct optee_call_queue *cq,
					 struct optee_call_waiter *w)
{
	wait_for_completion(&w->c);

	mutex_lock(&cq->mutex);

	/* Move to end of list to get out of the way for other waiters */
	list_del(&w->list_node);
	reinit_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);

	mutex_unlock(&cq->mutex);
}

static void optee_cq_complete_one(struct optee_call_queue *cq)
{
	struct optee_call_waiter *w;

	list_for_each_entry(w, &cq->waiters, list_node) {
		if (!completion_done(&w->c)) {
			complete(&w->c);
			break;
		}
	}
}

static void optee_cq_wait_final(struct optee_call_queue *cq,
				struct optee_call_waiter *w)
{
	/*
	 * We're done with the call to secure world. The thread in secure
	 * world that was used for this call is now available for some
	 * other task to use.
	 */
	mutex_lock(&cq->mutex);

	/* Get out of the list */
	list_del(&w->list_node);

	/* Wake up one eventual waiting task */
	optee_cq_complete_one(cq);

	/*
	 * If we're completed we've got a completion from another task that
	 * was just done with its call to secure world. Since yet another
	 * thread now is available in secure world wake up another eventual
	 * waiting task.
	 */
	if (completion_done(&w->c))
		optee_cq_complete_one(cq);

	mutex_unlock(&cq->mutex);
}

/* Requires the filpstate mutex to be held */
static struct optee_session *find_session(struct optee_context_data *ctxdata,
					  u32 session_id)
{
	struct optee_session *sess;

	list_for_each_entry(sess, &ctxdata->sess_list, list_node)
		if (sess->session_id == session_id)
			return sess;

	return NULL;
}

/**
 * optee_do_call_with_arg() - Do an SMC to OP-TEE in secure world
 * @ctx:	calling context
 * @parg:	physical address of message to pass to secure world
 *
 * Does and SMC to OP-TEE in secure world and handles eventual resulting
 * Remote Procedure Calls (RPC) from OP-TEE.
 *
 * Returns return code from secure world, 0 is OK
 */
int optee_do_call_with_arg(struct tee_context *ctx, struct tee_shm *arg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_call_waiter w = { };
	struct optee_rpc_param param = { };
	struct optee_call_ctx call_ctx = { };
	phys_addr_t parg = 0;
	int rc = 0;

	rc = tee_shm_get_pa(arg, 0, &parg);
	if (rc)
		return rc;

	param.a0 = OPTEE_SMC_CALL_WITH_ARG;
	reg_pair_from_64(&param.a1, &param.a2, parg);
	/* Initialize waiter */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		struct arm_smccc_res res;

		optee->invoke_fn(param.a0, param.a1, param.a2, param.a3,
				 param.a4, param.a5, param.a6, param.a7,
				 &res);

		if (res.a0 == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
			/*
			 * Out of threads in secure world, wait for a thread
			 * become available.
			 */
			optee_cq_wait_for_completion(&optee->call_queue, &w);
		} else if (OPTEE_SMC_RETURN_IS_RPC(res.a0)) {
			might_sleep();
			param.a0 = res.a0;
			param.a1 = res.a1;
			param.a2 = res.a2;
			param.a3 = res.a3;
			optee_handle_rpc(ctx, &param, &call_ctx);
		} else {
			rc = res.a0;
			break;
		}
	}

	optee_rpc_finalize_call(&call_ctx);
	/*
	 * We're done with our thread in secure world, if there's any
	 * thread waiters wake up one.
	 */
	optee_cq_wait_final(&optee->call_queue, &w);

	return rc;
}

static struct tee_shm *get_msg_arg(struct tee_context *ctx, size_t num_params,
				   struct optee_msg_arg **msg_arg)
{
	int rc = 0;
	struct tee_shm *shm = NULL;
	struct optee_msg_arg *ma = NULL;

	shm = tee_shm_alloc(ctx, OPTEE_MSG_GET_ARG_SIZE(num_params),
			    TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return shm;

	ma = tee_shm_get_va(shm, 0);
	if (IS_ERR(ma)) {
		rc = PTR_ERR(ma);
		goto out;
	}

	memset(ma, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	ma->num_params = num_params;
	*msg_arg = ma;
out:
	if (rc) {
		tee_shm_free(shm);
		return ERR_PTR(rc);
	}

	return shm;
}

int optee_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_msg_arg *msg_arg = NULL;
	struct optee_session *sess = NULL;
	struct tee_shm *shm = NULL;
	int rc = 0;

	/* +2 for the meta parameters added below */
	shm = get_msg_arg(ctx, arg->num_params + 2, &msg_arg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_OPEN_SESSION;
	msg_arg->cancel_id = arg->cancel_id;

	/*
	 * Initialize and add the meta parameters needed when opening a
	 * session.
	 */
	msg_arg->params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
				  OPTEE_MSG_ATTR_META;
	msg_arg->params[1].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
				  OPTEE_MSG_ATTR_META;
	memcpy(&msg_arg->params[0].u.value, arg->uuid, sizeof(arg->uuid));
	msg_arg->params[1].u.value.c = arg->clnt_login;

	rc = tee_session_calc_client_uuid((uuid_t *)&msg_arg->params[1].u.value,
					  arg->clnt_login, arg->clnt_uuid);
	if (rc)
		goto out;

	rc = optee->ops->to_msg_param(optee, msg_arg->params + 2,
				      arg->num_params, param);
	if (rc)
		goto out;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto out;
	}

	if (optee->ops->do_call_with_arg(ctx, shm)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (msg_arg->ret == TEEC_SUCCESS) {
		/* A new session has been created, add it to the list. */
		sess->session_id = msg_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);
	} else {
		kfree(sess);
	}

	if (optee->ops->from_msg_param(optee, param, arg->num_params,
				       msg_arg->params + 2)) {
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		/* Close session again to avoid leakage */
		optee_close_session(ctx, msg_arg->session);
	} else {
		arg->session = msg_arg->session;
		arg->ret = msg_arg->ret;
		arg->ret_origin = msg_arg->ret_origin;
	}
out:
	tee_shm_free(shm);

	return rc;
}

int optee_close_session_helper(struct tee_context *ctx, u32 session)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_msg_arg *msg_arg = NULL;
	struct tee_shm *shm = NULL;

	shm = get_msg_arg(ctx, 0, &msg_arg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CLOSE_SESSION;
	msg_arg->session = session;
	optee->ops->do_call_with_arg(ctx, shm);

	tee_shm_free(shm);

	return 0;
}

static int remove_session(struct tee_context *ctx, u32 session)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_session *sess;

	/* Check that the session is valid and remove it from the list */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	if (sess)
		list_del(&sess->list_node);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	kfree(sess);

	return 0;
}

int optee_close_session(struct tee_context *ctx, u32 session)
{
	int rc = remove_session(ctx, session);

	if (rc)
		return rc;

	return optee_close_session_helper(ctx, session);
}

int optee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_msg_arg *msg_arg = NULL;
	struct optee_session *sess = NULL;
	struct tee_shm *shm = NULL;
	int rc = 0;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, arg->session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, arg->num_params, &msg_arg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);
	msg_arg->cmd = OPTEE_MSG_CMD_INVOKE_COMMAND;
	msg_arg->func = arg->func;
	msg_arg->session = arg->session;
	msg_arg->cancel_id = arg->cancel_id;

	rc = optee->ops->to_msg_param(optee, msg_arg->params, arg->num_params,
				      param);
	if (rc)
		goto out;

	if (optee->ops->do_call_with_arg(ctx, shm)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (optee->ops->from_msg_param(optee, param, arg->num_params,
				       msg_arg->params)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	arg->ret = msg_arg->ret;
	arg->ret_origin = msg_arg->ret_origin;
out:
	tee_shm_free(shm);
	return rc;
}

int optee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_msg_arg *msg_arg = NULL;
	struct optee_session *sess = NULL;
	struct tee_shm *shm = NULL;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, 0, &msg_arg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CANCEL;
	msg_arg->session = session;
	msg_arg->cancel_id = cancel_id;
	optee->ops->do_call_with_arg(ctx, shm);

	tee_shm_free(shm);
	return 0;
}

/**
 * optee_enable_shm_cache() - Enables caching of some shared memory allocation
 *			      in OP-TEE
 * @optee:	main service struct
 */
void optee_enable_shm_cache(struct optee *optee)
{
	struct optee_call_waiter w;

	/* We need to retry until secure world isn't busy. */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		struct arm_smccc_res res;

		optee->invoke_fn(OPTEE_SMC_ENABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
				 0, &res);
		if (res.a0 == OPTEE_SMC_RETURN_OK)
			break;
		optee_cq_wait_for_completion(&optee->call_queue, &w);
	}
	optee_cq_wait_final(&optee->call_queue, &w);
}

/**
 * optee_disable_shm_cache() - Disables caching of some shared memory allocation
 *			      in OP-TEE
 * @optee:	main service struct
 */
void optee_disable_shm_cache(struct optee *optee)
{
	struct optee_call_waiter w;

	/* We need to retry until secure world isn't busy. */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		union {
			struct arm_smccc_res smccc;
			struct optee_smc_disable_shm_cache_result result;
		} res;

		optee->invoke_fn(OPTEE_SMC_DISABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
				 0, &res.smccc);
		if (res.result.status == OPTEE_SMC_RETURN_ENOTAVAIL)
			break; /* All shm's freed */
		if (res.result.status == OPTEE_SMC_RETURN_OK) {
			struct tee_shm *shm;

			shm = reg_pair_to_ptr(res.result.shm_upper32,
					      res.result.shm_lower32);
			tee_shm_free(shm);
		} else {
			optee_cq_wait_for_completion(&optee->call_queue, &w);
		}
	}
	optee_cq_wait_final(&optee->call_queue, &w);
}

/**
 * optee_ffa_disable_shm_cache() - Disables caching of some shared memory
 *                                  allocation in OP-TEE
 * @optee:	main service struct
 */
void optee_ffa_disable_shm_cache(struct optee *optee)
{
	BUG();
}

#define PAGELIST_ENTRIES_PER_PAGE				\
	((OPTEE_MSG_NONCONTIG_PAGE_SIZE / sizeof(u64)) - 1)

/**
 * optee_fill_pages_list() - write list of user pages to given shared
 * buffer.
 *
 * @dst: page-aligned buffer where list of pages will be stored
 * @pages: array of pages that represents shared buffer
 * @num_pages: number of entries in @pages
 * @page_offset: offset of user buffer from page start
 *
 * @dst should be big enough to hold list of user page addresses and
 *	links to the next pages of buffer
 */
void optee_fill_pages_list(u64 *dst, struct page **pages, int num_pages,
			   size_t page_offset)
{
	int n = 0;
	phys_addr_t optee_page;
	/*
	 * Refer to OPTEE_MSG_ATTR_NONCONTIG description in optee_msg.h
	 * for details.
	 */
	struct {
		u64 pages_list[PAGELIST_ENTRIES_PER_PAGE];
		u64 next_page_data;
	} *pages_data;

	/*
	 * Currently OP-TEE uses 4k page size and it does not looks
	 * like this will change in the future.  On other hand, there are
	 * no know ARM architectures with page size < 4k.
	 * Thus the next built assert looks redundant. But the following
	 * code heavily relies on this assumption, so it is better be
	 * safe than sorry.
	 */
	BUILD_BUG_ON(PAGE_SIZE < OPTEE_MSG_NONCONTIG_PAGE_SIZE);

	pages_data = (void *)dst;
	/*
	 * If linux page is bigger than 4k, and user buffer offset is
	 * larger than 4k/8k/12k/etc this will skip first 4k pages,
	 * because they bear no value data for OP-TEE.
	 */
	optee_page = page_to_phys(*pages) +
		round_down(page_offset, OPTEE_MSG_NONCONTIG_PAGE_SIZE);

	while (true) {
		pages_data->pages_list[n++] = optee_page;

		if (n == PAGELIST_ENTRIES_PER_PAGE) {
			pages_data->next_page_data =
				virt_to_phys(pages_data + 1);
			pages_data++;
			n = 0;
		}

		optee_page += OPTEE_MSG_NONCONTIG_PAGE_SIZE;
		if (!(optee_page & ~PAGE_MASK)) {
			if (!--num_pages)
				break;
			pages++;
			optee_page = page_to_phys(*pages);
		}
	}
}

/*
 * The final entry in each pagelist page is a pointer to the next
 * pagelist page.
 */
static size_t get_pages_list_size(size_t num_entries)
{
	int pages = DIV_ROUND_UP(num_entries, PAGELIST_ENTRIES_PER_PAGE);

	return pages * OPTEE_MSG_NONCONTIG_PAGE_SIZE;
}

u64 *optee_allocate_pages_list(size_t num_entries)
{
	return alloc_pages_exact(get_pages_list_size(num_entries), GFP_KERNEL);
}

void optee_free_pages_list(void *list, size_t num_entries)
{
	free_pages_exact(list, get_pages_list_size(num_entries));
}

static bool is_normal_memory(pgprot_t p)
{
#if defined(CONFIG_ARM)
	return (pgprot_val(p) & L_PTE_MT_MASK) == L_PTE_MT_WRITEALLOC;
#elif defined(CONFIG_ARM64)
	return (pgprot_val(p) & PTE_ATTRINDX_MASK) == PTE_ATTRINDX(MT_NORMAL);
#else
#error "Unuspported architecture"
#endif
}

static int __check_mem_type(struct vm_area_struct *vma, unsigned long end)
{
	while (vma && is_normal_memory(vma->vm_page_prot)) {
		if (vma->vm_end >= end)
			return 0;
		vma = vma->vm_next;
	}

	return -EINVAL;
}

static int check_mem_type(unsigned long start, size_t num_pages)
{
	struct mm_struct *mm = current->mm;
	int rc;

	/*
	 * Allow kernel address to register with OP-TEE as kernel
	 * pages are configured as normal memory only.
	 */
	if (virt_addr_valid(start))
		return 0;

	mmap_read_lock(mm);
	rc = __check_mem_type(find_vma(mm, start),
			      start + num_pages * PAGE_SIZE);
	mmap_read_unlock(mm);

	return rc;
}

int optee_shm_register(struct tee_context *ctx, struct tee_shm *shm,
		       struct page **pages, size_t num_pages,
		       unsigned long start)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_msg_arg *msg_arg = NULL;
	struct tee_shm *shm_arg = NULL;
	u64 *pages_list = NULL;
	int rc = 0;

	if (!num_pages)
		return -EINVAL;

	rc = check_mem_type(start, num_pages);
	if (rc)
		return rc;

	pages_list = optee_allocate_pages_list(num_pages);
	if (!pages_list)
		return -ENOMEM;

	shm_arg = get_msg_arg(ctx, 1, &msg_arg);
	if (IS_ERR(shm_arg)) {
		rc = PTR_ERR(shm_arg);
		goto out;
	}

	optee_fill_pages_list(pages_list, pages, num_pages,
			      tee_shm_get_page_offset(shm));

	msg_arg->cmd = OPTEE_MSG_CMD_REGISTER_SHM;
	msg_arg->params->attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
				OPTEE_MSG_ATTR_NONCONTIG;
	msg_arg->params->u.tmem.shm_ref = (unsigned long)shm;
	msg_arg->params->u.tmem.size = tee_shm_get_size(shm);
	/*
	 * In the least bits of msg_arg->params->u.tmem.buf_ptr we
	 * store buffer offset from 4k page, as described in OP-TEE ABI.
	 */
	msg_arg->params->u.tmem.buf_ptr = virt_to_phys(pages_list) |
	  (tee_shm_get_page_offset(shm) & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1));

	if (optee->ops->do_call_with_arg(ctx, shm) ||
	    msg_arg->ret != TEEC_SUCCESS)
		rc = -EINVAL;

	tee_shm_free(shm_arg);
out:
	optee_free_pages_list(pages_list, num_pages);
	return rc;
}

int optee_shm_unregister(struct tee_context *ctx, struct tee_shm *shm)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_msg_arg *msg_arg = NULL;
	struct tee_shm *shm_arg = NULL;
	int rc = 0;

	shm_arg = get_msg_arg(ctx, 1, &msg_arg);
	if (IS_ERR(shm_arg))
		return PTR_ERR(shm_arg);

	msg_arg->cmd = OPTEE_MSG_CMD_UNREGISTER_SHM;

	msg_arg->params[0].attr = OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
	msg_arg->params[0].u.rmem.shm_ref = (unsigned long)shm;

	if (optee->ops->do_call_with_arg(ctx, shm) ||
	    msg_arg->ret != TEEC_SUCCESS)
		rc = -EINVAL;
	tee_shm_free(shm_arg);
	return rc;
}

int optee_shm_register_supp(struct tee_context *ctx, struct tee_shm *shm,
			    struct page **pages, size_t num_pages,
			    unsigned long start)
{
	/*
	 * We don't want to register supplicant memory in OP-TEE.
	 * Instead information about it will be passed in RPC code.
	 */
	return check_mem_type(start, num_pages);
}

int optee_shm_unregister_supp(struct tee_context *ctx, struct tee_shm *shm)
{
	return 0;
}

#ifdef CONFIG_ARM_FFA_TRANSPORT
static int optee_ffa_yielding_call(struct tee_context *ctx,
				   struct ffa_send_direct_data *data)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	struct ffa_device *ffa_dev = optee->ffa.ffa_dev;
	u32 orig_cmd = data->data0;
	struct optee_call_waiter w;
	u32 w4 = data->data1;
	u32 w5 = data->data2;
	u32 w6 = data->data3;
	int rc;

	/* Initialize waiter */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		rc = ffa_ops->sync_send_receive(ffa_dev, ffa_dev->vm_id, data);

		if (rc) {
			pr_err("rc %d\n", rc);
			rc = -EIO;
			goto done;
		}

		switch ((int)data->data0) {
		case 0: //FFA_SUCCESS
			break;
		case -4: //FFA_BUSY
			if (orig_cmd == OPTEE_FFA_YIELDING_CALL_RESUME) {
				pr_err("err OPTEE_FFA_YIELDING_CALL_RESUME\n");
				rc = -EIO;
				goto done;
			}

			/*
			 * Out of threads in secure world, wait for a thread
			 * become available.
			 */
			optee_cq_wait_for_completion(&optee->call_queue, &w);
			data->data0 = orig_cmd;
			data->data1 = w4;
			data->data2 = w5;
			data->data3 = w6;
			continue;
		default:
			pr_err("data->data0 0x%lx\n", data->data0);
			rc = -EIO;
			goto done;
		}

		if (data->data1 == OPTEE_FFA_YIELDING_CALL_RETURN_DONE)
			goto done;

		might_sleep();
		w4 = data->data1;
		w5 = data->data2;
		w6 = data->data3;
		optee_handle_ffa_rpc(ctx, &w4, &w5, &w6);
		data->data0 = OPTEE_FFA_YIELDING_CALL_RESUME;
		data->data1 = w4;
		data->data2 = w5;
		data->data3 = w6;
	}
done:

	/*
	 * We're done with our thread in secure world, if there's any
	 * thread waiters wake up one.
	 */
	optee_cq_wait_final(&optee->call_queue, &w);

	return rc;
}

int optee_ffa_do_call_with_arg(struct tee_context *ctx, struct tee_shm *shm)
{
	struct ffa_send_direct_data data = {
		.data0 = OPTEE_FFA_YIELDING_CALL_WITH_ARG,
		.data1 = (u32)shm->sec_world_id,
		.data2 = (u32)(shm->sec_world_id >> 32)
	};

	if (shm->offset)
		return -EINVAL;

	return optee_ffa_yielding_call(ctx, &data);
}

int optee_ffa_shm_register(struct tee_context *ctx, struct tee_shm *shm,
			    struct page **pages, size_t num_pages,
			    unsigned long start)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	struct ffa_device *ffa_dev = optee->ffa.ffa_dev;
	u64 global_handle = 0;
	u32 rc = 0;
	struct sg_table sgt;
	struct ffa_mem_region_attributes mem_attr = {
		.receiver = ffa_dev->vm_id,
		.attrs = FFA_MEM_RW,
	};
	struct ffa_mem_ops_args args = {
		.use_txbuf = true,
		.attrs = &mem_attr,
		.nattrs = 1,
		.g_handle = &global_handle,
	};

	rc = check_mem_type(start, num_pages);
	if (rc)
		return rc;

	rc = sg_alloc_table_from_pages(&sgt, pages, num_pages, 0,
				       num_pages * 4096, GFP_KERNEL);
	if (rc)
		return rc;
	args.sg = sgt.sgl;
	rc = ffa_ops->memory_share(&args);
	sg_free_table(&sgt);
	if (rc)
		return rc;

	rc = optee_shm_add_ffa_handle(optee, shm, global_handle);
	if (rc) {
		ffa_ops->memory_reclaim(global_handle, 0);
		return rc;
	}

	shm->sec_world_id = global_handle;

	return 0;
}

int optee_ffa_shm_unregister(struct tee_context *ctx, struct tee_shm *shm)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	u64 global_handle = shm->sec_world_id;
	struct ffa_send_direct_data data = {
		.data0 = OPTEE_FFA_YIELDING_CALL_UNREGISTER_SHM,
		.data1 = (u32)global_handle,
		.data2 = (u32)(global_handle >> 32)
	};
	int rc;

	/* XXX to be moved below the call to memory_reclain()? */
	optee_shm_rem_ffa_handle(optee, global_handle);
	shm->sec_world_id = 0;

	rc = optee_ffa_yielding_call(ctx, &data);
	if (rc)
		pr_err("OPTEE_FFA_YIELDING_CALL_UNREGISTER_SHM id 0x%llx rc %d\n",
		       global_handle, rc);

	rc = ffa_ops->memory_reclaim(global_handle, 0);
	if (rc)
		pr_err("mem_reclain: 0x%llx %d", global_handle, rc);

	return rc;
}

int optee_ffa_shm_unregister_supp(struct tee_context *ctx,
				   struct tee_shm *shm)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	int rc;

	/*
	 * We're skipping the OPTEE_FFA_YIELDING_CALL_UNREGISTER_SHM call
	 * since this is OP-TEE freeing via RPC so it has already retired
	 * this ID.
	 */

	rc = ffa_ops->memory_reclaim(shm->sec_world_id, 0);
	if (rc)
		pr_err("mem_reclain: 0x%llx %d", shm->sec_world_id, rc);

	optee_shm_rem_ffa_handle(optee, shm->sec_world_id);

	shm->sec_world_id = 0;

	return rc;
}
#endif /*CONFIG_ARM_FFA_TRANSPORT*/
