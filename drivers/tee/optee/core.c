// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2021, Linaro Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include "optee_private.h"
#include "optee_smc.h"
#include "optee_ffa.h"
#include "shm_pool.h"

#define DRIVER_NAME "optee"

#define OPTEE_SHM_NUM_PRIV_PAGES	CONFIG_OPTEE_SHM_NUM_PRIV_PAGES

static void from_msg_param_value(struct tee_param *p, u32 attr,
				 const struct optee_msg_param *mp)
{
	p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT +
		  attr - OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	p->u.value.a = mp->u.value.a;
	p->u.value.b = mp->u.value.b;
	p->u.value.c = mp->u.value.c;
}

static int from_msg_param_tmp_mem(struct tee_param *p, u32 attr,
				  const struct optee_msg_param *mp)
{
	struct tee_shm *shm;
	phys_addr_t pa;
	int rc;

	p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
		  attr - OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	p->u.memref.size = mp->u.tmem.size;
	shm = (struct tee_shm *)(unsigned long)mp->u.tmem.shm_ref;
	if (!shm) {
		p->u.memref.shm_offs = 0;
		p->u.memref.shm = NULL;
		return 0;
	}

	rc = tee_shm_get_pa(shm, 0, &pa);
	if (rc)
		return rc;

	p->u.memref.shm_offs = mp->u.tmem.buf_ptr - pa;
	p->u.memref.shm = shm;

	/* Check that the memref is covered by the shm object */
	if (p->u.memref.size) {
		size_t o = p->u.memref.shm_offs +
			   p->u.memref.size - 1;

		rc = tee_shm_get_pa(shm, o, NULL);
		if (rc)
			return rc;
	}

	return 0;
}

static void from_msg_param_reg_mem(struct tee_param *p, u32 attr,
				   const struct optee_msg_param *mp)
{
	struct tee_shm *shm;

	p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
		  attr - OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
	p->u.memref.size = mp->u.rmem.size;
	shm = (struct tee_shm *)(unsigned long)mp->u.rmem.shm_ref;

	if (shm) {
		p->u.memref.shm_offs = mp->u.rmem.offs;
		p->u.memref.shm = shm;
	} else {
		p->u.memref.shm_offs = 0;
		p->u.memref.shm = NULL;
	}
}

/**
 * optee_from_msg_param() - convert from OPTEE_MSG parameters to
 *			    struct tee_param
 * @optee:	main service struct
 * @params:	subsystem internal parameter representation
 * @num_params:	number of elements in the parameter arrays
 * @msg_params:	OPTEE_MSG parameters
 * Returns 0 on success or <0 on failure
 */
static int optee_from_msg_param(struct optee *optee, struct tee_param *params,
				size_t num_params,
				const struct optee_msg_param *msg_params)
{
	int rc;
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct optee_msg_param *mp = msg_params + n;
		u32 attr = mp->attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			from_msg_param_value(p, attr, mp);
			break;
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			rc = from_msg_param_tmp_mem(p, attr, mp);
			if (rc)
				return rc;
			break;
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
			from_msg_param_reg_mem(p, attr, mp);
			break;

		default:
			return -EINVAL;
		}
	}
	return 0;
}

static void to_msg_param_value(struct optee_msg_param *mp,
			       const struct tee_param *p)
{
	mp->attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	mp->u.value.a = p->u.value.a;
	mp->u.value.b = p->u.value.b;
	mp->u.value.c = p->u.value.c;
}

static int to_msg_param_tmp_mem(struct optee_msg_param *mp,
				const struct tee_param *p)
{
	int rc;
	phys_addr_t pa;

	mp->attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.tmem.shm_ref = (unsigned long)p->u.memref.shm;
	mp->u.tmem.size = p->u.memref.size;

	if (!p->u.memref.shm) {
		mp->u.tmem.buf_ptr = 0;
		return 0;
	}

	rc = tee_shm_get_pa(p->u.memref.shm, p->u.memref.shm_offs, &pa);
	if (rc)
		return rc;

	mp->u.tmem.buf_ptr = pa;
	mp->attr |= OPTEE_MSG_ATTR_CACHE_PREDEFINED <<
		    OPTEE_MSG_ATTR_CACHE_SHIFT;

	return 0;
}

static int to_msg_param_reg_mem(struct optee_msg_param *mp,
				const struct tee_param *p)
{
	mp->attr = OPTEE_MSG_ATTR_TYPE_RMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.rmem.shm_ref = (unsigned long)p->u.memref.shm;
	mp->u.rmem.size = p->u.memref.size;
	mp->u.rmem.offs = p->u.memref.shm_offs;
	return 0;
}

/**
 * optee_to_msg_param() - convert from struct tee_params to OPTEE_MSG parameters
 * @optee:	main service struct
 * @msg_params:	OPTEE_MSG parameters
 * @num_params:	number of elements in the parameter arrays
 * @params:	subsystem itnernal parameter representation
 * Returns 0 on success or <0 on failure
 */
static int optee_to_msg_param(struct optee *optee,
			      struct optee_msg_param *msg_params,
			      size_t num_params, const struct tee_param *params)
{
	int rc;
	size_t n;

	for (n = 0; n < num_params; n++) {
		const struct tee_param *p = params + n;
		struct optee_msg_param *mp = msg_params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			to_msg_param_value(mp, p);
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (tee_shm_is_registered(p->u.memref.shm))
				rc = to_msg_param_reg_mem(mp, p);
			else
				rc = to_msg_param_tmp_mem(mp, p);
			if (rc)
				return rc;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static void optee_get_version(struct tee_device *teedev,
			      struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP,
	};
	struct optee *optee = tee_get_drvdata(teedev);

	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)
		v.gen_caps |= TEE_GEN_CAP_REG_MEM;
	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_MEMREF_NULL)
		v.gen_caps |= TEE_GEN_CAP_MEMREF_NULL;
	*vers = v;
}

static void optee_bus_scan(struct work_struct *work)
{
	WARN_ON(optee_enumerate_devices(PTA_CMD_GET_DEVICES_SUPP));
}

static int optee_open(struct tee_context *ctx)
{
	struct optee_context_data *ctxdata;
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);

	ctxdata = kzalloc(sizeof(*ctxdata), GFP_KERNEL);
	if (!ctxdata)
		return -ENOMEM;

	if (teedev == optee->supp_teedev) {
		bool busy = true;

		mutex_lock(&optee->supp.mutex);
		if (!optee->supp.ctx) {
			busy = false;
			optee->supp.ctx = ctx;
		}
		mutex_unlock(&optee->supp.mutex);
		if (busy) {
			kfree(ctxdata);
			return -EBUSY;
		}

		if (!optee->scan_bus_done) {
			INIT_WORK(&optee->scan_bus_work, optee_bus_scan);
			optee->scan_bus_wq = create_workqueue("optee_bus_scan");
			if (!optee->scan_bus_wq) {
				kfree(ctxdata);
				return -ECHILD;
			}
			queue_work(optee->scan_bus_wq, &optee->scan_bus_work);
			optee->scan_bus_done = true;
		}
	}
	mutex_init(&ctxdata->mutex);
	INIT_LIST_HEAD(&ctxdata->sess_list);

	ctx->cap_memref_null = optee_is_ffa_based(optee) ||
			       (optee->sec_caps &
				OPTEE_SMC_SEC_CAP_MEMREF_NULL);

	ctx->data = ctxdata;
	return 0;
}

static void optee_release_helper(struct tee_context *ctx,
				 int (*close_session)(struct tee_context *ctx,
						      u32 session))
{
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_session *sess;
	struct optee_session *sess_tmp;

	if (!ctxdata)
		return;

	list_for_each_entry_safe(sess, sess_tmp, &ctxdata->sess_list,
				 list_node) {
		list_del(&sess->list_node);
		close_session(ctx, sess->session_id);
		kfree(sess);
	}
	kfree(ctxdata);
	ctx->data = NULL;
}

static void optee_release(struct tee_context *ctx)
{
	optee_release_helper(ctx, optee_close_session_helper);
}

static void optee_release_supp(struct tee_context *ctx)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);

	optee_release_helper(ctx, optee_close_session_helper);
	if (optee->scan_bus_wq) {
		destroy_workqueue(optee->scan_bus_wq);
		optee->scan_bus_wq = NULL;
	}
	optee_supp_release(&optee->supp);
}

static const struct tee_driver_ops optee_clnt_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.open_session = optee_open_session,
	.close_session = optee_close_session,
	.invoke_func = optee_invoke_func,
	.cancel_req = optee_cancel_req,
	.shm_register = optee_shm_register,
	.shm_unregister = optee_shm_unregister,
};

static const struct tee_desc optee_clnt_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &optee_clnt_ops,
	.owner = THIS_MODULE,
};

static const struct tee_driver_ops optee_supp_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release_supp,
	.supp_recv = optee_supp_recv,
	.supp_send = optee_supp_send,
	.shm_register = optee_shm_register_supp,
	.shm_unregister = optee_shm_unregister_supp,
};

static const struct tee_desc optee_supp_desc = {
	.name = DRIVER_NAME "-supp",
	.ops = &optee_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static const struct optee_ops optee_ops = {
	.do_call_with_arg = optee_do_call_with_arg,
	.to_msg_param = optee_to_msg_param,
	.from_msg_param = optee_from_msg_param,
};

static bool optee_msg_api_uid_is_optee_api(optee_invoke_fn *invoke_fn)
{
	struct arm_smccc_res res;

	invoke_fn(OPTEE_SMC_CALLS_UID, 0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == OPTEE_MSG_UID_0 && res.a1 == OPTEE_MSG_UID_1 &&
	    res.a2 == OPTEE_MSG_UID_2 && res.a3 == OPTEE_MSG_UID_3)
		return true;
	return false;
}

static void optee_msg_get_os_revision(optee_invoke_fn *invoke_fn)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_call_get_os_revision_result result;
	} res = {
		.result = {
			.build_id = 0
		}
	};

	invoke_fn(OPTEE_SMC_CALL_GET_OS_REVISION, 0, 0, 0, 0, 0, 0, 0,
		  &res.smccc);

	if (res.result.build_id)
		pr_info("revision %lu.%lu (%08lx)", res.result.major,
			res.result.minor, res.result.build_id);
	else
		pr_info("revision %lu.%lu", res.result.major, res.result.minor);
}

static bool optee_msg_api_revision_is_compatible(optee_invoke_fn *invoke_fn)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_calls_revision_result result;
	} res;

	invoke_fn(OPTEE_SMC_CALLS_REVISION, 0, 0, 0, 0, 0, 0, 0, &res.smccc);

	if (res.result.major == OPTEE_MSG_REVISION_MAJOR &&
	    (int)res.result.minor >= OPTEE_MSG_REVISION_MINOR)
		return true;
	return false;
}

static bool optee_msg_exchange_capabilities(optee_invoke_fn *invoke_fn,
					    u32 *sec_caps)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_exchange_capabilities_result result;
	} res;
	u32 a1 = 0;

	/*
	 * TODO This isn't enough to tell if it's UP system (from kernel
	 * point of view) or not, is_smp() returns the the information
	 * needed, but can't be called directly from here.
	 */
	if (!IS_ENABLED(CONFIG_SMP) || nr_cpu_ids == 1)
		a1 |= OPTEE_SMC_NSEC_CAP_UNIPROCESSOR;

	invoke_fn(OPTEE_SMC_EXCHANGE_CAPABILITIES, a1, 0, 0, 0, 0, 0, 0,
		  &res.smccc);

	if (res.result.status != OPTEE_SMC_RETURN_OK)
		return false;

	*sec_caps = res.result.capabilities;
	return true;
}

static struct tee_shm_pool *optee_config_dyn_shm(void)
{
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;

	rc = optee_shm_pool_alloc_pages();
	if (IS_ERR(rc))
		return rc;
	priv_mgr = rc;

	rc = optee_shm_pool_alloc_pages();
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		return rc;
	}
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		tee_shm_pool_mgr_destroy(dmabuf_mgr);
	}

	return rc;
}

static struct tee_shm_pool *
optee_config_shm_memremap(optee_invoke_fn *invoke_fn, void **memremaped_shm)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_get_shm_config_result result;
	} res;
	unsigned long vaddr;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin;
	phys_addr_t end;
	void *va;
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;
	const int sz = OPTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE;

	invoke_fn(OPTEE_SMC_GET_SHM_CONFIG, 0, 0, 0, 0, 0, 0, 0, &res.smccc);
	if (res.result.status != OPTEE_SMC_RETURN_OK) {
		pr_err("static shm service not available\n");
		return ERR_PTR(-ENOENT);
	}

	if (res.result.settings != OPTEE_SMC_SHM_CACHED) {
		pr_err("only normal cached shared memory supported\n");
		return ERR_PTR(-EINVAL);
	}

	begin = roundup(res.result.start, PAGE_SIZE);
	end = rounddown(res.result.start + res.result.size, PAGE_SIZE);
	paddr = begin;
	size = end - begin;

	if (size < 2 * OPTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE) {
		pr_err("too small shared memory area\n");
		return ERR_PTR(-EINVAL);
	}

	va = memremap(paddr, size, MEMREMAP_WB);
	if (!va) {
		pr_err("shared memory ioremap failed\n");
		return ERR_PTR(-EINVAL);
	}
	vaddr = (unsigned long)va;

	rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, sz,
					    3 /* 8 bytes aligned */);
	if (IS_ERR(rc))
		goto err_memunmap;
	priv_mgr = rc;

	vaddr += sz;
	paddr += sz;
	size -= sz;

	rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, size, PAGE_SHIFT);
	if (IS_ERR(rc))
		goto err_free_priv_mgr;
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc))
		goto err_free_dmabuf_mgr;

	*memremaped_shm = va;

	return rc;

err_free_dmabuf_mgr:
	tee_shm_pool_mgr_destroy(dmabuf_mgr);
err_free_priv_mgr:
	tee_shm_pool_mgr_destroy(priv_mgr);
err_memunmap:
	memunmap(va);
	return rc;
}

#ifdef CONFIG_ARM_FFA_TRANSPORT
static void optee_ffa_get_version(struct tee_device *teedev,
				  struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP | TEE_GEN_CAP_REG_MEM |
			    TEE_GEN_CAP_MEMREF_NULL,
	};

	*vers = v;
}

struct shm_rhash {
	struct tee_shm *shm;
	u64 global_id;
	struct rhash_head linkage;
};

static void rh_free_fn(void *ptr, void *arg)
{
	kfree(ptr);
}

static const struct rhashtable_params shm_rhash_params = {
	.head_offset = offsetof(struct shm_rhash, linkage),
	.key_len     = sizeof(u64),
	.key_offset  = offsetof(struct shm_rhash, global_id),
	.automatic_shrinking = true,
};

struct tee_shm *optee_shm_from_ffa_handle(struct optee *optee, u64 global_id)
{
	struct tee_shm *shm = NULL;
	struct shm_rhash *r;

	mutex_lock(&optee->ffa.mutex);
	r = rhashtable_lookup_fast(&optee->ffa.global_ids, &global_id,
				   shm_rhash_params);
	if (r)
		shm = r->shm;
	mutex_unlock(&optee->ffa.mutex);

	return shm;
}

int optee_shm_add_ffa_handle(struct optee *optee, struct tee_shm *shm,
			     u64 global_id)
{
	struct shm_rhash *r;
	int rc;

	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	r->shm = shm;
	r->global_id = global_id;

	mutex_lock(&optee->ffa.mutex);
	rc = rhashtable_lookup_insert_fast(&optee->ffa.global_ids, &r->linkage,
					   shm_rhash_params);
	mutex_unlock(&optee->ffa.mutex);

	if (rc)
		kfree(r);

	return rc;
}

int optee_shm_rem_ffa_handle(struct optee *optee, u64 global_id)
{
	struct shm_rhash *r;
	int rc = -ENOENT;

	mutex_lock(&optee->ffa.mutex);
	r = rhashtable_lookup_fast(&optee->ffa.global_ids, &global_id,
				   shm_rhash_params);
	if (r)
		rc = rhashtable_remove_fast(&optee->ffa.global_ids,
					    &r->linkage, shm_rhash_params);
	mutex_unlock(&optee->ffa.mutex);

	if (!rc)
		kfree(r);

	return rc;
}

static void from_msg_param_ffa_mem(struct optee *optee, struct tee_param *p,
				   u32 attr, const struct optee_msg_param *mp)
{
	struct tee_shm *shm = NULL;
	u64 offs_high = 0;
	u64 offs_low = 0;

	p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
		  attr - OPTEE_MSG_ATTR_TYPE_FMEM_INPUT;
	p->u.memref.size = mp->u.fmem.size;

	if (mp->u.fmem.global_id != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID)
		shm = optee_shm_from_ffa_handle(optee, mp->u.fmem.global_id);
	p->u.memref.shm = shm;

	if (shm) {
		offs_low = mp->u.fmem.offs_low;
		offs_high = mp->u.fmem.offs_high;
	}
	p->u.memref.shm_offs = offs_low | offs_high << 32;
}

/**
 * optee_ffa_from_msg_param() - convert from OPTEE_MSG parameters to
 *				struct tee_param
 * @optee:	main service struct
 * @params:	subsystem internal parameter representation
 * @num_params:	number of elements in the parameter arrays
 * @msg_params:	OPTEE_MSG parameters
 *
 * Returns 0 on success or <0 on failure
 */
static int optee_ffa_from_msg_param(struct optee *optee,
				    struct tee_param *params, size_t num_params,
				    const struct optee_msg_param *msg_params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct optee_msg_param *mp = msg_params + n;
		u32 attr = mp->attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			from_msg_param_value(p, attr, mp);
			break;
		case OPTEE_MSG_ATTR_TYPE_FMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_INOUT:
			from_msg_param_ffa_mem(optee, p, attr, mp);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int to_msg_param_ffa_mem(struct optee_msg_param *mp,
				const struct tee_param *p)
{
	struct tee_shm *shm = p->u.memref.shm;

	mp->attr = OPTEE_MSG_ATTR_TYPE_FMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	if (shm) {
		u64 shm_offs = p->u.memref.shm_offs;

		mp->u.fmem.internal_offs = shm->offset;

		mp->u.fmem.offs_low = shm_offs;
		mp->u.fmem.offs_high = shm_offs >> 32;
		/* Check that the entire offset could be stored. */
		if (mp->u.fmem.offs_high != shm_offs >> 32)
			return -EINVAL;

		mp->u.fmem.global_id = shm->sec_world_id;
	} else {
		memset(&mp->u, 0, sizeof(mp->u));
		mp->u.fmem.global_id = OPTEE_MSG_FMEM_INVALID_GLOBAL_ID;
	}
	mp->u.fmem.size = p->u.memref.size;

	return 0;
}

/**
 * optee_to_msg_param() - convert from struct tee_params to OPTEE_MSG parameters
 * @optee:	main service struct
 * @msg_params:	OPTEE_MSG parameters
 * @num_params:	number of elements in the parameter arrays
 * @params:	subsystem itnernal parameter representation
 * Returns 0 on success or <0 on failure
 */
static int optee_ffa_to_msg_param(struct optee *optee,
				  struct optee_msg_param *msg_params,
				  size_t num_params,
				  const struct tee_param *params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		const struct tee_param *p = params + n;
		struct optee_msg_param *mp = msg_params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			to_msg_param_value(mp, p);
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (to_msg_param_ffa_mem(mp, p))
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static bool optee_ffa_api_is_compatbile(struct ffa_device *ffa_dev,
					const struct ffa_dev_ops *ops)
{
	struct ffa_send_direct_data data = { OPTEE_FFA_GET_API_VERSION };
	int rc;

	ops->mode_32bit_set(ffa_dev);

	rc = ops->sync_send_receive(ffa_dev, &data);
	if (rc) {
		pr_err("Unexpected error %d\n", rc);
		return false;
	}
	if (data.data0 != OPTEE_FFA_VERSION_MAJOR ||
	    data.data1 < OPTEE_FFA_VERSION_MINOR) {
		pr_err("Incompatible OP-TEE API version %lu.%lu",
		       data.data0, data.data1);
		return false;
	}

	data = (struct ffa_send_direct_data){ OPTEE_FFA_GET_OS_VERSION };
	rc = ops->sync_send_receive(ffa_dev, &data);
	if (rc) {
		pr_err("Unexpected error %d\n", rc);
		return false;
	}
	if (data.data2)
		pr_info("revision %lu.%lu (%08lx)",
			data.data0, data.data1, data.data2);
	else
		pr_info("revision %lu.%lu", data.data0, data.data1);

	return true;
}

static bool optee_ffa_exchange_caps(struct ffa_device *ffa_dev,
				    const struct ffa_dev_ops *ops,
				    u32 *sec_caps, unsigned int *rpc_arg_count)
{
	struct ffa_send_direct_data data = { OPTEE_FFA_EXCHANGE_CAPABILITIES };
	int rc;

	rc = ops->sync_send_receive(ffa_dev, &data);
	if (rc) {
		pr_err("Unexpected error %d", rc);
		return false;
	}
	if (data.data0) {
		pr_err("Unexpected exchange error %lu", data.data0);
		return false;
	}

	*sec_caps = 0;
	*rpc_arg_count = (u8)data.data1;

	return true;
}

static struct tee_shm_pool *optee_ffa_config_dyn_shm(void)
{
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;

	rc = optee_ffa_shm_pool_alloc_pages();
	if (IS_ERR(rc))
		return rc;
	priv_mgr = rc;

	rc = optee_ffa_shm_pool_alloc_pages();
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		return rc;
	}
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		tee_shm_pool_mgr_destroy(dmabuf_mgr);
	}

	return rc;
}

static const struct tee_driver_ops optee_ffa_clnt_ops = {
	.get_version = optee_ffa_get_version,
	.open = optee_open,
	.release = optee_release,
	.open_session = optee_open_session,
	.close_session = optee_close_session,
	.invoke_func = optee_invoke_func,
	.cancel_req = optee_cancel_req,
	.shm_register = optee_ffa_shm_register,
	.shm_unregister = optee_ffa_shm_unregister,
};

static const struct tee_desc optee_ffa_clnt_desc = {
	.name = DRIVER_NAME "ffa-clnt",
	.ops = &optee_ffa_clnt_ops,
	.owner = THIS_MODULE,
};

static const struct tee_driver_ops optee_ffa_supp_ops = {
	.get_version = optee_ffa_get_version,
	.open = optee_open,
	.release = optee_release_supp,
	.supp_recv = optee_supp_recv,
	.supp_send = optee_supp_send,
	.shm_register = optee_ffa_shm_register, /* same as for clnt ops */
	.shm_unregister = optee_ffa_shm_unregister_supp,
};

static const struct tee_desc optee_ffa_supp_desc = {
	.name = DRIVER_NAME "ffa-supp",
	.ops = &optee_ffa_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static const struct optee_ops optee_ffa_ops = {
	.do_call_with_arg = optee_ffa_do_call_with_arg,
	.to_msg_param = optee_ffa_to_msg_param,
	.from_msg_param = optee_ffa_from_msg_param,
};

static void optee_ffa_remove(struct ffa_device *ffa_dev)
{
	(void)ffa_dev;
}

static int optee_ffa_probe(struct ffa_device *ffa_dev)
{
	const struct ffa_dev_ops *ffa_ops;
	unsigned int rpc_arg_count;
	struct tee_device *teedev;
	struct optee *optee;
	u32 sec_caps;
	int rc;

	ffa_ops = ffa_dev_ops_get(ffa_dev);
	if (!ffa_ops) {
		pr_warn("failed \"method\" init: ffa\n");
		return -ENOENT;
	}

	if (!optee_ffa_api_is_compatbile(ffa_dev, ffa_ops))
		return -EINVAL;

	if (!optee_ffa_exchange_caps(ffa_dev, ffa_ops, &sec_caps,
				     &rpc_arg_count))
		return -EINVAL;

	optee = kzalloc(sizeof(*optee), GFP_KERNEL);
	if (!optee) {
		rc = -ENOMEM;
		goto err;
	}
	optee->pool = optee_ffa_config_dyn_shm();
	if (IS_ERR(optee->pool)) {
		rc = PTR_ERR(optee->pool);
		optee->pool = NULL;
		goto err;
	}

	optee->ops = &optee_ffa_ops;
	optee->ffa.ffa_dev = ffa_dev;
	optee->ffa.ffa_ops = ffa_ops;
	optee->sec_caps = sec_caps;
	optee->rpc_arg_count = rpc_arg_count;

	teedev = tee_device_alloc(&optee_ffa_clnt_desc, NULL, optee->pool,
				  optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->teedev = teedev;

	teedev = tee_device_alloc(&optee_ffa_supp_desc, NULL, optee->pool,
				  optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->supp_teedev = teedev;

	rc = tee_device_register(optee->teedev);
	if (rc)
		goto err;

	rc = tee_device_register(optee->supp_teedev);
	if (rc)
		goto err;

	rc = rhashtable_init(&optee->ffa.global_ids, &shm_rhash_params);
	if (rc)
		goto err;
	mutex_init(&optee->ffa.mutex);
	mutex_init(&optee->call_queue.mutex);
	INIT_LIST_HEAD(&optee->call_queue.waiters);
	optee_wait_queue_init(&optee->wait_queue);
	optee_supp_init(&optee->supp);
	ffa_dev_set_drvdata(ffa_dev, optee);

	pr_info("initialized driver\n");
	return 0;
err:
	/*
	 * tee_device_unregister() is safe to call even if the
	 * devices hasn't been registered with
	 * tee_device_register() yet.
	 */
	tee_device_unregister(optee->supp_teedev);
	tee_device_unregister(optee->teedev);
	if (optee->pool)
		tee_shm_pool_free(optee->pool);
	kfree(optee);
	return rc;
}

static const struct ffa_device_id optee_ffa_device_id[] = {
	/* 486178e0-e7f8-11e3-bc5e0002a5d5c51b */
	{ UUID_INIT(0x486178e0, 0xe7f8, 0x11e3,
		    0xbc, 0x5e, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b) },
	{}
};

static struct ffa_driver optee_ffa_driver = {
	.name = "optee",
	.probe = optee_ffa_probe,
	.remove = optee_ffa_remove,
	.id_table = optee_ffa_device_id,
};

module_ffa_driver(optee_ffa_driver);
#endif /*CONFIG_ARM_FFA_TRANSPORT*/

/* Simple wrapper functions to be able to use a function pointer */
static void optee_smccc_smc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct arm_smccc_res *res)
{
	arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7, res);
}

static void optee_smccc_hvc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct arm_smccc_res *res)
{
	arm_smccc_hvc(a0, a1, a2, a3, a4, a5, a6, a7, res);
}

static optee_invoke_fn *get_invoke_func(struct device *dev)
{
	const char *method;

	pr_info("probing for conduit method.\n");

	if (device_property_read_string(dev, "method", &method)) {
		pr_warn("missing \"method\" property\n");
		return ERR_PTR(-ENXIO);
	}

	if (!strcmp("hvc", method))
		return optee_smccc_hvc;
	else if (!strcmp("smc", method))
		return optee_smccc_smc;

	pr_warn("invalid \"method\" property: %s\n", method);
	return ERR_PTR(-EINVAL);
}

static int optee_remove(struct platform_device *pdev)
{
	struct optee *optee = platform_get_drvdata(pdev);

	/*
	 * Ask OP-TEE to free all cached shared memory objects to decrease
	 * reference counters and also avoid wild pointers in secure world
	 * into the old shared memory range.
	 */
	if (!optee_is_ffa_based(optee))
		optee_disable_shm_cache(optee);

	/*
	 * The two devices have to be unregistered before we can free the
	 * other resources.
	 */
	tee_device_unregister(optee->supp_teedev);
	tee_device_unregister(optee->teedev);

	tee_shm_pool_free(optee->pool);
	if (optee->memremaped_shm)
		memunmap(optee->memremaped_shm);
	optee_wait_queue_exit(&optee->wait_queue);
	optee_supp_uninit(&optee->supp);
	mutex_destroy(&optee->call_queue.mutex);

#ifdef CONFIG_ARM_FFA_TRANSPORT
	if (optee->ffa.ffa_ops) {
		mutex_destroy(&optee->ffa.mutex);
		rhashtable_free_and_destroy(&optee->ffa.global_ids,
					    rh_free_fn, NULL);
	}
#endif /*CONFIG_ARM_FFA_TRANSPORT*/

	kfree(optee);

	return 0;
}

static int optee_probe(struct platform_device *pdev)
{
	optee_invoke_fn *invoke_fn;
	struct tee_shm_pool *pool = ERR_PTR(-EINVAL);
	struct optee *optee = NULL;
	void *memremaped_shm = NULL;
	struct tee_device *teedev;
	u32 sec_caps;
	int rc;

	invoke_fn = get_invoke_func(&pdev->dev);
	if (IS_ERR(invoke_fn))
		return PTR_ERR(invoke_fn);

	if (!optee_msg_api_uid_is_optee_api(invoke_fn)) {
		pr_warn("api uid mismatch\n");
		return -EINVAL;
	}

	optee_msg_get_os_revision(invoke_fn);

	if (!optee_msg_api_revision_is_compatible(invoke_fn)) {
		pr_warn("api revision mismatch\n");
		return -EINVAL;
	}

	if (!optee_msg_exchange_capabilities(invoke_fn, &sec_caps)) {
		pr_warn("capabilities mismatch\n");
		return -EINVAL;
	}

	/*
	 * Try to use dynamic shared memory if possible
	 */
	if (sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)
		pool = optee_config_dyn_shm();

	/*
	 * If dynamic shared memory is not available or failed - try static one
	 */
	if (IS_ERR(pool) && (sec_caps & OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM))
		pool = optee_config_shm_memremap(invoke_fn, &memremaped_shm);

	if (IS_ERR(pool))
		return PTR_ERR(pool);

	optee = kzalloc(sizeof(*optee), GFP_KERNEL);
	if (!optee) {
		rc = -ENOMEM;
		goto err;
	}

	optee->ops = &optee_ops;
	optee->invoke_fn = invoke_fn;
	optee->sec_caps = sec_caps;

	teedev = tee_device_alloc(&optee_clnt_desc, NULL, pool, optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->teedev = teedev;

	teedev = tee_device_alloc(&optee_supp_desc, NULL, pool, optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->supp_teedev = teedev;

	rc = tee_device_register(optee->teedev);
	if (rc)
		goto err;

	rc = tee_device_register(optee->supp_teedev);
	if (rc)
		goto err;

	mutex_init(&optee->call_queue.mutex);
	INIT_LIST_HEAD(&optee->call_queue.waiters);
	optee_wait_queue_init(&optee->wait_queue);
	optee_supp_init(&optee->supp);
	optee->memremaped_shm = memremaped_shm;
	optee->pool = pool;

	optee_enable_shm_cache(optee);

	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)
		pr_info("dynamic shared memory is enabled\n");

	platform_set_drvdata(pdev, optee);

	rc = optee_enumerate_devices(PTA_CMD_GET_DEVICES);
	if (rc) {
		optee_remove(pdev);
		return rc;
	}

	pr_info("initialized driver\n");
	return 0;
err:
	if (optee) {
		/*
		 * tee_device_unregister() is safe to call even if the
		 * devices hasn't been registered with
		 * tee_device_register() yet.
		 */
		tee_device_unregister(optee->supp_teedev);
		tee_device_unregister(optee->teedev);
		kfree(optee);
	}
	if (pool)
		tee_shm_pool_free(pool);
	if (memremaped_shm)
		memunmap(memremaped_shm);
	return rc;
}

static const struct of_device_id optee_dt_match[] = {
	{ .compatible = "linaro,optee-tz" },
	{},
};
MODULE_DEVICE_TABLE(of, optee_dt_match);

static struct platform_driver optee_driver = {
	.probe  = optee_probe,
	.remove = optee_remove,
	.driver = {
		.name = "optee",
		.of_match_table = optee_dt_match,
	},
};
module_platform_driver(optee_driver);

MODULE_AUTHOR("Linaro");
MODULE_DESCRIPTION("OP-TEE driver");
MODULE_SUPPORTED_DEVICE("");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:optee");
