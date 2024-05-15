// SPDX-License-Identifier: GPL-2.0
/*
 * DMABUF restricted heap exporter for MediaTek
 *
 * Copyright (C) 2024 MediaTek Inc.
 */
#define pr_fmt(fmt)     "rheap_mtk: " fmt

#include <linux/cma.h>
#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/of_reserved_mem.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/uuid.h>

#include "restricted_heap.h"

#define TZ_TA_MEM_UUID_MTK		"4477588a-8476-11e2-ad15-e41f1390d676"

#define TEE_PARAM_NUM			4

enum mtk_secure_mem_type {
	/*
	 * MediaTek static chunk memory carved out for TrustZone. The memory
	 * management is inside the TEE.
	 */
	MTK_SECURE_MEMORY_TYPE_CM_TZ	= 1,
	/*
	 * MediaTek dynamic chunk memory carved out from CMA.
	 * In normal case, the CMA could be used in kernel; When SVP start, we will
	 * allocate whole this CMA and pass whole the CMA PA and size into TEE to
	 * protect it, then the detail memory management also is inside the TEE.
	 */
	MTK_SECURE_MEMORY_TYPE_CM_CMA	= 2,
};

/* This structure also is synchronized with tee, thus not use the phys_addr_t */
struct mtk_tee_scatterlist {
	u64		pa;
	u32		length;
} __packed;

enum mtk_secure_buffer_tee_cmd {
	/*
	 * Allocate the zeroed secure memory from TEE.
	 *
	 * [in]  value[0].a: The buffer size.
	 *       value[0].b: alignment.
	 * [in]  value[1].a: enum mtk_secure_mem_type.
	 * [inout] [in]  value[2].a: pa base in cma case.
	 *               value[2].b: The buffer size in cma case.
	 *         [out] value[2].a: entry number of memory block.
	 *                           If this is 1, it means the memory is continuous.
	 *               value[2].b: buffer PA base.
	 * [out] value[3].a: The secure handle.
	 */
	MTK_TZCMD_SECMEM_ZALLOC		= 0x10000, /* MTK TEE Command ID Base */

	/*
	 * Free secure memory.
	 *
	 * [in]  value[0].a: The secure handle of this buffer, It's value[3].a of
	 *                   MTK_TZCMD_SECMEM_ZALLOC.
	 * [out] value[1].a: return value, 0 means successful, otherwise fail.
	 */
	MTK_TZCMD_SECMEM_FREE		= 0x10001,

	/*
	 * Get secure memory sg-list.
	 *
	 * [in]  value[0].a: The secure handle of this buffer, It's value[3].a of
	 *                   MTK_TZCMD_SECMEM_ZALLOC.
	 * [out] value[1].a: The array of sg items (struct mtk_tee_scatterlist).
	 */
	MTK_TZCMD_SECMEM_RETRIEVE_SG	= 0x10002,
};

struct mtk_restricted_heap_data {
	struct tee_context	*tee_ctx;
	u32			tee_session;

	const enum mtk_secure_mem_type mem_type;

	struct page		*cma_page;
	unsigned long		cma_used_size;
	struct mutex		lock; /* lock for cma_used_size */
};

static int mtk_tee_ctx_match(struct tee_ioctl_version_data *ver, const void *data)
{
	return ver->impl_id == TEE_IMPL_ID_OPTEE;
}

static int mtk_tee_session_init(struct mtk_restricted_heap_data *data)
{
	struct tee_param t_param[TEE_PARAM_NUM] = {0};
	struct tee_ioctl_open_session_arg arg = {0};
	uuid_t ta_mem_uuid;
	int ret;

	data->tee_ctx = tee_client_open_context(NULL, mtk_tee_ctx_match, NULL, NULL);
	if (IS_ERR(data->tee_ctx)) {
		pr_err_once("%s: open context failed, ret=%ld\n", __func__,
			    PTR_ERR(data->tee_ctx));
		return -ENODEV;
	}

	arg.num_params = TEE_PARAM_NUM;
	arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	ret = uuid_parse(TZ_TA_MEM_UUID_MTK, &ta_mem_uuid);
	if (ret)
		goto close_context;
	memcpy(&arg.uuid, &ta_mem_uuid.b, sizeof(ta_mem_uuid));

	ret = tee_client_open_session(data->tee_ctx, &arg, t_param);
	if (ret < 0 || arg.ret) {
		pr_err_once("%s: open session failed, ret=%d:%d\n",
			    __func__, ret, arg.ret);
		ret = -EINVAL;
		goto close_context;
	}
	data->tee_session = arg.session;
	return 0;

close_context:
	tee_client_close_context(data->tee_ctx);
	return ret;
}

static int mtk_tee_service_call(struct tee_context *tee_ctx, u32 session,
				unsigned int command, struct tee_param *params)
{
	struct tee_ioctl_invoke_arg arg = {0};
	int ret;

	arg.num_params = TEE_PARAM_NUM;
	arg.session = session;
	arg.func = command;

	ret = tee_client_invoke_func(tee_ctx, &arg, params);
	if (ret < 0 || arg.ret) {
		pr_err("%s: cmd 0x%x ret %d:%x.\n", __func__, command, ret, arg.ret);
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int mtk_tee_secmem_free(struct restricted_heap *rheap, u64 restricted_addr)
{
	struct mtk_restricted_heap_data *data = rheap->priv_data;
	struct tee_param params[TEE_PARAM_NUM] = {0};

	params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	params[0].u.value.a = restricted_addr;
	params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;

	mtk_tee_service_call(data->tee_ctx, data->tee_session,
			     MTK_TZCMD_SECMEM_FREE, params);
	if (params[1].u.value.a) {
		pr_err("%s, SECMEM_FREE buffer(0x%llx) fail(%lld) from TEE.\n",
		       rheap->name, restricted_addr, params[1].u.value.a);
		return -EINVAL;
	}
	return 0;
}

static int mtk_tee_restrict_memory(struct restricted_heap *rheap, struct restricted_buffer *buf)
{
	struct mtk_restricted_heap_data *data = rheap->priv_data;
	struct tee_param params[TEE_PARAM_NUM] = {0};
	struct mtk_tee_scatterlist *tee_sg_item;
	struct mtk_tee_scatterlist *tee_sg_buf;
	unsigned int sg_num, size, i;
	struct tee_shm *sg_shm;
	struct scatterlist *sg;
	phys_addr_t pa_tee;
	u64 r_addr;
	int ret;

	/* Alloc the secure buffer and get the sg-list number from TEE */
	params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	params[0].u.value.a = buf->size;
	params[0].u.value.b = PAGE_SIZE;
	params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	params[1].u.value.a = data->mem_type;
	params[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	if (rheap->cma && data->mem_type == MTK_SECURE_MEMORY_TYPE_CM_CMA) {
		params[2].u.value.a = rheap->cma_paddr;
		params[2].u.value.b = rheap->cma_size;
	}
	params[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
	ret = mtk_tee_service_call(data->tee_ctx, data->tee_session,
				   MTK_TZCMD_SECMEM_ZALLOC, params);
	if (ret)
		return -ENOMEM;

	sg_num = params[2].u.value.a;
	r_addr = params[3].u.value.a;

	/* If there is only one entry, It means the buffer is continuous, Get the PA directly. */
	if (sg_num == 1) {
		pa_tee = params[2].u.value.b;
		if (!pa_tee)
			goto tee_secmem_free;
		if (sg_alloc_table(&buf->sg_table, 1, GFP_KERNEL))
			goto tee_secmem_free;
		sg_set_page(buf->sg_table.sgl, phys_to_page(pa_tee), buf->size, 0);
		buf->restricted_addr = r_addr;
		return 0;
	}

	/*
	 * If the buffer inside TEE are discontinuous, Use sharemem to retrieve
	 * the detail sg list from TEE.
	 */
	tee_sg_buf = kmalloc_array(sg_num, sizeof(*tee_sg_item), GFP_KERNEL);
	if (!tee_sg_buf) {
		ret = -ENOMEM;
		goto tee_secmem_free;
	}

	size = sg_num * sizeof(*tee_sg_item);
	sg_shm = tee_shm_register_kernel_buf(data->tee_ctx, tee_sg_buf, size);
	if (!sg_shm)
		goto free_tee_sg_buf;

	memset(params, 0, sizeof(params));
	params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	params[0].u.value.a = r_addr;
	params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
	params[1].u.memref.shm = sg_shm;
	params[1].u.memref.size = size;
	ret = mtk_tee_service_call(data->tee_ctx, data->tee_session,
				   MTK_TZCMD_SECMEM_RETRIEVE_SG, params);
	if (ret)
		goto put_shm;

	if (sg_alloc_table(&buf->sg_table, sg_num, GFP_KERNEL))
		goto put_shm;

	for_each_sgtable_sg(&buf->sg_table, sg, i) {
		tee_sg_item = tee_sg_buf + i;
		if (!tee_sg_item->pa)
			goto free_buf_sg;
		sg_set_page(sg, phys_to_page(tee_sg_item->pa),
			    tee_sg_item->length, 0);
	}

	tee_shm_put(sg_shm);
	kfree(tee_sg_buf);
	buf->restricted_addr = r_addr;
	return 0;

free_buf_sg:
	sg_free_table(&buf->sg_table);
put_shm:
	tee_shm_put(sg_shm);
free_tee_sg_buf:
	kfree(tee_sg_buf);
tee_secmem_free:
	mtk_tee_secmem_free(rheap, r_addr);
	return ret;
}

static void mtk_tee_unrestrict_memory(struct restricted_heap *rheap, struct restricted_buffer *buf)
{
	sg_free_table(&buf->sg_table);
	mtk_tee_secmem_free(rheap, buf->restricted_addr);
}

static int
mtk_restricted_memory_allocate(struct restricted_heap *rheap, struct restricted_buffer *buf)
{
	/* The memory allocating is within the TEE. */
	return 0;
}

static void
mtk_restricted_memory_free(struct restricted_heap *rheap, struct restricted_buffer *buf)
{
}

static int mtk_restricted_memory_cma_allocate(struct restricted_heap *rheap,
					      struct restricted_buffer *buf)
{
	struct mtk_restricted_heap_data *data = rheap->priv_data;
	int ret = 0;
	/*
	 * Allocate CMA only when allocating buffer for the first time, and just
	 * increase cma_used_size at the other time, Actually the memory
	 * allocating is within the TEE.
	 */
	mutex_lock(&data->lock);
	if (!data->cma_used_size) {
		data->cma_page = cma_alloc(rheap->cma, rheap->cma_size >> PAGE_SHIFT,
					   get_order(PAGE_SIZE), false);
		if (!data->cma_page) {
			ret = -ENOMEM;
			goto out_unlock;
		}
	} else if (data->cma_used_size + buf->size > rheap->cma_size) {
		ret = -EINVAL;
		goto out_unlock;
	}
	data->cma_used_size += buf->size;

out_unlock:
	mutex_unlock(&data->lock);
	return ret;
}

static void mtk_restricted_memory_cma_free(struct restricted_heap *rheap,
					   struct restricted_buffer *buf)
{
	struct mtk_restricted_heap_data *data = rheap->priv_data;

	mutex_lock(&data->lock);
	data->cma_used_size -= buf->size;
	if (!data->cma_used_size)
		cma_release(rheap->cma, data->cma_page,
			    rheap->cma_size >> PAGE_SHIFT);
	mutex_unlock(&data->lock);
}

static int mtk_restricted_heap_init(struct restricted_heap *rheap)
{
	struct mtk_restricted_heap_data *data = rheap->priv_data;

	if (!data->tee_ctx)
		return mtk_tee_session_init(data);
	return 0;
}

static const struct restricted_heap_ops mtk_restricted_heap_ops = {
	.heap_init		= mtk_restricted_heap_init,
	.alloc			= mtk_restricted_memory_allocate,
	.free			= mtk_restricted_memory_free,
	.restrict_buf		= mtk_tee_restrict_memory,
	.unrestrict_buf		= mtk_tee_unrestrict_memory,
};

static struct mtk_restricted_heap_data mtk_restricted_heap_data = {
	.mem_type		= MTK_SECURE_MEMORY_TYPE_CM_TZ,
};

static const struct restricted_heap_ops mtk_restricted_heap_ops_cma = {
	.heap_init		= mtk_restricted_heap_init,
	.alloc			= mtk_restricted_memory_cma_allocate,
	.free			= mtk_restricted_memory_cma_free,
	.restrict_buf		= mtk_tee_restrict_memory,
	.unrestrict_buf		= mtk_tee_unrestrict_memory,
};

static struct mtk_restricted_heap_data mtk_restricted_heap_data_cma = {
	.mem_type		= MTK_SECURE_MEMORY_TYPE_CM_CMA,
};

static struct restricted_heap mtk_restricted_heaps[] = {
	{
		.name		= "restricted_mtk_cm",
		.ops		= &mtk_restricted_heap_ops,
		.priv_data	= &mtk_restricted_heap_data,
	},
	{
		.name		= "restricted_mtk_cma",
		.ops		= &mtk_restricted_heap_ops_cma,
		.priv_data	= &mtk_restricted_heap_data_cma,
	},
};

static int __init mtk_restricted_cma_init(struct reserved_mem *rmem)
{
	struct restricted_heap *rheap = mtk_restricted_heaps, *rheap_cma = NULL;
	struct mtk_restricted_heap_data *data;
	struct cma *cma;
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(mtk_restricted_heaps); i++, rheap++) {
		data = rheap->priv_data;
		if (data->mem_type == MTK_SECURE_MEMORY_TYPE_CM_CMA) {
			rheap_cma = rheap;
			break;
		}
	}
	if (!rheap_cma)
		return -EINVAL;

	ret = cma_init_reserved_mem(rmem->base, rmem->size, 0, rmem->name,
				    &cma);
	if (ret) {
		pr_err("%s: %s set up CMA fail. ret %d.\n", __func__, rmem->name, ret);
		return ret;
	}

	rheap_cma->cma = cma;
	rheap_cma->cma_paddr = rmem->base;
	rheap_cma->cma_size = rmem->size;
	return 0;
}

RESERVEDMEM_OF_DECLARE(restricted_cma, "mediatek,dynamic-restricted-region",
		       mtk_restricted_cma_init);

static int mtk_restricted_heap_initialize(void)
{
	struct restricted_heap *rheap = mtk_restricted_heaps;
	struct mtk_restricted_heap_data *data;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mtk_restricted_heaps); i++, rheap++) {
		data = rheap->priv_data;
		if (data->mem_type == MTK_SECURE_MEMORY_TYPE_CM_CMA && !rheap->cma)
			continue;
		if (!restricted_heap_add(rheap))
			mutex_init(&data->lock);
	}
	return 0;
}
module_init(mtk_restricted_heap_initialize);
MODULE_DESCRIPTION("MediaTek Restricted Heap Driver");
MODULE_LICENSE("GPL");
