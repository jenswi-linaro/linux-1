// SPDX-License-Identifier: GPL-2.0
/*
 * DMABUF restricted heap exporter for MediaTek
 *
 * Copyright (C) 2024 MediaTek Inc.
 */
#define pr_fmt(fmt)     "rheap_mtk: " fmt

#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/module.h>
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
};

struct mtk_restricted_heap_data {
	struct tee_context	*tee_ctx;
	u32			tee_session;

	const enum mtk_secure_mem_type mem_type;

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

static int mtk_restricted_heap_init(struct restricted_heap *rheap)
{
	struct mtk_restricted_heap_data *data = rheap->priv_data;

	if (!data->tee_ctx)
		return mtk_tee_session_init(data);
	return 0;
}

static const struct restricted_heap_ops mtk_restricted_heap_ops = {
	.heap_init		= mtk_restricted_heap_init,
};

static struct mtk_restricted_heap_data mtk_restricted_heap_data = {
	.mem_type		= MTK_SECURE_MEMORY_TYPE_CM_TZ,
};

static struct restricted_heap mtk_restricted_heaps[] = {
	{
		.name		= "restricted_mtk_cm",
		.ops		= &mtk_restricted_heap_ops,
		.priv_data	= &mtk_restricted_heap_data,
	},
};

static int mtk_restricted_heap_initialize(void)
{
	struct restricted_heap *rheap = mtk_restricted_heaps;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mtk_restricted_heaps); i++, rheap++)
		restricted_heap_add(rheap);
	return 0;
}
module_init(mtk_restricted_heap_initialize);
MODULE_DESCRIPTION("MediaTek Restricted Heap Driver");
MODULE_LICENSE("GPL");
