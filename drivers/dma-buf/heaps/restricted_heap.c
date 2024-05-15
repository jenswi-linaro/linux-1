// SPDX-License-Identifier: GPL-2.0
/*
 * DMABUF restricted heap exporter
 *
 * Copyright (C) 2024 MediaTek Inc.
 */

#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/slab.h>

#include "restricted_heap.h"

static int
restricted_heap_memory_allocate(struct restricted_heap *rheap, struct restricted_buffer *buf)
{
	const struct restricted_heap_ops *ops = rheap->ops;
	int ret;

	ret = ops->alloc(rheap, buf);
	if (ret)
		return ret;

	if (ops->restrict_buf) {
		ret = ops->restrict_buf(rheap, buf);
		if (ret)
			goto buf_free;
	}
	return 0;

buf_free:
	ops->free(rheap, buf);
	return ret;
}

static void
restricted_heap_memory_free(struct restricted_heap *rheap, struct restricted_buffer *buf)
{
	const struct restricted_heap_ops *ops = rheap->ops;

	if (ops->unrestrict_buf)
		ops->unrestrict_buf(rheap, buf);

	ops->free(rheap, buf);
}

static struct dma_buf *
restricted_heap_allocate(struct dma_heap *heap, unsigned long size,
			 unsigned long fd_flags, unsigned long heap_flags)
{
	struct restricted_heap *rheap = dma_heap_get_drvdata(heap);
	struct restricted_buffer *restricted_buf;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	int ret;

	restricted_buf = kzalloc(sizeof(*restricted_buf), GFP_KERNEL);
	if (!restricted_buf)
		return ERR_PTR(-ENOMEM);

	restricted_buf->size = ALIGN(size, PAGE_SIZE);
	restricted_buf->heap = heap;

	ret = restricted_heap_memory_allocate(rheap, restricted_buf);
	if (ret)
		goto err_free_buf;
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.size = restricted_buf->size;
	exp_info.flags = fd_flags;
	exp_info.priv = restricted_buf;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto err_free_rstrd_mem;
	}

	return dmabuf;

err_free_rstrd_mem:
	restricted_heap_memory_free(rheap, restricted_buf);
err_free_buf:
	kfree(restricted_buf);
	return ERR_PTR(ret);
}

static const struct dma_heap_ops rheap_ops = {
	.allocate = restricted_heap_allocate,
};

int restricted_heap_add(struct restricted_heap *rheap)
{
	struct dma_heap_export_info exp_info;
	struct dma_heap *heap;

	exp_info.name = rheap->name;
	exp_info.ops = &rheap_ops;
	exp_info.priv = (void *)rheap;

	heap = dma_heap_add(&exp_info);
	if (IS_ERR(heap))
		return PTR_ERR(heap);
	return 0;
}
EXPORT_SYMBOL_GPL(restricted_heap_add);
