// SPDX-License-Identifier: GPL-2.0
/*
 * DMABUF ffa heap exporter
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2019, 2020 Linaro Ltd.
 *
 * Portions based off of Andrew Davis' SRAM heap:
 * Copyright (C) 2019 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 */

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <uapi/linux/vm_sockets.h>

#include "virtio_msg_internal.h"

MODULE_IMPORT_NS("DMA_BUF");
MODULE_IMPORT_NS("DMA_BUF_HEAP");

struct ffa_heap_buffer {
	struct dma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	struct sg_table sg_table;
	int vmap_cnt;
	void *vaddr;
	dma_addr_t dma_handle;
};

struct dma_heap_attachment {
	struct device *dev;
	struct sg_table table;
	struct list_head list;
	bool mapped;
};

/* FF-A specific implementation of struct vsock_shmem_desc */
struct vsock_shmem_desc_payload_ffa {
	__u64 dma_handle;
	__u64 size;
};

static int dup_sg_table(struct sg_table *from, struct sg_table *to)
{
	struct scatterlist *sg, *new_sg;
	int ret, i;

	ret = sg_alloc_table(to, from->orig_nents, GFP_KERNEL);
	if (ret)
		return ret;

	new_sg = to->sgl;
	for_each_sgtable_sg(from, sg, i) {
		sg_set_page(new_sg, sg_page(sg), sg->length, sg->offset);
		new_sg = sg_next(new_sg);
	}

	return 0;
}

static int ffa_heap_attach(struct dma_buf *dmabuf,
			      struct dma_buf_attachment *attachment)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;
	int ret;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	ret = dup_sg_table(&buffer->sg_table, &a->table);
	if (ret) {
		kfree(a);
		return ret;
	}

	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);
	a->mapped = false;

	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void ffa_heap_detach(struct dma_buf *dmabuf,
			       struct dma_buf_attachment *attachment)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a = attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(&a->table);
	kfree(a);
}

static struct sg_table *ffa_heap_map_dma_buf(struct dma_buf_attachment *attachment,
						enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	struct sg_table *table = &a->table;
	int ret;

	ret = dma_map_sgtable(attachment->dev, table, direction, 0);
	if (ret)
		return ERR_PTR(ret);

	a->mapped = true;
	return table;
}

static void ffa_heap_unmap_dma_buf(struct dma_buf_attachment *attachment,
				      struct sg_table *table,
				      enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;

	a->mapped = false;
	dma_unmap_sgtable(attachment->dev, table, direction, 0);
}

static int ffa_heap_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
						enum dma_data_direction direction)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(a, &buffer->attachments, list) {
		if (!a->mapped)
			continue;
		dma_sync_sgtable_for_cpu(a->dev, &a->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int ffa_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					      enum dma_data_direction direction)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		flush_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(a, &buffer->attachments, list) {
		if (!a->mapped)
			continue;
		dma_sync_sgtable_for_device(a->dev, &a->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int ffa_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct sg_table *table = &buffer->sg_table;
	unsigned long addr = vma->vm_start;
	struct sg_page_iter piter;
	int ret;

	for_each_sgtable_page(table, &piter, vma->vm_pgoff) {
		struct page *page = sg_page_iter_page(&piter);

		ret = remap_pfn_range(vma, addr, page_to_pfn(page), PAGE_SIZE,
				      vma->vm_page_prot);
		if (ret)
			return ret;
		addr += PAGE_SIZE;
		if (addr >= vma->vm_end)
			return 0;
	}
	return 0;
}

static void *ffa_heap_do_vmap(struct ffa_heap_buffer *buffer)
{
	struct sg_table *table = &buffer->sg_table;
	int npages = PAGE_ALIGN(buffer->len) / PAGE_SIZE;
	struct page **pages = vmalloc(sizeof(struct page *) * npages);
	struct page **tmp = pages;
	struct sg_page_iter piter;
	void *vaddr;

	if (!pages)
		return ERR_PTR(-ENOMEM);

	for_each_sgtable_page(table, &piter, 0) {
		WARN_ON(tmp - pages >= npages);
		*tmp++ = sg_page_iter_page(&piter);
	}

	vaddr = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
	vfree(pages);

	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

static int ffa_heap_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	void *vaddr;
	int ret = 0;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt) {
		buffer->vmap_cnt++;
		iosys_map_set_vaddr(map, buffer->vaddr);
		goto out;
	}

	vaddr = ffa_heap_do_vmap(buffer);
	if (IS_ERR(vaddr)) {
		ret = PTR_ERR(vaddr);
		goto out;
	}

	buffer->vaddr = vaddr;
	buffer->vmap_cnt++;
	iosys_map_set_vaddr(map, buffer->vaddr);
out:
	mutex_unlock(&buffer->lock);

	return ret;
}

static void ffa_heap_vunmap(struct dma_buf *dmabuf, struct iosys_map *map)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!--buffer->vmap_cnt) {
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
	iosys_map_clear(map);
}

static void ffa_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct sg_table *table = &buffer->sg_table;
	struct page *page = sg_page(table->sgl);

	__free_pages(page, compound_order(page));
	sg_free_table(table);
	kfree(buffer);
}

static void ffa_heap_dma_buf_unshmem(struct dma_buf *dmabuf)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct device *dev = dma_heap_get_drvdata(buffer->heap);
	struct sg_table *table = &buffer->sg_table;
	dma_addr_t dma = buffer->dma_handle;

	if (WARN_ON(!sg_is_last(table->sgl)))
		return;

	/* Unshare all shared memory areas */
	vmsg_ffa_bus_area_unshare(dev, &dma, buffer->len / PAGE_SIZE);
}

static int ffa_heap_dma_buf_shmem(struct dma_buf *dmabuf, void *data)
{
	struct ffa_heap_buffer *buffer = dmabuf->priv;
	struct device *dev = dma_heap_get_drvdata(buffer->heap);
	struct sg_table *table = &buffer->sg_table;
	struct page *page = sg_page(table->sgl);
	struct vsock_shmem_desc *desc = data;
	struct vsock_shmem_desc_payload_ffa *payload =
		(struct vsock_shmem_desc_payload_ffa *)desc->payload;
	dma_addr_t dma_handle;
	int ret;

	static_assert(sizeof(*payload) <= VSOCK_SHMEM_PAYLOAD_SIZE_MAX);

	if (WARN_ON(!sg_is_last(table->sgl)))
		return -EINVAL;

	dma_handle = page_to_phys(page);
	ret = vmsg_ffa_bus_area_share(dev, page_to_virt(page),
				      buffer->len / PAGE_SIZE, &dma_handle);
	if (ret)
		return ret;

	desc->type = VSOCK_SHMEM_TYPE_FFA;
	desc->len = sizeof(*desc) + sizeof(*payload);
	payload->dma_handle = dma_handle;
	payload->size = buffer->len;
	buffer->dma_handle = dma_handle;

	return 0;
}

static const struct dma_buf_ops ffa_heap_buf_ops = {
	.attach = ffa_heap_attach,
	.detach = ffa_heap_detach,
	.map_dma_buf = ffa_heap_map_dma_buf,
	.unmap_dma_buf = ffa_heap_unmap_dma_buf,
	.begin_cpu_access = ffa_heap_dma_buf_begin_cpu_access,
	.end_cpu_access = ffa_heap_dma_buf_end_cpu_access,
	.mmap = ffa_heap_mmap,
	.vmap = ffa_heap_vmap,
	.vunmap = ffa_heap_vunmap,
	.release = ffa_heap_dma_buf_release,
	.shmem = ffa_heap_dma_buf_shmem,
	.unshmem = ffa_heap_dma_buf_unshmem,
};

static struct dma_buf *ffa_heap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    u32 fd_flags,
					    u64 heap_flags)
{
	struct ffa_heap_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	struct sg_table *table;
	struct scatterlist *sg;
	struct page *page;
	int ret = -ENOMEM;

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = len;

	page = alloc_pages(0, get_order(len));
	if (!page)
		goto free_buffer;

	table = &buffer->sg_table;
	if (sg_alloc_table(table, 1, GFP_KERNEL))
		goto free_page;

	sg = table->sgl;
	sg_set_page(sg, page, page_size(page), 0);

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &ffa_heap_buf_ops;
	exp_info.size = buffer->len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_sg_table;
	}

	return dmabuf;

free_sg_table:
	sg_free_table(table);
free_page:
	__free_pages(page, compound_order(page));
free_buffer:
	kfree(buffer);

	return ERR_PTR(ret);
}

static const struct dma_heap_ops ffa_heap_ops = {
	.allocate = ffa_heap_allocate,
};

void virtio_msg_ffa_heap_create(struct device *dev)
{
	struct dma_heap_export_info exp_info;

	exp_info.name = "ffa";
	exp_info.ops = &ffa_heap_ops;
	exp_info.priv = dev;

	dma_heap_add(&exp_info);
}
