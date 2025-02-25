/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/device.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/dma-buf.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include "tee_private.h"

static void tee_shm_release(struct tee_shm *shm)
{
	struct tee_device *teedev = shm->teedev;
	struct tee_shm_pool_mgr *poolm;

	mutex_lock(&teedev->mutex);
	list_del(&shm->list_node);
	mutex_unlock(&teedev->mutex);

	if (shm->flags & TEE_SHM_DMA_BUF)
		poolm = &teedev->pool->dma_buf_mgr;
	else
		poolm = &teedev->pool->private_mgr;

	poolm->ops->free(poolm, shm);
	kfree(shm);

	tee_device_put(teedev);
}

static struct sg_table *tee_shm_op_map_dma_buf(struct dma_buf_attachment
			*attach, enum dma_data_direction dir)
{
	return NULL;
}

static void tee_shm_op_unmap_dma_buf(struct dma_buf_attachment *attach,
			struct sg_table *table, enum dma_data_direction dir)
{
}

static void tee_shm_op_release(struct dma_buf *dmabuf)
{
	struct tee_shm *shm = dmabuf->priv;

	tee_shm_release(shm);
}

static void *tee_shm_op_kmap_atomic(struct dma_buf *dmabuf,
			unsigned long pgnum)
{
	return NULL;
}

static void *tee_shm_op_kmap(struct dma_buf *dmabuf, unsigned long pgnum)
{
	return NULL;
}

static int tee_shm_op_mmap(struct dma_buf *dmabuf,
			struct vm_area_struct *vma)
{
	struct tee_shm *shm = dmabuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	return remap_pfn_range(vma, vma->vm_start, shm->paddr >> PAGE_SHIFT,
			       size, vma->vm_page_prot);
}

static struct dma_buf_ops tee_shm_dma_buf_ops = {
	.map_dma_buf = tee_shm_op_map_dma_buf,
	.unmap_dma_buf = tee_shm_op_unmap_dma_buf,
	.release = tee_shm_op_release,
	.kmap_atomic = tee_shm_op_kmap_atomic,
	.kmap = tee_shm_op_kmap,
	.mmap = tee_shm_op_mmap,
};

struct tee_shm *tee_shm_alloc(struct tee_device *teedev, size_t size,
			u32 flags)
{
	struct tee_shm_pool_mgr *poolm = NULL;
	struct tee_shm *shm;
	void *ret;
	int rc;

	if (!(flags & TEE_SHM_MAPPED)) {
		dev_err(teedev->dev.parent,
			"only mapped allocations supported\n");
		return ERR_PTR(-EINVAL);
	}

	if ((flags & ~(TEE_SHM_MAPPED|TEE_SHM_DMA_BUF))) {
		dev_err(teedev->dev.parent, "invalid shm flags 0x%x", flags);
		return ERR_PTR(-EINVAL);
	}

	if (!tee_device_get(teedev))
		return ERR_PTR(-EINVAL);

	if (!teedev->pool) {
		/* teedev has been detached from driver */
		ret = ERR_PTR(-EINVAL);
		goto err;
	}

	shm = kzalloc(sizeof(struct tee_shm), GFP_KERNEL);
	if (!shm) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	shm->flags = flags;
	shm->teedev = teedev;
	if (flags & TEE_SHM_DMA_BUF)
		poolm = &teedev->pool->dma_buf_mgr;
	else
		poolm = &teedev->pool->private_mgr;

	rc = poolm->ops->alloc(poolm, shm, size);
	if (rc) {
		ret = ERR_PTR(rc);
		goto err;
	}

	mutex_lock(&teedev->mutex);
	list_add_tail(&shm->list_node, &teedev->list_shm);
	mutex_unlock(&teedev->mutex);

	if (flags & TEE_SHM_DMA_BUF) {
		DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

		exp_info.ops = &tee_shm_dma_buf_ops;
		exp_info.size = shm->size;
		exp_info.flags = O_RDWR;
		exp_info.priv = shm;

		shm->dmabuf = dma_buf_export(&exp_info);
		if (IS_ERR(shm->dmabuf)) {
			ret = ERR_CAST(shm->dmabuf);
			goto err;
		}
	}

	return shm;
err:
	if (poolm && shm && shm->kaddr)
		poolm->ops->free(poolm, shm);
	kfree(shm);
	tee_device_put(teedev);
	return ret;
}
EXPORT_SYMBOL_GPL(tee_shm_alloc);

int tee_shm_get_fd(struct tee_shm *shm)
{
	u32 req_flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;
	int fd;

	if ((shm->flags & req_flags) != req_flags)
		return -EINVAL;

	fd = dma_buf_fd(shm->dmabuf, O_CLOEXEC);
	if (fd >= 0)
		get_dma_buf(shm->dmabuf);
	return fd;
}
EXPORT_SYMBOL_GPL(tee_shm_get_fd);

int tee_shm_put_fd(int fd)
{
	return __close_fd(current->files, fd);
}
EXPORT_SYMBOL_GPL(tee_shm_put_fd);

void tee_shm_free(struct tee_shm *shm)
{

	/*
	 * dma_buf_put() decreases the dmabuf reference counter and will
	 * call tee_shm_release() when the last reference is gone.
	 *
	 * In the case of driver private memory we call tee_shm_release
	 * directly instead as it doesn't have a reference counter.
	 */
	if (shm->flags & TEE_SHM_DMA_BUF)
		dma_buf_put(shm->dmabuf);
	else
		tee_shm_release(shm);
}
EXPORT_SYMBOL_GPL(tee_shm_free);

static bool cmp_key_va(struct tee_shm *shm, uintptr_t va)
{
	uintptr_t shm_va = (uintptr_t)shm->kaddr;

	return (va >= shm_va) && (va < (shm_va + shm->size));
}

static bool cmp_key_pa(struct tee_shm *shm, uintptr_t pa)
{
	return (pa >= shm->paddr) && (pa < (shm->paddr + shm->size));
}

static struct tee_shm *tee_shm_find_by_key(struct tee_device *teedev, u32 flags,
			bool (*cmp)(struct tee_shm *shm, uintptr_t key),
			uintptr_t key)
{
	struct tee_shm *ret = NULL;
	struct tee_shm *shm;

	mutex_lock(&teedev->mutex);
	list_for_each_entry(shm, &teedev->list_shm, list_node) {
		if (cmp(shm, key)) {
			ret = shm;
			break;
		}
	}
	mutex_unlock(&teedev->mutex);

	return ret;
}

struct tee_shm *tee_shm_find_by_va(struct tee_device *teedev, u32 flags,
			void *va)
{
	return tee_shm_find_by_key(teedev, flags, cmp_key_va, (uintptr_t)va);
}
EXPORT_SYMBOL_GPL(tee_shm_find_by_va);

struct tee_shm *tee_shm_find_by_pa(struct tee_device *teedev, u32 flags,
			phys_addr_t pa)
{
	return tee_shm_find_by_key(teedev, flags, cmp_key_pa, pa);
}
EXPORT_SYMBOL_GPL(tee_shm_find_by_pa);

int tee_shm_va2pa(struct tee_shm *shm, void *va, phys_addr_t *pa)
{
	/* Check that we're in the range of the shm */
	if ((char *)va < (char *)shm->kaddr)
		return -EINVAL;
	if ((char *)va >= ((char *)shm->kaddr + shm->size))
		return -EINVAL;

	return tee_shm_get_pa(
			shm, (unsigned long)va - (unsigned long)shm->kaddr, pa);
}
EXPORT_SYMBOL_GPL(tee_shm_va2pa);

int tee_shm_pa2va(struct tee_shm *shm, phys_addr_t pa, void **va)
{
	/* Check that we're in the range of the shm */
	if (pa < shm->paddr)
		return -EINVAL;
	if (pa >= (shm->paddr + shm->size))
		return -EINVAL;

	if (va) {
		void *v = tee_shm_get_va(shm, pa - shm->paddr);

		if (IS_ERR(v))
			return PTR_ERR(v);
		*va = v;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(tee_shm_pa2va);

void *tee_shm_get_va(struct tee_shm *shm, size_t offs)
{
	if (offs >= shm->size)
		return ERR_PTR(-EINVAL);
	return (char *)shm->kaddr + offs;
}
EXPORT_SYMBOL_GPL(tee_shm_get_va);

int tee_shm_get_pa(struct tee_shm *shm, size_t offs, phys_addr_t *pa)
{
	if (offs >= shm->size)
		return -EINVAL;
	if (pa)
		*pa = shm->paddr + offs;
	return 0;
}
EXPORT_SYMBOL_GPL(tee_shm_get_pa);

static bool is_shm_dma_buf(struct dma_buf *dmabuf)
{
	return dmabuf->ops == &tee_shm_dma_buf_ops;
}

struct tee_shm *tee_shm_get_from_fd(int fd)
{
	struct dma_buf *dmabuf = dma_buf_get(fd);

	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	if (!is_shm_dma_buf(dmabuf)) {
		dma_buf_put(dmabuf);
		return ERR_PTR(-EINVAL);
	}
	return dmabuf->priv;
}
EXPORT_SYMBOL_GPL(tee_shm_get_from_fd);

void tee_shm_put(struct tee_shm *shm)
{
	if (shm->flags & TEE_SHM_DMA_BUF)
		dma_buf_put(shm->dmabuf);
}
EXPORT_SYMBOL_GPL(tee_shm_put);
