// SPDX-License-Identifier: GPL-2.0
/*
 * DMABUF secure heap exporter
 *
 * Copyright 2021 NXP.
 * Copyright 2024 Linaro Limited.
 */

#define pr_fmt(fmt)     "rheap_linaro: " fmt

#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include "restricted_heap.h"

#define MAX_HEAP_COUNT	2
#define HEAP_NAME_LEN	32

struct resmem_restricted {
	phys_addr_t base;
	phys_addr_t size;

	char name[HEAP_NAME_LEN];

	bool no_map;
};

static struct resmem_restricted restricted_data[MAX_HEAP_COUNT] = {0};
static unsigned int restricted_data_count;

static int linaro_restricted_memory_allocate(struct restricted_heap *heap,
					     struct restricted_buffer *buf)
{
	struct gen_pool *pool = heap->priv_data;
	unsigned long pa;
	int ret;

	buf->size = ALIGN(buf->size, PAGE_SIZE);
	pa = gen_pool_alloc(pool, buf->size);
	if (!pa)
		return -ENOMEM;

	ret = sg_alloc_table(&buf->sg_table, 1, GFP_KERNEL);
	if (ret) {
		gen_pool_free(pool, pa, buf->size);
		return ret;
	}

	sg_set_page(buf->sg_table.sgl, phys_to_page(pa), buf->size, 0);

	return 0;
}

static void linaro_restricted_memory_free(struct restricted_heap *heap,
					  struct restricted_buffer *buf)
{
	struct gen_pool *pool = heap->priv_data;
	struct scatterlist *sg;
	unsigned int i;

	for_each_sg(buf->sg_table.sgl, sg, buf->sg_table.nents, i)
		gen_pool_free(pool, page_to_phys(sg_page(sg)), sg->length);
	sg_free_table(&buf->sg_table);
}

static const struct restricted_heap_ops linaro_restricted_heap_ops = {
	.alloc = linaro_restricted_memory_allocate,
	.free = linaro_restricted_memory_free,
};

static int add_heap(struct resmem_restricted *mem)
{
	struct restricted_heap *heap;
	struct gen_pool *pool;
	int ret;

	if (mem->base == 0 || mem->size == 0) {
		pr_err("restricted_data base or size is not correct\n");
		return -EINVAL;
	}

	heap = kzalloc(sizeof(*heap), GFP_KERNEL);
	if (!heap)
		return -ENOMEM;

	pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!pool) {
		ret = -ENOMEM;
		goto err_free_heap;
	}

	ret = gen_pool_add(pool, mem->base, mem->size, -1);
	if (ret)
		goto err_free_pool;

	heap->no_map = mem->no_map;
	heap->priv_data = pool;
	heap->name = mem->name;
	heap->ops = &linaro_restricted_heap_ops;

	ret = restricted_heap_add(heap);
	if (ret)
		goto err_free_pool;

	return 0;

err_free_pool:
	gen_pool_destroy(pool);
err_free_heap:
	kfree(heap);

	return ret;
}

static int __init rmem_restricted_heap_setup(struct reserved_mem *rmem)
{
	size_t len = HEAP_NAME_LEN;
	const char *s;
	bool no_map;

	if (WARN_ONCE(restricted_data_count >= MAX_HEAP_COUNT,
		      "Cannot handle more than %u restricted heaps\n",
		      MAX_HEAP_COUNT))
		return -EINVAL;

	no_map = of_get_flat_dt_prop(rmem->fdt_node, "no-map", NULL);
	s = strchr(rmem->name, '@');
	if (s)
		len = umin(s - rmem->name + 1, len);

	restricted_data[restricted_data_count].base = rmem->base;
	restricted_data[restricted_data_count].size = rmem->size;
	restricted_data[restricted_data_count].no_map = no_map;
	strscpy(restricted_data[restricted_data_count].name, rmem->name, len);

	restricted_data_count++;
	return 0;
}

RESERVEDMEM_OF_DECLARE(linaro_restricted_heap, "linaro,restricted-heap",
		       rmem_restricted_heap_setup);

static int linaro_restricted_heap_init(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < restricted_data_count; i++) {
		ret = add_heap(&restricted_data[i]);
		if (ret)
			return ret;
	}
	return 0;
}

module_init(linaro_restricted_heap_init);
MODULE_DESCRIPTION("Linaro Restricted Heap Driver");
MODULE_LICENSE("GPL");
