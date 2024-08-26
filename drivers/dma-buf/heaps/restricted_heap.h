/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Restricted heap Header.
 *
 * Copyright (C) 2024 MediaTek, Inc.
 */

#ifndef _DMABUF_RESTRICTED_HEAP_H_
#define _DMABUF_RESTRICTED_HEAP_H_

struct restricted_buffer {
	struct dma_heap		*heap;
	size_t			size;

	struct sg_table		sg_table;

	/* A reference to a buffer in the trusted or secure world. */
	u64			restricted_addr;
};

struct restricted_heap {
	const char		*name;

	const struct restricted_heap_ops *ops;

	struct cma		*cma;
	unsigned long		cma_paddr;
	unsigned long		cma_size;

	bool			no_map;

	void			*priv_data;
};

struct restricted_heap_ops {
	int	(*heap_init)(struct restricted_heap *rheap);

	int	(*alloc)(struct restricted_heap *rheap, struct restricted_buffer *buf);
	void	(*free)(struct restricted_heap *rheap, struct restricted_buffer *buf);

	int	(*restrict_buf)(struct restricted_heap *rheap, struct restricted_buffer *buf);
	void	(*unrestrict_buf)(struct restricted_heap *rheap, struct restricted_buffer *buf);
};

int restricted_heap_add(struct restricted_heap *rheap);

#endif
