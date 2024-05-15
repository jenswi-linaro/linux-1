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
};

struct restricted_heap {
	const char		*name;
};

int restricted_heap_add(struct restricted_heap *rheap);

#endif
