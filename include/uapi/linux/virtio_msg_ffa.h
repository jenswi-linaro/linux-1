/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Virtio message FF-A (Arm Firmware Framework) bus header.
 *
 * Copyright (C) 2025 Google LLC and Linaro.
 * Viresh Kumar <viresh.kumar@linaro.org>
 */

#ifndef _LINUX_VIRTIO_MSG_FFA_H
#define _LINUX_VIRTIO_MSG_FFA_H

#include <linux/types.h>

/* Message types */
#define VIRTIO_MSG_FFA_BUS_VERSION			0x80
#define VIRTIO_MSG_FFA_BUS_AREA_SHARE			0x81
#define VIRTIO_MSG_FFA_BUS_AREA_UNSHARE			0x82
#define VIRTIO_MSG_FFA_BUS_RESET			0x83
#define VIRTIO_MSG_FFA_BUS_EVENT_POLL			0x84
#define VIRTIO_MSG_FFA_BUS_EVENT_CONFIGURE		0x85
#define VIRTIO_MSG_FFA_BUS_FIFO_CONFIGURE		0x86
#define VIRTIO_MSG_FFA_BUS_ERROR			0x87
#define VIRTIO_MSG_FFA_BUS_AREA_RELEASE			0xC0

#define VIRTIO_MSG_FEATURES				0
#define VIRTIO_MSG_FFA_BUS_VERSION_CREATE(major, minor)	\
	((((major) & 0xFFFF) << 16) | ((minor) & 0xFFFF))
#define VIRTIO_MSG_FFA_BUS_VERSION_1_0			VIRTIO_MSG_FFA_BUS_VERSION_CREATE(1,0)
#define VIRTIO_MSG_FFA_BUS_MSG_SIZE			VIRTIO_MSG_MIN_SIZE
#define VIRTIO_MSG_FFA_BUS_MSG_MAX_SIZE			104

#define VIRTIO_MSG_FFA_FEATURE_DIRECT_MSG_RX_SUPP	(1 << 0)
#define VIRTIO_MSG_FFA_FEATURE_DIRECT_MSG_TX_SUPP	(1 << 1)
#define VIRTIO_MSG_FFA_FEATURE_INDIRECT_MSG_RX_SUPP	(1 << 2)
#define VIRTIO_MSG_FFA_FEATURE_INDIRECT_MSG_TX_SUPP	(1 << 3)
#define VIRTIO_MSG_FFA_FEATURE_NOTIFICATION_RX_SUPP	(1 << 4)
#define VIRTIO_MSG_FFA_FEATURE_NOTIFICATION_TX_SUPP	(1 << 5)
#define VIRTIO_MSG_FFA_FEATURE_FIFO_TX_RX_SUPP		(1 << 6)

#define VIRTIO_MSG_FFA_FEATURE_DIRECT_MSG_SUPP		\
	(VIRTIO_MSG_FFA_FEATURE_DIRECT_MSG_RX_SUPP |	\
	 VIRTIO_MSG_FFA_FEATURE_DIRECT_MSG_TX_SUPP)

#define VIRTIO_MSG_FFA_FEATURE_INDIRECT_MSG_SUPP	\
	(VIRTIO_MSG_FFA_FEATURE_INDIRECT_MSG_RX_SUPP |	\
	 VIRTIO_MSG_FFA_FEATURE_INDIRECT_MSG_TX_SUPP)

#define VIRTIO_MSG_FFA_FEATURE_BOTH_SUPP		\
	(VIRTIO_MSG_FFA_FEATURE_DIRECT_MSG_SUPP |	\
	 VIRTIO_MSG_FFA_FEATURE_INDIRECT_MSG_SUPP)

#define VIRTIO_MSG_FFA_AREA_ID_MAX			0xFFFF
#define VIRTIO_MSG_FFA_AREA_ID_OFFSET			48
#define VIRTIO_MSG_FFA_OFFSET_MASK			\
	((ULL(1) << VIRTIO_MSG_FFA_AREA_ID_OFFSET) - 1)

#define VIRTIO_MSG_FFA_EVENT_DELIVERY_TYPE_POLL		0
#define VIRTIO_MSG_FFA_EVENT_DELIVERY_TYPE_NOTIF	1
#define VIRTIO_MSG_FFA_EVENT_DELIVERY_TYPE_INDIRECT	2
#define VIRTIO_MSG_FFA_EVENT_DELIVERY_TYPE_FIFO		3

#define VIRTIO_MSG_FFA_RESULT_OK			(0)
#define VIRTIO_MSG_FFA_RESULT_ERROR			(1 << 0)
#define VIRTIO_MSG_FFA_RESULT_BUSY			(1 << 1)

/* Message payload format */

struct bus_ffa_version {
	__le32 bus_version;
	__le32 transport_revision;
} __attribute__((packed));

struct bus_ffa_version_resp {
	__le32 bus_version;
	__le32 transport_revision;
	__le32 transport_features;
	__le32 bus_features;
	__le16 area_num;
} __attribute__((packed));

struct bus_area_share {
	__le16 area_id;
	__le64 mem_handle;
	__le64 tag;
	__le32 count;
	__le32 attr;
} __attribute__((packed));

struct bus_area_share_resp {
	__le16 area_id;
	__le16 result;
} __attribute__((packed));

struct bus_area_unshare {
	__le16 area_id;
} __attribute__((packed));

struct bus_area_unshare_resp {
	__le16 area_id;
	__le16 result;
} __attribute__((packed));

struct bus_reset_resp {
	__le16 result;
} __attribute__((packed));

struct bus_event_configure {
	__u8 type;
	__u8 reserved;
	__le16 notify_id;
} __attribute__((packed));

struct bus_event_configure_resp {
	__le16 result;
} __attribute__((packed));

struct bus_fifo_configure {
	__le64 mem_handle;
	__le16 page_count;
	__le16 notify_id;
} __attribute__((packed));

struct bus_fifo_configure_resp {
	__le16 result;
	__le16 notify_id;
} __attribute__((packed));

struct bus_area_release {
	__le16 area_id;
} __attribute__((packed));

#endif /* _LINUX_VIRTIO_MSG_FFA_H */
