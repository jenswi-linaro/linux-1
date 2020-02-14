/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019, 2020 Arm Ltd.
 */

#ifndef __LINUX_ARM_SPCI_H
#define __LINUX_ARM_SPCI_H

#define SPCI_ERROR_32                 0x84000060
#define SPCI_SUCCESS_32               0x84000061

#define SPCI_RX_RELEASE_32            0x84000065
#define SPCI_RXTX_MAP_32              0x84000066

#define SPCI_PARTITION_INFO_GET_32    0x84000068
#define SPCI_ID_GET_32                0x84000069

#define SPCI_MSG_SEND_32              0x8400006E
#define SPCI_MSG_SEND_DIRECT_REQ_32   0x8400006F
#define SPCI_MSG_SEND_DIRECT_RESP_32  0x84000070
#define SPCI_MEM_RECLAIM_32           0x84000077

#define SPCI_MEM_SHARE_64             0xC4000073
#define SPCI_MEM_RECLAIM_64           0xC4000077

/* SPCI error codes. */
#define SPCI_SUCCESS            (0)
#define SPCI_NOT_SUPPORTED      (-1)
#define SPCI_INVALID_PARAMETERS (-2)
#define SPCI_NO_MEMORY          (-3)
#define SPCI_BUSY               (-4)
#define SPCI_INTERRUPTED        (-5)
#define SPCI_DENIED             (-6)
#define SPCI_RETRY              (-7)

#define SPCI_BASE_GRANULE_SIZE 4096

struct page;

enum spci_mem_permission {
	SPCI_MEM_R,
	SPCI_MEM_RX,
	SPCI_MEM_RW,
};

enum spci_mem_type {
	SPCI_MEM_DEVICE,
	SPCI_MEM_NORMAL,
};

enum spci_mem_cacheability {
	SPCI_NON_CACHEABLE = 1,
	SPCI_WRITE_THROUGH,
	SPCI_WRITE_BACK,
};

enum spci_mem_device_type {
	SPCI_NGNRNE,
	SPCI_NGNRE,
	SPCI_NGRE,
	SPCI_GRE,
};


/* The type of a SPCI endpoint ID */
typedef u16 spci_sp_id_t;

struct spci_mem_region_constituent {
	u64 address;
	u32 page_count;
};

struct spci_mem_region_attributes {
	spci_sp_id_t receiver;
	u16 attrs;
};

struct spci_mem_region {
	u32 tag;
	u32 flags;
	u32 page_count;
	u32 constituent_count;
	u32 constituent_offset;
	u32 attribute_count;

	struct spci_mem_region_attributes attributes[];
};

struct spci_partition_info {
		/** The ID of the VM the information is about. */
		spci_sp_id_t id;
		/**
		 * The number of execution contexts implemented by the
		 * partition.
		 */
		uint16_t execution_context;
		/**
		 * The Partition's properties, e.g. supported messaging
		 * methods
		 */
		uint32_t partition_properties;
};


/**
 * struct spci_ops - represents the various SPCI protocol operations
 * available for an SCPI endpoint.
 */
struct spci_ops {
	int (*async_msg_send)(spci_sp_id_t dst_id, u32 len, u32 attributes);
	struct arm_smcccv1_2_return
	(*sync_msg_send)(spci_sp_id_t dst_id, u64 w3, u64 w4, u64 w5,
			 u64 w6, u64 w7);

	/**
	 * Registers a memory region with the SPCI implementation.
	 * Params:
	 *  - tag: Implementation defined value.
	 *  - flags:
	 *  - attrs[]: Array of destination VMs and permissions with which the
	 *     Stage-2 mappings are set.
	 *  - num_attrs: Count of elements pointed to by attrs.
	 *  - pages[]: Array of pointers to struct page representing the pages
	 *     to be shared.
	 *  - num_pages: Count of elements pointed to by pages.
	 *  - global_handle: A system-wide unique handle referring to the shared
	 *     set of physical pages being shared.
	 *
	 * Return: 0 in case of success, otherwise a negative value
	 * (error code).
	 */
	int (*mem_share)(u32 tag, u32 flags,
			  struct spci_mem_region_attributes attrs[],
			  u32 num_attrs, struct page *pages[],
			  u32 num_pages, u32 *global_handle);
	/**
	 * Reclaims a memory region previously registered with the SPCI
	 *  implementation.
	 * Params:
	 *  - global_handle: The global identifier of the memory region being
	 *     reclaimed.
	 *  - clear_memory: Set if the memory is meant to be cleared before
	 *     being mapped in the owner's Stage-2.
	 *
	 * Return: 0 in case of success, otherwise a negative value
	 * (error code).
	 */
	int (*mem_reclaim)(u32 global_handle, bool clear_memory);
	/**
	 * Returns information on a sub-set of partitions within a system
	 * identified by a UUID.
	 * Params:
	 *  - uuid0-3: The 128 bit UUID of the desired partition(s) represented
	 *              as 4 32 bit uints in form: uuid0-uuid1-uuid2-uuid3.
	 *  - spci_partition_info**: A pointer to an array of
	 *	                     `spci_parition_info` structs that will be
	 *	                     allocated and populated with the
	 *	                     discovered partitions information. The
	 *	                     caller is responsible for freeing the
	 *	                     memory allocated by the SPCI driver.
	 * Return: The number of discovered partitions in the system and the
	 *	   length of the array of spci_partition_info structs,
	 *	   otherwise a negative value (error code).
	 */
	int (*partition_info_get)(u32 uuid0, u32 uuid1, u32 uuid2, u32 uuid3,
				   struct spci_partition_info**);
};

#if IS_REACHABLE(CONFIG_ARM_SPCI_TRANSPORT)
struct spci_ops *get_spci_ops(void);
#else
static inline struct spci_ops *get_spci_ops(void) { return NULL; }
#endif

#endif /*__LINUX_ARM_SPCI_H*/
