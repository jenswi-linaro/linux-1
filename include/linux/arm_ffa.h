/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019, 2020 Arm Ltd.
 */

#ifndef __LINUX_ARM_FFA_H
#define __LINUX_ARM_FFA_H

#define FFA_ERROR_32                 0x84000060
#define FFA_SUCCESS_32               0x84000061
#define FFA_INTERRUPT_32             0x84000062
#define FFA_VERSION_32               0x84000063
#define FFA_FEATURES_32              0x84000064
#define FFA_RX_RELEASE_32            0x84000065
#define FFA_RXTX_MAP_32              0x84000066

#define FFA_PARTITION_INFO_GET_32    0x84000068
#define FFA_ID_GET_32                0x84000069

#define FFA_RUN_32                   0x8400006D
#define FFA_MSG_SEND_32              0x8400006E
#define FFA_MSG_SEND_DIRECT_REQ_32   0x8400006F
#define FFA_MSG_SEND_DIRECT_RESP_32  0x84000070
#define FFA_MEM_RECLAIM_32           0x84000077
#define FFA_MEM_OP_PAUSE_32          0x84000078
#define FFA_MEM_OP_RESUME_32         0x84000079

#define FFA_MEM_SHARE_64             0xC4000073

#define FFA_MEM_FRAG_RX_32			  0x8400007A
#define FFA_MEM_FRAG_TX_32			  0x8400007B

/* FFA error codes. */
#define FFA_SUCCESS            (0)
#define FFA_NOT_SUPPORTED      (-1)
#define FFA_INVALID_PARAMETERS (-2)
#define FFA_NO_MEMORY          (-3)
#define FFA_BUSY               (-4)
#define FFA_INTERRUPTED        (-5)
#define FFA_DENIED             (-6)
#define FFA_RETRY              (-7)
#define FFA_ABORTED            (-8)

#define FFA_BASE_GRANULE_SIZE 4096

struct scatterlist;

enum ffa_mem_permission {
	FFA_MEM_R   = 0x1,
	FFA_MEM_RW  = 0x2,
	FFA_MEM_XN  = 0x4,
	FFA_MEM_X   = 0x8,
};

#define FFA_MEMTYPE_OFFSET 4
enum ffa_mem_type {
	FFA_MEM_DEVICE = 0x1,
	FFA_MEM_NORMAL = 0x2,
};


#define FFA_CACHEABILITY_OFFSET 2
enum ffa_mem_cacheability {
	FFA_NON_CACHEABLE = 0x1,
	FFA_WRITE_BACK = 0x3,
};

enum ffa_mem_shareability {
	FFA_NON_SHAREABLE,
	FFA_OUTER_SHAREABLE = 0x2,
	FFA_INNER_SHAREABLE = 0x3,
};

#define FFA_DEVICE_OFFSET 2
enum ffa_mem_device_type {
	FFA_NGNRNE,
	FFA_NGNRE,
	FFA_NGRE,
	FFA_GRE,
};

enum mem_clear_t {
	FFA_KEEP_MEMORY,
	FFA_CLEAR_MEMORY,
};

typedef u64 ffa_mem_handle_t;

/* The type of an FFA endpoint ID */
typedef u16 ffa_sp_id_t;

struct ffa_mem_region_constituent {
	u64 address;
	u32 page_count;
	u32 reserved_12_15;
};

struct ffa_composite_memory_region {

	uint32_t total_page_count;
	uint32_t constituent_count;

	uint64_t reserved_0;

	struct ffa_mem_region_constituent constituents[];
};

struct ffa_mem_region_attributes {
	ffa_sp_id_t receiver;
	u8 attrs;
	u32 composite_off;
	u64 reserved_8_15;
};

/* Table 43 */
struct ffa_memory_region_attribute {
	uint8_t attribute;
};

struct ffa_mem_region {
	u16 sender_id;
	struct ffa_memory_region_attribute region_attr;
	u8 reserved_0;
	u32 flags;
	u64 handle;
	u64 tag;
	u32 reserved_1;
	u32 endpoint_count;
	struct ffa_mem_region_attributes endpoints[];
};

static inline struct ffa_composite_memory_region *
ffa_get_composite(struct ffa_mem_region *mem_region, u32 num_endpoints)
{
	struct ffa_composite_memory_region *composite;

	composite = (struct ffa_composite_memory_region *)
		(&mem_region->endpoints[num_endpoints]);
	return composite;
}


struct ffa_partition_info {
		/** The ID of the VM the information is about. */
		ffa_sp_id_t id;
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
 * struct ffa_ops - represents the various FFA protocol operations
 * available for an SCPI endpoint.
 */
struct ffa_ops {
	int (*async_msg_send)(ffa_sp_id_t dst_id, u32 len, u32 attributes);
	struct arm_smcccv1_2_return
	(*sync_msg_send)(ffa_sp_id_t dst_id, u64 w3, u64 w4, u64 w5,
			 u64 w6, u64 w7);

	/**
	 * Registers a memory region with the FFA implementation.
	 *
	 * Params:
	 *  - tag: Implementation defined value.
	 *  - flags:
	 *   - FFA_KEEP_MEMORY: DO not clear the memory region;
	 *   - FFA_CLEAR_MEMORY: Clear the memory region.
	 *  - attrs[]: Array of destination VMs and permissions with which the
	 *     Stage-2 mappings are set.
	 *  - num_attrs: Count of elements pointed to by attrs.
	 *  - sg: scatter list holding the pages to be shared.
	 *  - global_handle: A system-wide unique handle referring to the shared
	 *     set of physical pages being shared.
	 *  - use_tx: select if memorry region description is transmitted in tx
	 *     or in a dynamically allocated buffer. When using the tx buffer a
	 *     global lock on the tx buffer will be held.
	 *
	 * Return: 0 in case of success, otherwise a negative value
	 * (error code).
	 */
	int (*mem_share)(u32 tag, enum mem_clear_t flags,
			  struct ffa_mem_region_attributes attrs[],
			  u32 num_attrs, struct scatterlist *sg, u32 nents,
			  ffa_mem_handle_t *global_handle, bool use_tx);

	/**
	 * Reclaims a memory region previously registered with the FFA
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
	int (*mem_reclaim)(ffa_mem_handle_t global_handle,
		enum mem_clear_t flags);
	/**
	 * Returns information on a sub-set of partitions within a system
	 * identified by a UUID.
	 * Params:
	 *  - uuid0-3: The 128 bit UUID of the desired partition(s) represented
	 *              as 4 32 bit uints in form: uuid0-uuid1-uuid2-uuid3.
	 *  - ffa_partition_info**: A pointer to an array of
	 *	                     `ffa_parition_info` structs that will be
	 *	                     allocated and populated with the
	 *	                     discovered partitions information. The
	 *	                     caller is responsible for freeing the
	 *	                     memory allocated by the FFA driver.
	 * Return: The number of discovered partitions in the system and the
	 *	   length of the array of ffa_partition_info structs,
	 *	   otherwise a negative value (error code).
	 */
	int (*partition_info_get)(u32 uuid0, u32 uuid1, u32 uuid2, u32 uuid3,
				   struct ffa_partition_info **buffer);
};

#if IS_REACHABLE(CONFIG_ARM_FFA_TRANSPORT)
struct ffa_ops *get_ffa_ops(void);
#else
static inline struct ffa_ops *get_ffa_ops(void) { return NULL; }
#endif

#endif /*__LINUX_ARM_FFA_H*/
