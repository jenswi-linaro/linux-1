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

#ifndef __TEE_H
#define __TEE_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * This file describes the API provided by a TEE driver to user space.
 *
 * Each TEE driver defines a TEE specific protocol which is used for the
 * data passed back and forth using TEE_IOC_CMD.
 */


/* Helpers to make the ioctl defines */
#define TEE_IOC_MAGIC	0xa4
#define TEE_IOC_BASE	0

/* Flags relating to shared memory */
#define TEE_IOCTL_SHM_MAPPED	0x1	/* memory mapped in normal world */
#define TEE_IOCTL_SHM_DMA_BUF	0x2	/* dma-buf handle on shared memory */

#define TEE_MAX_ARG_SIZE	1024

#define TEE_GEN_CAP_GP		(1 << 0)/* Global Platform compliant TEE */

/*
 * TEE Implementation ID
 */
#define TEE_IMPL_ID_OPTEE	1

/*
 * OP-TEE specific capabilities
 */
#define TEE_OPTEE_CAP_TZ	(1 << 0)

/**
 * struct tee_ioctl_version_data - TEE version
 * @impl_id:	[out] TEE implementation id
 * @impl_caps:	[out] Implementation specific capabilities
 * @gen_caps:	[out] Generic capabilities, defined by TEE_GEN_CAPS_* above
 *
 * Identifies the TEE implementaion, @impl_id is one of TEE_IMPL_ID_* above.
 * @impl_caps is implementation specific, for example TEE_OPTEE_CAP_*
 * is valid when @impl_id == TEE_IMPL_ID_OPTEE.
 */
struct tee_ioctl_version_data {
	__u32 impl_id;
	__u32 impl_caps;
	__u32 gen_caps;
};
/**
 * TEE_IOC_VERSION - query version of TEE
 *
 * Takes a tee_version struct and returns with the TEE version data filled
 * in.
 */
#define TEE_IOC_VERSION		_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 0, \
				     struct tee_ioctl_version_data)

/**
 * struct tee_ioctl_shm_alloc_data - Shared memory allocate argument
 * @size:	[in/out] Size of shared memory to allocate
 * @flags:	[in/out] Flags to/from allocation.
 * @fd:		[out] dma_buf file descriptor of the shared memory
 *
 * The flags field should currently be zero as input. Updated by the call
 * with actual flags as defined by TEE_IOCTL_SHM_* above.
 * This structure is used as argument for TEE_IOC_SHM_ALLOC below.
 */
struct tee_ioctl_shm_alloc_data {
	__u64 size;
	__u32 flags;
	__s32 fd;
};
/**
 * TEE_IOC_SHM_ALLOC - allocate shared memory
 *
 * Allocates shared memory between the user space process and secure OS.
 * The returned file descriptor is used to map the shared memory into user
 * space. The shared memory is freed when the descriptor is closed and the
 * memory is unmapped.
 */
#define TEE_IOC_SHM_ALLOC	_IOWR(TEE_IOC_MAGIC, TEE_IOC_BASE + 1, \
				     struct tee_ioctl_shm_alloc_data)

/**
 * struct tee_ioctl_buf_data - Variable sized buffer
 * @buf_ptr:	[in] A __user pointer to a buffer
 * @buf_len:	[in] Length of the buffer above
 *
 * Used as argument for TEE_IOC_OPEN_SESSION, TEE_IOC_INVOKE,
 * TEE_IOC_SUPPL_RECV, and TEE_IOC_SUPPL_SEND below.
 */
struct tee_ioctl_buf_data {
	__u64 buf_ptr;
	__u64 buf_len;
};


/*
 * Attributes for struct tee_ioctl_param, selects field in the union
 */
#define TEE_IOCTL_PARAM_ATTR_TYPE_NONE		0	/* parameter not used */

/*
 * These defines value parameters (struct tee_ioctl_param_value)
 */
#define TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT	1
#define TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT	2
#define TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT	3	/* input and output */

/*
 * These defines shared memory reference parameters (struct
 * tee_ioctl_param_memref)
 */
#define TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT	5
#define TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT	6
#define TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT	7	/* input and output */

/*
 * Mask for the type part of the attribute, leaves room for more types
 */
#define TEE_IOCTL_PARAM_ATTR_TYPE_MASK		0xff

/*
 * Matches TEEC_LOGIN_* in GP TEE Client API
 * Is only defined for GP compliant TEEs
 */
#define TEE_IOCTL_LOGIN_PUBLIC			0
#define TEE_IOCTL_LOGIN_USER			1
#define TEE_IOCTL_LOGIN_GROUP			2
#define TEE_IOCTL_LOGIN_APPLICATION		4
#define TEE_IOCTL_LOGIN_USER_APPLICATION	5
#define TEE_IOCTL_LOGIN_GROUP_APPLICATION	6

/**
 * struct tee_ioctl_param_memref - memory reference
 * @shm_offs:	Offset into the shared memory object
 * @size:	Size of the buffer
 * @shm_fd:	Shared memory file descriptor
 *
 * Shared memory is allocated with TEE_IOC_SHM_ALLOC which returns a file
 * descriptor connected to the shared memory object. A memref can reference
 * a part of a shared memory by specifying an offset (@shm_offs) and @size
 * of the object. To supply the entire shared memory object set @shm_offs to 0
 * and @size to the previously returned size of the object.
 */
struct tee_ioctl_param_memref {
	__u64 shm_offs;
	__u64 size;
	__s64 shm_fd;
};

/**
 * struct tee_ioctl_param_value - values
 * @a: first value
 * @b: second value
 * @c: third value
 */
struct tee_ioctl_param_value {
	__u64 a;
	__u64 b;
	__u64 c;
};

/**
 * struct tee_ioctl_param - parameter
 * @attr: attributes
 * @memref: a memory reference
 * @value: a value
 *
 * @attr & TEE_PARAM_ATTR_TYPE_MASK indicates if memref or value is used in
 * the union. TEE_PARAM_ATTR_TYPE_VALUE_* indicates value and
 * TEE_PARAM_ATTR_TYPE_MEMREF_* indicates memref. TEE_PARAM_ATTR_TYPE_NONE
 * indicates that none of the members are used.
 */
struct tee_ioctl_param {
	__u64 attr;
	union {
		struct tee_ioctl_param_memref memref;
		struct tee_ioctl_param_value value;
	} u;
};

#define TEE_IOCTL_UUID_LEN		16

/**
 * struct tee_ioctl_open_session_arg - Open session argument
 * @uuid:	[in] UUID of the Trusted Application
 * @clnt_uuid:	[in] UUID of client
 * @clnt_login:	[in] Login class of client, TEE_LOGIN_* above
 * @cancel_id:	[in] Cancellation id, a unique value to identify this request
 * @session:	[out] Session id
 * @ret:	[out] return value
 * @ret_origin	[out] origin of the return value
 * @num_params	[in] number of parameters following this struct
 */
struct tee_ioctl_open_session_arg {
	__u8 uuid[TEE_IOCTL_UUID_LEN];
	__u8 clnt_uuid[TEE_IOCTL_UUID_LEN];
	__u32 clnt_login;
	__u32 cancel_id;
	__u32 session;
	__u32 ret;
	__u32 ret_origin;
	__u32 num_params;
	/*
	 * this struct is 8 byte aligned since the 'struct tee_ioctl_param'
	 * which follows requires 8 byte alignment.
	 *
	 * Commented out element used to visualize the layout dynamic part
	 * of the struct. This field is not available at all if
	 * num_params == 0.
	 *
	 * struct tee_ioctl_param params[num_params];
	 */
} __aligned(8);

/**
 * TEE_IOC_OPEN_SESSION - opens a session to a Trusted Application
 *
 * Takes a struct tee_ioctl_buf_data which contains a struct
 * tee_ioctl_open_session_arg followed by any array of struct
 * tee_ioctl_param
 */
#define TEE_IOC_OPEN_SESSION	_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 2, \
				     struct tee_ioctl_buf_data)

/**
 * struct tee_ioctl_invoke_func_arg - Invokes a function in a Trusted Application
 * @func:	[in] Trusted Application function, specific to the TA
 * @session:	[in] Session id
 * @cancel_id:	[in] Cancellation id, a unique value to identify this request
 * @ret:	[out] return value
 * @ret_origin	[out] origin of the return value
 * @num_params	[in] number of parameters following this struct
 */
struct tee_ioctl_invoke_arg {
	__u32 func;
	__u32 session;
	__u32 cancel_id;
	__u32 ret;
	__u32 ret_origin;
	__u32 num_params;
	/*
	 * this struct is 8 byte aligned since the 'struct tee_ioctl_param'
	 * which follows requires 8 byte alignment.
	 *
	 * Commented out element used to visualize the layout dynamic part
	 * of the struct. This field is not available at all if
	 * num_params == 0.
	 *
	 * struct tee_ioctl_param params[num_params];
	 */
} __aligned(8);

/**
 * TEE_IOC_INVOKE - Invokes a function in a Trusted Application
 *
 * Takes a struct tee_ioctl_buf_data which contains a struct
 * tee_invoke_func_arg followed by any array of struct tee_param
 */
#define TEE_IOC_INVOKE		_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 3, \
				     struct tee_ioctl_buf_data)

/**
 * struct tee_ioctl_cancel_arg - Cancels an open session or invoke ioctl
 * @cancel_id:	[in] Cancellation id, a unique value to identify this request
 * @session:	[in] Session id, if the session is opened, else set to 0
 */
struct tee_ioctl_cancel_arg {
	__u32 cancel_id;
	__u32 session;
};
/**
 * TEE_IOC_CANCEL - Cancels an open session or invoke
 */
#define TEE_IOC_CANCEL		_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 4, \
				     struct tee_ioctl_cancel_arg)

/**
 * struct tee_ioctl_close_session_arg - Closes an open session
 * @session:	[in] Session id
 */
struct tee_ioctl_close_session_arg {
	__u32 session;
};
/**
 * TEE_IOC_CLOSE_SESSION - Closes a session
 */
#define TEE_IOC_CLOSE_SESSION	_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 5, \
				     struct tee_ioctl_close_session_arg)

/**
 * struct tee_iocl_supp_recv_arg - Receive a request for a supplicant function
 * @func:	[in] supplicant function
 * @num_params	[in/out] number of parameters following this struct
 *
 * @num_params is the number of params that tee-supplicant has room to
 * receive when input, @num_params is the number of actual params
 * tee-supplicant receives when output.
 */
struct tee_iocl_supp_recv_arg {
	__u32 func;
	__u32 num_params;
	/*
	 * this struct is 8 byte aligned since the 'struct tee_ioctl_param'
	 * which follows requires 8 byte alignment.
	 *
	 * Commented out element used to visualize the layout dynamic part
	 * of the struct. This field is not available at all if
	 * num_params == 0.
	 *
	 * struct tee_ioctl_param params[num_params];
	 */
} __aligned(8);
/**
 * TEE_IOC_SUPPL_RECV - Receive a request for a supplicant function
 *
 * Takes a struct tee_ioctl_buf_data which contains a struct
 * tee_iocl_supp_recv_arg followed by any array of struct tee_param
 */
#define TEE_IOC_SUPPL_RECV	_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 6, \
				     struct tee_ioctl_buf_data)


/**
 * struct tee_iocl_supp_send_arg - Send a response to a received request
 * @ret:	[out] return value
 * @num_params	[in] number of parameters following this struct
 */
struct tee_iocl_supp_send_arg {
	__u32 ret;
	__u32 num_params;
	/*
	 * this struct is 8 byte aligned since the 'struct tee_ioctl_param'
	 * which follows requires 8 byte alignment.
	 *
	 * Commented out element used to visualize the layout dynamic part
	 * of the struct. This field is not available at all if
	 * num_params == 0.
	 *
	 * struct tee_ioctl_param params[num_params];
	 */
} __aligned(8);
/**
 * TEE_IOC_SUPPL_SEND - Receive a request for a supplicant function
 *
 * Takes a struct tee_ioctl_buf_data which contains a struct
 * tee_iocl_supp_send_arg followed by any array of struct tee_param
 */
#define TEE_IOC_SUPPL_SEND	_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 7, \
				     struct tee_ioctl_buf_data)


/*
 * Five syscalls are used when communicating with the TEE driver.
 * open(): opens the device associated with the driver
 * ioctl(): as described above operating on the file descriptor from open()
 * close(): two cases
 *   - closes the device file descriptor
 *   - closes a file descriptor connected to allocated shared memory
 * mmap(): maps shared memory into user space using information from struct
 *	   tee_ioctl_shm_alloc_data
 * munmap(): unmaps previously shared memory
 */

#endif /*__TEE_H*/
