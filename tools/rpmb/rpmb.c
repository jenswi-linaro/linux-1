// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2016-2019 Intel Corp. All rights reserved
 * Copyright (C) 2021-2022 Linaro Ltd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <keyutils.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* if uapi header isn't installed, this might not yet exist */
#ifndef __packed
#define __packed __attribute__((packed))
#endif

#include "linux/rpmb.h"
#include "linux/virtio_rpmb.h"

#define RPMB_KEY_SIZE 32
#define RPMB_MAC_SIZE 32
#define RPMB_NONCE_SIZE 16
#define RPMB_BLOCK_SIZE 256

#define min(a, b)			\
	({ __typeof__ (a) _a = (a);	\
	   __typeof__ (b) _b = (b);	\
		_a < _b ? _a : _b; })


static bool verbose;
#define rpmb_dbg(fmt, ARGS...) do {                     \
	if (verbose)                                    \
		fprintf(stderr, "rpmb: " fmt, ##ARGS);  \
} while (0)

#define rpmb_msg(fmt, ARGS...) \
	fprintf(stderr, "rpmb: " fmt, ##ARGS)

#define rpmb_err(fmt, ARGS...) \
	fprintf(stderr, "rpmb:%d error: " fmt, __LINE__, ##ARGS)


/*
 * Utility functions
 */
static int open_dev_file(const char *devfile, struct rpmb_ioc_cap_cmd *cap)
{
	struct rpmb_ioc_ver_cmd ver;
	int fd;
	int ret;

	fd = open(devfile, O_RDWR);
	if (fd < 0)
		rpmb_err("Cannot open: %s: %s.\n", devfile, strerror(errno));

	ret = ioctl(fd, RPMB_IOC_VER_CMD, &ver);
	if (ret < 0) {
		rpmb_err("ioctl failure %d: %s.\n", ret, strerror(errno));
		goto err;
	}

	printf("RPMB API Version %X\n", ver.api_version);

	ret = ioctl(fd, RPMB_IOC_CAP_CMD, cap);
	if (ret < 0) {
		rpmb_err("ioctl failure %d: %s.\n", ret, strerror(errno));
		goto err;
	}

	rpmb_dbg("RPMB rpmb_target = %d\n", cap->target);
	rpmb_dbg("RPMB capacity    = %d\n", cap->capacity);
	rpmb_dbg("RPMB block_size  = %d\n", cap->block_size);
	rpmb_dbg("RPMB wr_cnt_max  = %d\n", cap->wr_cnt_max);
	rpmb_dbg("RPMB rd_cnt_max  = %d\n", cap->rd_cnt_max);
	rpmb_dbg("RPMB auth_method = %d\n", cap->auth_method);

	return fd;
err:
	close(fd);
	return -1;
}

static int open_rd_file(const char *datafile, const char *type)
{
	int fd;

	if (!strcmp(datafile, "-"))
		fd = STDIN_FILENO;
	else
		fd = open(datafile, O_RDONLY);

	if (fd < 0)
		rpmb_err("Cannot open %s: %s: %s.\n",
			 type, datafile, strerror(errno));

	return fd;
}

static int open_wr_file(const char *datafile, const char *type)
{
	int fd;

	if (!strcmp(datafile, "-"))
		fd = STDOUT_FILENO;
	else
		fd = open(datafile, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0)
		rpmb_err("Cannot open %s: %s: %s.\n",
			 type, datafile, strerror(errno));
	return fd;
}

static void close_fd(int fd)
{
	if (fd > 0 && fd != STDIN_FILENO && fd != STDOUT_FILENO)
		close(fd);
}

/* need to just cast out 'const' in write(2) */
typedef ssize_t (*rwfunc_t)(int fd, void *buf, size_t count);
/* blocking rw wrapper */
static ssize_t rw(rwfunc_t func, int fd, unsigned char *buf, size_t size)
{
	ssize_t ntotal = 0, n;
	char *_buf = (char *)buf;

	do {
		n = func(fd, _buf + ntotal, size - ntotal);
		if (n == -1 && errno != EINTR) {
			ntotal = -1;
			break;
		} else if (n > 0) {
			ntotal += n;
		}
	} while (n != 0 && (size_t)ntotal != size);

	return ntotal;
}

static ssize_t read_file(int fd, unsigned char *data, size_t size)
{
	ssize_t ret;

	ret = rw(read, fd, data, size);
	if (ret < 0) {
		rpmb_err("cannot read file: %s\n.", strerror(errno));
	} else if ((size_t)ret != size) {
		rpmb_err("read %zd but must be %zu bytes length.\n", ret, size);
		ret = -EINVAL;
	}

	return ret;
}

static ssize_t write_file(int fd, unsigned char *data, size_t size)
{
	ssize_t ret;

	ret = rw((rwfunc_t)write, fd, data, size);
	if (ret < 0) {
		rpmb_err("cannot read file: %s.\n", strerror(errno));
	} else if ((size_t)ret != size) {
		rpmb_err("data is %zd but must be %zu bytes length.\n",
			 ret, size);
		ret = -EINVAL;
	}
	return ret;
}

static void __dump_buffer(const char *buf)
{
	fprintf(stderr, "%s\n", buf);
}

static void
dump_hex_buffer(const char *title, const void *buf, size_t len)
{
#define PBUF_SZ (16 * 3)
	const unsigned char *_buf = (const unsigned char *)buf;
	char pbuf[PBUF_SZ];
	int j = 0;

	if (title)
		fprintf(stderr, "%s\n", title);
	while (len-- > 0) {
		snprintf(&pbuf[j], PBUF_SZ - j, "%02X ", *_buf++);
		j += 3;
		if (j == PBUF_SZ) {
			__dump_buffer(pbuf);
			j = 0;
		}
	}
	if (j)
		__dump_buffer(pbuf);
}

/*
 * MAC bits
 */

/* The hmac calculation is from data to the end of the frame */
#define vrpmb_hmac_data_len \
	(sizeof(struct virtio_rpmb_frame) - \
	 offsetof(struct virtio_rpmb_frame, data))

static int vrpmb_calc_hmac_sha256(struct virtio_rpmb_frame *frames,
				  size_t blocks_cnt,
				  const unsigned char key[],
				  unsigned int key_size,
				  unsigned char mac[],
				  unsigned int mac_size)
{
	HMAC_CTX *ctx;
	int ret;
	unsigned int i;

	 /* SSL returns 1 on success 0 on failure */

	ctx = HMAC_CTX_new();

	ret = HMAC_Init_ex(ctx, key, key_size, EVP_sha256(), NULL);
	if (ret == 0)
		goto out;
	for (i = 0; i < blocks_cnt; i++)
		HMAC_Update(ctx, frames[i].data, vrpmb_hmac_data_len);

	ret = HMAC_Final(ctx, mac, &mac_size);
	if (ret == 0)
		goto out;
	if (mac_size != RPMB_MAC_SIZE)
		ret = 0;

	ret = 1;
out:
	HMAC_CTX_free(ctx);
	return ret == 1 ? 0 : -1;
}


static int vrpmb_check_mac(const unsigned char *key,
			   struct virtio_rpmb_frame *frames_out,
			   unsigned int cnt_out)
{
	unsigned char mac[RPMB_MAC_SIZE];

	if (cnt_out == 0) {
		rpmb_err("RPMB 0 output frames.\n");
		return -1;
	}

	vrpmb_calc_hmac_sha256(frames_out, cnt_out,
			       key, RPMB_KEY_SIZE,
			       mac, RPMB_MAC_SIZE);

	if (memcmp(mac, frames_out[cnt_out - 1].key_mac, RPMB_MAC_SIZE)) {
		rpmb_err("RPMB hmac mismatch:\n");
		dump_hex_buffer("Result MAC: ",
				frames_out[cnt_out - 1].key_mac, RPMB_MAC_SIZE);
		dump_hex_buffer("Expected MAC: ", mac, RPMB_MAC_SIZE);
		return -1;
	}

	return 0;
}

/* Compute the frames MAC and insert it */
static void vrpmb_compute_mac(const unsigned char *key,
			      struct virtio_rpmb_frame *frame)
{
	vrpmb_calc_hmac_sha256(frame, 1, key, RPMB_KEY_SIZE, &frame->key_mac, RPMB_MAC_SIZE);
}

/*
 * VirtIO RPMB Bits
 */

static const char *vrpmb_op_str(uint16_t op)
{
#define RPMB_OP(_op) case VIRTIO_RPMB_REQ_##_op: return #_op

	switch (op) {
	RPMB_OP(PROGRAM_KEY);
	RPMB_OP(GET_WRITE_COUNTER);
	RPMB_OP(DATA_WRITE);
	RPMB_OP(DATA_READ);
	RPMB_OP(RESULT_READ);
	break;
	default:
		return "unknown";
	}
#undef RPMB_OP
}

static const char *vrpmb_result_str(uint16_t result)
{
#define str(x) #x
#define RPMB_ERR(_res) case VIRTIO_RPMB_RES_##_res:         \
	{ if (result & VIRTIO_RPMB_RES_WRITE_COUNTER_EXPIRED)	\
		return "COUNTER_EXPIRE:" str(_res);  \
	else                                         \
		return str(_res);                    \
	}

	switch (result & 0x000F) {
	RPMB_ERR(OK);
	RPMB_ERR(GENERAL_FAILURE);
	RPMB_ERR(AUTH_FAILURE);
	RPMB_ERR(COUNT_FAILURE);
	RPMB_ERR(ADDR_FAILURE);
	RPMB_ERR(WRITE_FAILURE);
	RPMB_ERR(READ_FAILURE);
	RPMB_ERR(NO_AUTH_KEY);
	break;
	default:
		return "unknown";
	}
#undef RPMB_ERR
#undef str
};

#define RPMB_REQ2RESP(_OP) ((_OP) << 8)
#define RPMB_RESP2REQ(_OP) ((_OP) >> 8)

static void vrpmb_dump_frame(const char *title, const struct virtio_rpmb_frame *f)
{
	uint16_t result, req_resp;

	if (!verbose)
		return;

	if (!f)
		return;

	result = be16toh(f->result);
	req_resp = be16toh(f->req_resp);
	if (req_resp & 0xf00)
		req_resp = RPMB_RESP2REQ(req_resp);

	fprintf(stderr, "--------------- %s ---------------\n",
		title ? title : "start");
	fprintf(stderr, "ptr: %p\n", f);
	dump_hex_buffer("key_mac: ", f->key_mac, 32);
	dump_hex_buffer("data: ", f->data, 256);
	dump_hex_buffer("nonce: ", f->nonce, 16);
	fprintf(stderr, "write_counter: %u\n", be32toh(f->write_counter));
	fprintf(stderr, "address:  %0X\n", be16toh(f->address));
	fprintf(stderr, "block_count: %u\n", be16toh(f->block_count));
	fprintf(stderr, "result %s:%d\n", vrpmb_result_str(result), result);
	fprintf(stderr, "req_resp %s\n", vrpmb_op_str(req_resp));
	fprintf(stderr, "--------------- End ---------------\n");
}

static bool vrpmb_check_req_resp(uint16_t req, struct virtio_rpmb_frame *f)
{
	uint16_t req_resp = be16toh(f->req_resp);

	if (RPMB_REQ2RESP(req) != req_resp) {
		rpmb_err("RPMB response mismatch %04X != %04X\n.",
			 RPMB_REQ2RESP(req), req_resp);
		return false;
	}

	rpmb_msg("validated response: 0x%x\n", req_resp);
	return true;
}



static struct virtio_rpmb_frame * vrpmb_alloc_frames(int n)
{
	struct virtio_rpmb_frame *frames;

	frames = calloc(n, sizeof(struct virtio_rpmb_frame));
	if (frames)
		memset(frames, 0, n *  sizeof(struct virtio_rpmb_frame));
	return frames;
}

static int vrpmb_program_key(int dev_fd, void *key)
{
	struct rpmb_ioc_reqresp_cmd cmd;
	struct virtio_rpmb_frame *out, *in;
	int ret;

	out = vrpmb_alloc_frames(2);

	/* construct outgoing frames */
	out[0].req_resp = htobe16(VIRTIO_RPMB_REQ_PROGRAM_KEY);
	out[0].block_count = htobe16(1);
	memcpy(&out[0].key_mac[0], key, RPMB_MAC_SIZE);
	RAND_bytes((void *) &out[0].nonce, RPMB_NONCE_SIZE);
	out[1].req_resp = htobe16(VIRTIO_RPMB_REQ_RESULT_READ);
	RAND_bytes((void *) &out[1].nonce, RPMB_NONCE_SIZE);

	cmd.len = sizeof(struct virtio_rpmb_frame) * 2;
	cmd.request = (void *) out;

	vrpmb_dump_frame("pkey", &out[0]);
	vrpmb_dump_frame("request", &out[1]);

	/* space for response */
	in = vrpmb_alloc_frames(1);
	cmd.rlen = sizeof(struct virtio_rpmb_frame);
	cmd.response = (void *) in;

	/* do it */
	ret = ioctl(dev_fd, RPMB_IOC_PKEY_CMD, &cmd);
	if (ret < 0) {
		rpmb_err("pkey ioctl failure %d: %s.\n", ret, strerror(errno));
		goto out;
	}

	vrpmb_dump_frame("response", in);

	/* validate response */
	if (!vrpmb_check_req_resp(VIRTIO_RPMB_REQ_PROGRAM_KEY, in)) {
		ret = -1;
		goto out;
	}

	ret = vrpmb_check_mac(key, in, 1);
	if (ret) {
		rpmb_err("%s: check mac error %d\n", __func__, ret);
		goto out;
	}

out:
	if (ret)
		rpmb_err("RPMB operation %s failed=%d %s[0x%04x]\n",
			 vrpmb_op_str(out->req_resp), ret,
			 vrpmb_result_str(in->result), in->result);

	free(in);
	free(out);
	return ret;
}

static int vrpmb_get_write_counter(int dev_fd, void *key)
{
	struct rpmb_ioc_reqresp_cmd cmd;
	struct virtio_rpmb_frame *out, *in = NULL;
	int ret;

	out = vrpmb_alloc_frames(1);
	in = vrpmb_alloc_frames(1);
	if (!out || !in) {
		rpmb_err("couldn't allocate frames");
		return -ENOMEM;
	}

	/* Query frame */
	out[0].req_resp = htobe16(VIRTIO_RPMB_REQ_GET_WRITE_COUNTER);
	out[0].block_count = htobe16(1);
	RAND_bytes((void *) &out[0].nonce, RPMB_NONCE_SIZE);

	cmd.request = (void *) out;
	cmd.len = sizeof(struct virtio_rpmb_frame);
	cmd.response = (void *) in;
	cmd.rlen = sizeof(struct virtio_rpmb_frame);

	ret = ioctl(dev_fd, RPMB_IOC_COUNTER_CMD, &cmd);
	if (ret < 0) {
		rpmb_err("get wcount ioctl failure %d: %s.\n", ret,
			 strerror(errno));
		goto out;
	}

	vrpmb_dump_frame("write_counter", in);

	ret = be32toh(in->write_counter);
	rpmb_msg("counter 0x%x\n", ret);

	/* validate response */
	if (!vrpmb_check_req_resp(VIRTIO_RPMB_REQ_GET_WRITE_COUNTER, in)) {
		ret = -1;
		goto out;
	}

	if (memcmp(&in->nonce, &out[0].nonce, RPMB_NONCE_SIZE)) {
		rpmb_err("RPMB NONCE mismatch\n");
		dump_hex_buffer("Result NONCE:",
				&in->nonce, RPMB_NONCE_SIZE);
		dump_hex_buffer("Expected NONCE: ",
				&out[0].nonce, RPMB_NONCE_SIZE);
		ret = -1;
		goto out;
	}

	if (key) {
		ret = vrpmb_check_mac(key, in, 1);
		if (ret)
			rpmb_err("%s: check mac error %d\n", __func__, ret);
	}

	ret = be32toh(in->write_counter);
	rpmb_msg("counter 0x%x\n", ret);

out:
	free(out);
	free(in);
	return ret;

}

static int vrpmb_write_blocks(int dev_fd, void *key, void *data, int addr, int len)
{
	struct rpmb_ioc_reqresp_cmd cmd;
	struct virtio_rpmb_frame *out, *in = NULL;
	int frames = (len / 256) + 1;
	uint8_t *p = (uint8_t *) data;
	int i, ret;
	int write_count = vrpmb_get_write_counter(dev_fd, key);

	out = vrpmb_alloc_frames(frames);
	in = vrpmb_alloc_frames(1);
	if (!out || !in) {
		rpmb_err("couldn't allocate frames");
		return -ENOMEM;
	}

	/* First frame */
	out[0].req_resp = htobe16(VIRTIO_RPMB_REQ_DATA_WRITE);
	out[0].block_count = htobe16(frames - 1);
	out[0].address = htobe16(addr);
	out[0].write_counter = htobe32(write_count);

	/* Copy data to write and prepare frames */
	for (i = 0; i < frames; i++) {
		struct virtio_rpmb_frame *f = &out[i];

		memcpy(&f->data, &p[i * 256], 256);
		RAND_bytes((void *) &f->nonce, RPMB_NONCE_SIZE);
		vrpmb_compute_mac(key, f);
	}

	vrpmb_dump_frame("write_blocks", &out[0]);

	/* Response request */
	out[frames - 1].req_resp = htobe16(VIRTIO_RPMB_REQ_RESULT_READ);
	out[frames - 1].block_count = htobe16(1);
	RAND_bytes((void *) &out[frames - 1].nonce, RPMB_NONCE_SIZE);
	vrpmb_compute_mac(key, &out[frames - 1]);

	vrpmb_dump_frame("result_req", &out[frames - 1]);

	cmd.request = (void *) out;
	cmd.len = frames * sizeof(struct virtio_rpmb_frame);
	cmd.response = (void *) in;
	cmd.rlen = sizeof(struct virtio_rpmb_frame);

	ret = ioctl(dev_fd, RPMB_IOC_WBLOCKS_CMD, &cmd);
	if (ret < 0) {
		rpmb_err("wblocks ioctl failure %d: %s.\n", ret,
			 strerror(errno));
	}

	free(out);
	free(in);
	return ret;
}

/*
 * To read blocks we receive a bunch of frames from the vrpmb device
 * which we need to validate and extract the actual data into
 * requested buffer.
 */
static int vrpmb_read_blocks(int dev_fd, void *key, int addr, int count, void *data, int len)
{
	struct rpmb_ioc_rblocks_cmd cmd;
	int frame_length = count * sizeof(struct virtio_rpmb_frame);
	struct virtio_rpmb_frame *frames = malloc(frame_length);
	int i, ret = -1;

	rpmb_dbg("%s: reading %d blocks into %d bytes (%d bytes of frames)\n",
		 __func__, count, len, frame_length);

	if (!frames) {
		rpmb_err("unable to allocate memory for frames");
		return -1;
	}

	cmd.addr = addr;
	cmd.count = count;
	cmd.len = frame_length;
	cmd.data = (__u8 *) frames;

	ret = ioctl(dev_fd, RPMB_IOC_RBLOCKS_CMD, &cmd);
	if (ret < 0) {
		rpmb_err("rblocks ioctl failure %d: %s.\n", ret,
			 strerror(errno));
		goto out;
	}

	for (i = 0; i < count; i++) {
		struct virtio_rpmb_frame *f = &frames[i];

		vrpmb_dump_frame("block data", f);

		if (key) {
			ret = vrpmb_check_mac(key, f, 1);
			if (ret) {
				rpmb_err("%s: check mac error frame %d/%d\n", __func__, i, ret);
				break;
			}
		}

		memcpy(data, &f->data, RPMB_BLOCK_SIZE);
		data += RPMB_BLOCK_SIZE;
	}
	ret = 0;

 out:
	free(frames);
	return ret;
}

/*
 * Generic RPMB bits
 */
static int op_get_info(int nargs, char *argv[])
{
	int dev_fd;
	struct rpmb_ioc_cap_cmd cap;

	if (nargs != 1)
		return -EINVAL;

	memset(&cap, 0, sizeof(cap));
	dev_fd = open_dev_file(argv[0], &cap);
	if (dev_fd < 0)
		return -errno;
	argv++;

	printf("RPMB rpmb_target = %d\n", cap.target);
	printf("RPMB capacity    = %d\n", cap.capacity);
	printf("RPMB block_size  = %d\n", cap.block_size);
	printf("RPMB wr_cnt_max  = %d\n", cap.wr_cnt_max);
	printf("RPMB rd_cnt_max  = %d\n", cap.rd_cnt_max);
	printf("RPMB auth_method = %d\n", cap.auth_method);

	close(dev_fd);

	return 0;
}

static void *read_key(const char *path)
{
	int key_fd = open_rd_file(path, "key file");
	void *key;

	if (key_fd < 0)
		return NULL;

	key = malloc(RPMB_KEY_SIZE);

	if (!key) {
		rpmb_err("out of memory for key\n");
		return NULL;
	}

	if (read(key_fd, key, RPMB_KEY_SIZE) != RPMB_KEY_SIZE) {
		rpmb_err("couldn't read key (%s)\n", strerror(errno));
		return NULL;
	}

	close(key_fd);
	return key;
}

static int op_rpmb_program_key(int nargs, char *argv[])
{
	int ret = -EINVAL, fd = -1;
	struct rpmb_ioc_cap_cmd cap;
	void *key;

	if (nargs < 1 || nargs > 2)
		return ret;

	fd = open_dev_file(argv[0], &cap);
	if (fd < 0) {
		perror("opening RPMB device");
		return ret;
	}
	argv++;

	key = read_key(argv[0]);

	if (key)
		ret = vrpmb_program_key(fd, key);

	close_fd(fd);
	return ret;
}


static int op_rpmb_get_write_counter(int nargs, char **argv)
{
	int ret, fd = -1;
	struct rpmb_ioc_cap_cmd cap;
	void *key = NULL;

	ret = -EINVAL;
	if (nargs < 1 || nargs > 2)
		return ret;

	fd = open_dev_file(argv[0], &cap);
	if (fd < 0) {
		perror("opening RPMB device");
		return ret;
	}
	argv++;

	if (argv[0]) {
		key = read_key(argv[0]);
		if (!key)
			rpmb_err("failed to read key data");
	}

	ret = vrpmb_get_write_counter(fd, key);
	if (ret < 0) {
		rpmb_err("counter ioctl failure %d: %s.\n", ret, strerror(errno));
	} else {
		printf("Counter value is: %d\n", ret);
		ret = 0;
	}

	close_fd(fd);
	return ret;
}

static int op_rpmb_read_blocks(int nargs, char **argv)
{
	int ret, data_fd, fd = -1;
	struct rpmb_ioc_cap_cmd cap;
	unsigned long numarg;
	uint16_t addr, blocks_cnt;
	void *key = NULL;

	ret = -EINVAL;
	if (nargs < 4 || nargs > 5)
		return ret;

	fd = open_dev_file(argv[0], &cap);
	if (fd < 0) {
		perror("opening RPMB device");
		return ret;
	}
	argv++;

	errno = 0;
	numarg = strtoul(argv[0], NULL, 0);
	if (errno || numarg > USHRT_MAX) {
		rpmb_err("wrong block address\n");
		goto out;
	}
	addr = (uint16_t)numarg;
	argv++;

	errno = 0;
	numarg = strtoul(argv[0], NULL, 0);
	if (errno || numarg > USHRT_MAX) {
		rpmb_err("wrong blocks count\n");
		goto out;
	}
	blocks_cnt = (uint16_t)numarg;
	argv++;

	if (blocks_cnt == 0) {
		rpmb_err("wrong blocks count\n");
		goto out;
	}

	data_fd = open_wr_file(argv[0], "output data");
	if (data_fd < 0)
		goto out;
	argv++;

	if (argv[0]) {
		key = read_key(argv[0]);
		if (!key) {
			rpmb_err("failed to read key data");
			goto out;
		}
	}

	while (blocks_cnt > 0) {
		int to_copy = min(blocks_cnt, cap.rd_cnt_max);
		int length = to_copy * RPMB_BLOCK_SIZE;
		void *data = malloc(length);

		if (!data) {
			ret = ENOMEM;
			goto out;
		}

		vrpmb_read_blocks(fd, key, addr, to_copy, data, length);

		ret = write_file(data_fd, data, length);
		if (ret < 0) {
			perror("writing data");
			goto out;
		} else {
			rpmb_dbg("wrote %d bytes/%d blocks to file\n", length, to_copy);
		}

		free(data);
		addr += to_copy;
		blocks_cnt -= to_copy;
	}

	ret = 0;
out:
	close_fd(fd);
	close_fd(data_fd);

	return ret;
}

static int op_rpmb_write_blocks(int nargs, char **argv)
{
	int ret, data_fd, fd = -1;
	struct rpmb_ioc_cap_cmd cap;
	unsigned long numarg;
	uint16_t addr, blocks_cnt;
	void *key;

	ret = -EINVAL;
	if (nargs < 4 || nargs > 5)
		return ret;

	fd = open_dev_file(argv[0], &cap);
	if (fd < 0) {
		perror("opening RPMB device");
		return ret;
	}
	argv++;

	errno = 0;
	numarg = strtoul(argv[0], NULL, 0);
	if (errno || numarg > USHRT_MAX) {
		rpmb_err("wrong block address\n");
		goto out;
	}
	addr = (uint16_t)numarg;
	argv++;

	errno = 0;
	numarg = strtoul(argv[0], NULL, 0);
	if (errno || numarg > USHRT_MAX) {
		rpmb_err("wrong blocks count\n");
		goto out;
	}
	blocks_cnt = (uint16_t)numarg;
	argv++;

	if (blocks_cnt == 0) {
		rpmb_err("wrong blocks count\n");
		goto out;
	}

	data_fd = open_rd_file(argv[0], "input data");
	if (data_fd < 0)
		goto out;
	argv++;

	key = read_key(nargs == 5 ? argv[0] : NULL);
	if (!key) {
		rpmb_err("failed to read key data");
		goto out;
	}

	while (blocks_cnt > 0) {
		int to_copy = min(blocks_cnt, cap.wr_cnt_max);
		int length = to_copy * 256;
		void *data = malloc(length);

		if (!data) {
			ret = ENOMEM;
			goto out;
		}

		ret = read_file(data_fd, data, length);
		if (ret < 0) {
			perror("reading data");
			goto out;
		}

		ret = vrpmb_write_blocks(fd, key, data, addr, length);
		if (ret < 0) {
			rpmb_err("wblocks ioctl failure %d: %s.\n", ret,
				 strerror(errno));
			goto out;
		}

		free(data);
		addr += to_copy;
		blocks_cnt -= to_copy;
	}

	ret = 0;
out:
	close_fd(fd);
	close_fd(data_fd);

	return ret;
}

typedef int (*rpmb_op)(int argc, char *argv[]);

struct rpmb_cmd {
	const char *op_name;
	rpmb_op     op;
	const char  *usage; /* usage title */
	const char  *help;  /* help */
};

static const struct rpmb_cmd cmds[] = {
	{
		"get-info",
		op_get_info,
		"<RPMB_DEVICE>",
		"    Get RPMB device info\n",
	},
	{
		"program-key",
		op_rpmb_program_key,
		"<RPMB_DEVICE> <KEYFILE>",
		"    Program authentication KEYFILE\n"
		"    NOTE: This is a one-time programmable irreversible change.\n",
	},
	{
		"write-counter",
		op_rpmb_get_write_counter,
		"<RPMB_DEVICE>",
		"    Rertrive write counter value from the <RPMB_DEVICE> to stdout.\n"
	},
	{
		"write-blocks",
		op_rpmb_write_blocks,
		"<RPMB_DEVICE> <address> <block_count> <DATA_FILE> <KEYID>",
		"    <block count> of 256 bytes will be written from the DATA_FILE\n"
		"    to the <RPMB_DEVICE> at block offset <address>.\n"
		"    When DATA_FILE is -, read from standard input.\n",
	},
	{
		"read-blocks",
		op_rpmb_read_blocks,
		"<RPMB_DEVICE> <address> <blocks count> <OUTPUT_FILE>",
		"    <block count> of 256 bytes will be read from <RPMB_DEVICE>\n"
		"    to the OUTPUT_FILE\n"
		"    When OUTPUT_FILE is -, write to standard output\n",
	},

	{ NULL, NULL, NULL, NULL }
};

static void help(const char *prog, const struct rpmb_cmd *cmd)
{
	printf("%s %s %s\n", prog, cmd->op_name, cmd->usage);
	printf("%s\n", cmd->help);
}

static void usage(const char *prog)
{
	int i;

	printf("\n");
	printf("Usage: %s [-v] <command> <args>\n\n", prog);
	for (i = 0; cmds[i].op_name; i++)
		printf("       %s %s %s\n",
		       prog, cmds[i].op_name, cmds[i].usage);

	printf("\n");
	printf("      %s -v/--verbose: runs in verbose mode\n", prog);
	printf("      %s help : shows this help\n", prog);
	printf("      %s help <command>: shows detailed help\n", prog);
}

static bool call_for_help(const char *arg)
{
	return !strcmp(arg, "help") ||
	       !strcmp(arg, "-h")   ||
	       !strcmp(arg, "--help");
}

static bool parse_verbose(const char *arg)
{
	return !strcmp(arg, "-v") ||
	       !strcmp(arg, "--verbose");
}

static const
struct rpmb_cmd *parse_args(const char *prog, int *_argc, char **_argv[])
{
	int i;
	int argc = *_argc;
	char **argv =  *_argv;
	const struct rpmb_cmd *cmd = NULL;
	bool need_help = false;

	argc--; argv++;

	if (argc == 0)
		goto out;

	if (call_for_help(argv[0])) {
		argc--; argv++;
		if (argc == 0)
			goto out;

		need_help = true;
	}

	if (parse_verbose(argv[0])) {
		argc--; argv++;
		if (argc == 0)
			goto out;

		verbose = true;
	}

	for (i = 0; cmds[i].op_name; i++) {
		if (!strncmp(argv[0], cmds[i].op_name,
			     strlen(cmds[i].op_name))) {
			cmd = &cmds[i];
			argc--; argv++;
			break;
		}
	}

	if (!cmd)
		goto out;

	if (need_help || (argc > 0 && call_for_help(argv[0]))) {
		help(prog, cmd);
		argc--; argv++;
		return NULL;
	}

out:
	*_argc = argc;
	*_argv = argv;

	if (!cmd)
		usage(prog);

	return cmd;
}

int main(int argc, char *argv[])
{
	const char *prog = basename(argv[0]);
	const struct rpmb_cmd *cmd;
	int ret;

	cmd = parse_args(prog, &argc, &argv);
	if (!cmd)
		exit(EXIT_SUCCESS);

	ret = cmd->op(argc, argv);
	if (ret == -EINVAL)
		help(prog, cmd);

	exit(ret);
}
