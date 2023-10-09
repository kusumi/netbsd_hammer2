/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2022 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _FS_HAMMER2_IOCTL_H_
#define _FS_HAMMER2_IOCTL_H_

#include <sys/param.h>
#include <sys/ioccom.h>
#include <sys/syslimits.h>

#include "hammer2_disk.h"

/*
 * Ioctl to get version.
 */
struct hammer2_ioc_version {
	int			version;
	char			reserved[256 - 4];
};

typedef struct hammer2_ioc_version hammer2_ioc_version_t;

/*
 * Ioctls to manage PFSs.
 *
 * PFSs can be clustered by matching their pfs_clid, and the PFSs making up
 * a cluster can be uniquely identified by combining the vol_id with
 * the pfs_clid.
 */
struct hammer2_ioc_pfs {
	hammer2_key_t		name_key;	/* super-root directory scan */
	hammer2_key_t		name_next;	/* (GET only) */
	uint8_t			pfs_type;
	uint8_t			pfs_subtype;
	uint8_t			reserved0012;
	uint8_t			reserved0013;
	uint32_t		pfs_flags;
	uint64_t		reserved0018;
	struct uuid		pfs_fsid;	/* identifies PFS instance */
	struct uuid		pfs_clid;	/* identifies PFS cluster */
	char			name[NAME_MAX+1]; /* PFS label */
};

typedef struct hammer2_ioc_pfs hammer2_ioc_pfs_t;

#define HAMMER2_PFSFLAGS_NOSYNC		0x00000001

/*
 * Ioctl to manage inodes.
 */
struct hammer2_ioc_inode {
	uint32_t		flags;
	void			*unused;
	hammer2_key_t		data_count;
	hammer2_key_t		inode_count;
	hammer2_inode_data_t	ip_data;
};

typedef struct hammer2_ioc_inode hammer2_ioc_inode_t;

#define HAMMER2IOC_INODE_FLAG_IQUOTA	0x00000001
#define HAMMER2IOC_INODE_FLAG_DQUOTA	0x00000002
#define HAMMER2IOC_INODE_FLAG_COPIES	0x00000004
#define HAMMER2IOC_INODE_FLAG_CHECK	0x00000008
#define HAMMER2IOC_INODE_FLAG_COMP	0x00000010

/*
 * Ioctl for bulkfree scan.
 */
struct hammer2_ioc_bulkfree {
	hammer2_off_t		sbase;	/* starting storage offset */
	hammer2_off_t		sstop;	/* (set on return) */
	size_t			size;	/* swapable kernel memory to use */
	hammer2_off_t		count_allocated;	/* alloc fixups this run */
	hammer2_off_t		count_freed;		/* bytes freed this run */
	hammer2_off_t		total_fragmented;	/* merged result */
	hammer2_off_t		total_allocated;	/* merged result */
	hammer2_off_t		total_scanned;		/* bytes of storage */
};

typedef struct hammer2_ioc_bulkfree hammer2_ioc_bulkfree_t;

/*
 * Unconditionally delete a hammer2 directory entry or inode number.
 */
struct hammer2_ioc_destroy {
	enum { HAMMER2_DELETE_NOP,
	       HAMMER2_DELETE_FILE,
	       HAMMER2_DELETE_INUM } cmd;
	char			path[HAMMER2_INODE_MAXNAME];
	hammer2_key_t		inum;
};

typedef struct hammer2_ioc_destroy hammer2_ioc_destroy_t;

/*
 * Grow the filesystem.  If size is set to 0 H2 will auto-size to the
 * partition it is in.  The caller can resize the partition, then issue
 * the ioctl.
 */
struct hammer2_ioc_growfs {
	hammer2_off_t		size;
	int			modified;
	int			unused01;
	int			unusedary[14];
};

typedef struct hammer2_ioc_growfs hammer2_ioc_growfs_t;

/*
 * Ioctl to manage volumes.
 */
struct hammer2_ioc_volume {
	char			path[MAXPATHLEN];
	int			id;
	hammer2_off_t		offset;
	hammer2_off_t		size;
};

typedef struct hammer2_ioc_volume hammer2_ioc_volume_t;

struct hammer2_ioc_volume_list {
	hammer2_ioc_volume_t	*volumes;
	int			nvolumes;
	int			version;
	char			pfs_name[HAMMER2_INODE_MAXNAME];
};

typedef struct hammer2_ioc_volume_list hammer2_ioc_volume_list_t;

/*
 * Ioctl list.
 */
#define HAMMER2IOC_VERSION_GET		_IOWR('h', 64, struct hammer2_ioc_version)
#define HAMMER2IOC_PFS_GET		_IOWR('h', 80, struct hammer2_ioc_pfs)
#define HAMMER2IOC_PFS_CREATE		_IOWR('h', 81, struct hammer2_ioc_pfs)
#define HAMMER2IOC_PFS_DELETE		_IOWR('h', 82, struct hammer2_ioc_pfs)
#define HAMMER2IOC_PFS_LOOKUP		_IOWR('h', 83, struct hammer2_ioc_pfs)
#define HAMMER2IOC_PFS_SNAPSHOT		_IOWR('h', 84, struct hammer2_ioc_pfs)
#define HAMMER2IOC_INODE_GET		_IOWR('h', 86, struct hammer2_ioc_inode)
#define HAMMER2IOC_INODE_SET		_IOWR('h', 87, struct hammer2_ioc_inode)
#define HAMMER2IOC_DEBUG_DUMP		_IOWR('h', 91, int)
#define HAMMER2IOC_BULKFREE_SCAN	_IOWR('h', 92, struct hammer2_ioc_bulkfree)
#define HAMMER2IOC_DESTROY		_IOWR('h', 94, struct hammer2_ioc_destroy)
#define HAMMER2IOC_EMERG_MODE		_IOWR('h', 95, int)
#define HAMMER2IOC_GROWFS		_IOWR('h', 96, struct hammer2_ioc_growfs)
#define HAMMER2IOC_VOLUME_LIST		_IOWR('h', 97, struct hammer2_ioc_volume_list)

#endif /* !_FS_HAMMER2_IOCTL_H_ */
