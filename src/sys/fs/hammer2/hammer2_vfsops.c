/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2022 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$Id$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <miscfs/genfs/genfs.h>

#include "hammer2.h"
#include "hammer2_mount.h"

MODULE(MODULE_CLASS_VFS, hammer2, NULL);

/* global list of HAMMER2 */
TAILQ_HEAD(hammer2_mntlist, hammer2_dev); /* <-> hammer2_dev::mntentry */
typedef struct hammer2_mntlist hammer2_mntlist_t;
static hammer2_mntlist_t hammer2_mntlist;

/* global list of PFS */
TAILQ_HEAD(hammer2_pfslist, hammer2_pfs); /* <-> hammer2_pfs::mntentry */
typedef struct hammer2_pfslist hammer2_pfslist_t;
static hammer2_pfslist_t hammer2_pfslist;
static hammer2_pfslist_t hammer2_spmplist;

static int hammer2_supported_version = HAMMER2_VOL_VERSION_DEFAULT;
int hammer2_cluster_meta_read = 1; /* for physical read-ahead */
int hammer2_cluster_data_read = 4; /* for physical read-ahead */
long hammer2_inode_allocs;
long hammer2_chain_allocs;
long hammer2_dio_allocs;
int hammer2_dio_limit = 256;

#define HAMMER2_SYSCTL_SUPPORTED_VERSION	1
#define HAMMER2_SYSCTL_CLUSTER_META_READ	2
#define HAMMER2_SYSCTL_CLUSTER_DATA_READ	3
#define HAMMER2_SYSCTL_INODE_ALLOCS		4
#define HAMMER2_SYSCTL_CHAIN_ALLOCS		5
#define HAMMER2_SYSCTL_DIO_ALLOCS		6
#define HAMMER2_SYSCTL_DIO_LIMIT		7

SYSCTL_SETUP(hammer2_sysctl_create, "hammer2 sysctl")
{
	int error;

	/*
	 * XXX the "34" below could be dynamic, thereby eliminating one
	 * more instance of the "number to vfs" mapping problem, but
	 * "34" is the order as taken from sys/mount.h
	 */
	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "hammer2",
	    SYSCTL_DESCR("HAMMER2 filesystem"),
	    NULL, 0, NULL, 0,
	    CTL_VFS, 34, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READONLY,
	    CTLTYPE_INT, "supported_version",
	    SYSCTL_DESCR("Highest supported HAMMER2 version"),
	    NULL, 0, &hammer2_supported_version, 0,
	    CTL_VFS, 34, HAMMER2_SYSCTL_SUPPORTED_VERSION, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "cluster_meta_read",
	    SYSCTL_DESCR("Cluster read count for meta data"),
	    NULL, 0, &hammer2_cluster_meta_read, 0,
	    CTL_VFS, 34, HAMMER2_SYSCTL_CLUSTER_META_READ, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "cluster_data_read",
	    SYSCTL_DESCR("Cluster read count for user data"),
	    NULL, 0, &hammer2_cluster_data_read, 0,
	    CTL_VFS, 34, HAMMER2_SYSCTL_CLUSTER_DATA_READ, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READONLY,
	    CTLTYPE_QUAD, "inode_allocs",
	    SYSCTL_DESCR("Number of inode allocated"),
	    NULL, 0, &hammer2_inode_allocs, 0,
	    CTL_VFS, 34, HAMMER2_SYSCTL_INODE_ALLOCS, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READONLY,
	    CTLTYPE_QUAD, "chain_allocs",
	    SYSCTL_DESCR("Number of chain allocated"),
	    NULL, 0, &hammer2_chain_allocs, 0,
	    CTL_VFS, 34, HAMMER2_SYSCTL_CHAIN_ALLOCS, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READONLY,
	    CTLTYPE_QUAD, "dio_allocs",
	    SYSCTL_DESCR("Number of dio allocated"),
	    NULL, 0, &hammer2_dio_allocs, 0,
	    CTL_VFS, 34, HAMMER2_SYSCTL_DIO_ALLOCS, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "dio_limit",
	    SYSCTL_DESCR("Number of dio to keep for reuse"),
	    NULL, 0, &hammer2_dio_limit, 0,
	    CTL_VFS, 34, HAMMER2_SYSCTL_DIO_LIMIT, CTL_EOL);
	if (error)
		goto fail;

	return;
fail:
	printf("sysctl_createv failed with error %d", error);
}

static int
hammer2_assert_clean(void)
{
	int error = 0;

	KKASSERT(hammer2_inode_allocs == 0);
	if (hammer2_inode_allocs > 0) {
		hprintf("%ld inode left\n", hammer2_inode_allocs);
		error = EINVAL;
	}
	KKASSERT(hammer2_chain_allocs == 0);
	if (hammer2_chain_allocs > 0) {
		hprintf("%ld chain left\n", hammer2_chain_allocs);
		error = EINVAL;
	}
	KKASSERT(hammer2_dio_allocs == 0);
	if (hammer2_dio_allocs > 0) {
		hprintf("%ld dio left\n", hammer2_dio_allocs);
		error = EINVAL;
	}

	return (error);
}

static int
hammer2_mount(struct mount *mp, const char *path, void *data, size_t *data_len)
{

	return (EOPNOTSUPP);
}

static int
hammer2_start(struct mount *mp, int flags)
{

	return (0);
}

static int
hammer2_unmount(struct mount *mp, int mntflags)
{

	return (EOPNOTSUPP);
}

static void
hammer2_init(void)
{
	hammer2_assert_clean();

	hammer2_dio_limit = buf_nbuf() * 2;
	if (hammer2_dio_limit > 100000)
		hammer2_dio_limit = 100000;

	/*
	zone_buffer_read = uma_zcreate("hammer2_buffer_read", 65536,
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	if (zone_buffer_read == NULL) {
		hprintf("failed to create zone_buffer_read\n");
		return (ENOMEM);
	}

	zone_xops = uma_zcreate("hammer2_xops", sizeof(hammer2_xop_t),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	if (zone_xops == NULL) {
		uma_zdestroy(zone_buffer_read);
		zone_buffer_read = NULL;
		hprintf("failed to create zone_xops\n");
		return (ENOMEM);
	}
	*/

	//lockinit(&hammer2_mntlk, PVFS, "mntlk", 0, 0);

	TAILQ_INIT(&hammer2_mntlist);
	TAILQ_INIT(&hammer2_pfslist);
	TAILQ_INIT(&hammer2_spmplist);
}

static void
hammer2_done(void)
{
	//lockdestroy(&hammer2_mntlk);

	/*
	if (zone_buffer_read) {
		uma_zdestroy(zone_buffer_read);
		zone_buffer_read = NULL;
	}
	if (zone_xops) {
		uma_zdestroy(zone_xops);
		zone_xops = NULL;
	}
	*/

	hammer2_assert_clean();

	KKASSERT(TAILQ_EMPTY(&hammer2_mntlist));
	KKASSERT(TAILQ_EMPTY(&hammer2_pfslist));
	KKASSERT(TAILQ_EMPTY(&hammer2_spmplist));
}

static const struct vnodeopv_desc * const hammer2_vnodeopv_descs[] = {
	//&hammer2_vnodeop_opv_desc,
	NULL,
};

static struct vfsops hammer2_vfsops = {
	.vfs_name = MOUNT_HAMMER2,
	.vfs_min_mount_data = sizeof(struct hammer2_mount_info),
	.vfs_mount = hammer2_mount,
	.vfs_start = hammer2_start,
	.vfs_unmount = hammer2_unmount,
	.vfs_root = (void *)eopnotsupp,
	.vfs_quotactl = (void *)eopnotsupp,
	.vfs_statvfs = (void *)eopnotsupp,
	.vfs_sync = (void *)eopnotsupp,
	.vfs_vget = (void *)eopnotsupp,
	.vfs_loadvnode = (void *)eopnotsupp,
	.vfs_newvnode = (void *)eopnotsupp,
	.vfs_fhtovp = (void *)eopnotsupp,
	.vfs_vptofh = (void *)eopnotsupp,
	.vfs_init = hammer2_init,
	.vfs_reinit = (void *)eopnotsupp,
	.vfs_done = hammer2_done,
	.vfs_mountroot = (void *)eopnotsupp,
	.vfs_snapshot = (void *)eopnotsupp,
	.vfs_extattrctl = (void *)eopnotsupp,
	.vfs_suspendctl = (void *)genfs_suspendctl,
	.vfs_renamelock_enter = (void *)eopnotsupp,
	.vfs_renamelock_exit = (void *)eopnotsupp,
	.vfs_fsync = (void *)eopnotsupp,
	.vfs_opv_descs = hammer2_vnodeopv_descs
};

static int
hammer2_modcmd(modcmd_t cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
		error = vfs_attach(&hammer2_vfsops);
		if (error)
			break;
		break;
	case MODULE_CMD_FINI:
		error = vfs_detach(&hammer2_vfsops);
		if (error)
			break;
		break;
	default:
		error = ENOTTY;
		break;
	}

	return error;
}
