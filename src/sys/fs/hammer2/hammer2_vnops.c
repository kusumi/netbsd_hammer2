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

#include "hammer2.h"

#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/uio.h>
#include <sys/unistd.h>

#include <miscfs/genfs/genfs.h>
#include <miscfs/genfs/genfs_node.h>
#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>

static int
hammer2_inactive(void *v)
{
	struct vop_inactive_v2_args /* {
		struct vnode *a_vp;
		bool *a_recycle;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (ip->meta.mode == 0) {
		/*
		 * If we are done with the inode, reclaim it
		 * so that it can be reused immediately.
		 */
		*ap->a_recycle = true;
	}

	return (0);
}

static int
hammer2_reclaim(void *v)
{
	struct vop_reclaim_v2_args /* {
		struct vnode *a_vp;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	VOP_UNLOCK(vp);

	genfs_node_destroy(vp);

	vp->v_data = NULL;
	ip->vp = NULL;

	hammer2_inode_drop(ip);

	return (0);
}

static int
hammer2_check_possible(struct vnode *vp, hammer2_inode_t *ip, mode_t mode)
{
	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the file system.
	 */
	if (mode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
			break;
		default:
			break;
		}
	}

	return (0);
}

static int
hammer2_check_permitted(struct vnode *vp, hammer2_inode_t *ip, accmode_t accmode,
    kauth_cred_t cred)
{
	return kauth_authorize_vnode(cred, KAUTH_ACCESS_ACTION(accmode,
	    vp->v_type, ip->meta.mode & ALLPERMS), vp, NULL,
	    genfs_can_access(vp, cred, hammer2_to_unix_xid(&ip->meta.uid),
	    hammer2_to_unix_xid(&ip->meta.gid), ip->meta.mode & ALLPERMS,
	    NULL, accmode));
}

static int
hammer2_access(void *v)
{
	struct vop_access_args /* {
		struct vnode *a_vp;
		accmode_t  a_accmode;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);
	int error;

	error = hammer2_check_possible(vp, ip, ap->a_accmode);
	if (error)
		return (error);

	error = hammer2_check_permitted(vp, ip, ap->a_accmode, ap->a_cred);

	return (error);
}

static int
hammer2_getattr(void *v)
{
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	hammer2_inode_t *ip = VTOI(vp);
	hammer2_pfs_t *pmp = ip->pmp;

	vap->va_fsid = pmp->mp->mnt_stat.f_fsid;
	vap->va_fileid = ip->meta.inum;
	vap->va_mode = ip->meta.mode;
	vap->va_nlink = ip->meta.nlinks;
	vap->va_uid = hammer2_to_unix_xid(&ip->meta.uid);
	vap->va_gid = hammer2_to_unix_xid(&ip->meta.gid);
	vap->va_rdev = NODEV;
	vap->va_size = ip->meta.size;
	vap->va_flags = ip->meta.uflags;
	hammer2_time_to_timespec(ip->meta.ctime, &vap->va_ctime);
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_mtime);
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_atime);
	vap->va_gen = 1;
	vap->va_blocksize = vp->v_mount->mnt_stat.f_iosize;
	if (ip->meta.type == HAMMER2_OBJTYPE_DIRECTORY) {
		/*
		 * Can't really calculate directory use sans the files under
		 * it, just assume one block for now.
		 */
		vap->va_bytes = HAMMER2_INODE_BYTES;
	} else {
		vap->va_bytes = hammer2_inode_data_count(ip);
	}
	vap->va_type = hammer2_get_vtype(ip->meta.type);
	vap->va_filerev = 0;

	return (0);
}

static int
hammer2_setattr(void *v)
{
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;

	if (vap->va_type != VNON
	    || vap->va_nlink != (nlink_t)VNOVAL
	    || vap->va_fsid != (dev_t)VNOVAL
	    || vap->va_fileid != (ino_t)VNOVAL
	    || vap->va_blocksize != (long)VNOVAL
	    || vap->va_rdev != (dev_t)VNOVAL
	    || vap->va_bytes != (u_quad_t)VNOVAL
	    || vap->va_gen != (u_long)VNOVAL
	    || vap->va_flags != (u_long)VNOVAL
	    || vap->va_uid != (uid_t)VNOVAL
	    || vap->va_gid != (gid_t)VNOVAL
	    || vap->va_atime.tv_sec != (time_t)VNOVAL
	    || vap->va_mtime.tv_sec != (time_t)VNOVAL
	    || vap->va_mode != (mode_t)VNOVAL)
		return (EROFS);

	if (vap->va_size != (u_quad_t)VNOVAL) {
		switch (vp->v_type) {
		case VDIR:
			return (EISDIR);
		case VLNK:
		case VREG:
			return (EROFS);
		case VCHR:
		case VBLK:
		case VSOCK:
		case VFIFO:
			return (0);
		default:
			return (EINVAL);
		}
	}

	return (EINVAL);
}

static int
hammer2_write_dirent(struct uio *uio, ino_t d_fileno, uint8_t d_type,
    uint16_t d_namlen, const char *d_name, int *errorp)
{
	struct dirent dirent;

	bzero(&dirent, sizeof(dirent));
	dirent.d_fileno = d_fileno;
	dirent.d_type = d_type;
	dirent.d_namlen = d_namlen;
	dirent.d_reclen = _DIRENT_SIZE(&dirent);
	if (dirent.d_reclen > uio->uio_resid)
		return (1); /* uio has no space left, end this readdir */
	bcopy(d_name, dirent.d_name, d_namlen);

	*errorp = uiomove(&dirent, dirent.d_reclen, uio);

	return (0); /* uio has space left */
}

static int
hammer2_readdir(void *v)
{
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		kauth_cred_t a_cred;
		int **a_eofflag;
		off_t **a_cookies;
		int ncookies;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;

	hammer2_xop_readdir_t *xop;
	hammer2_inode_t *ip = VTOI(vp);
	const hammer2_inode_data_t *ripdata;
	hammer2_blockref_t bref;
	hammer2_tid_t inum;
	off_t saveoff = uio->uio_offset;
	off_t *cookies;
	int ncookies, r, dtype;
	int cookie_index = 0, eofflag = 0, error = 0;
	uint16_t namlen;
	const char *dname;

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/* Setup cookies directory entry cookies if requested. */
	if (ap->a_ncookies) {
		ncookies = uio->uio_resid / 16 + 1;
		if (ncookies > 1024)
			ncookies = 1024;
		cookies = malloc(ncookies * sizeof(off_t), M_TEMP, M_WAITOK);
	} else {
		ncookies = -1;
		cookies = NULL;
	}

	hammer2_inode_lock(ip, HAMMER2_RESOLVE_SHARED);

	/*
	 * Handle artificial entries.  To ensure that only positive 64 bit
	 * quantities are returned to userland we always strip off bit 63.
	 * The hash code is designed such that codes 0x0000-0x7FFF are not
	 * used, allowing us to use these codes for articial entries.
	 *
	 * Entry 0 is used for '.' and entry 1 is used for '..'.  Do not
	 * allow '..' to cross the mount point into (e.g.) the super-root.
	 */
	if (saveoff == 0) {
		inum = ip->meta.inum & HAMMER2_DIRHASH_USERMSK;
		r = hammer2_write_dirent(uio, inum, DT_DIR, 1, ".", &error);
		if (r)
			goto done;
		if (cookies)
			cookies[cookie_index] = saveoff;
		++saveoff;
		++cookie_index;
		if (cookie_index == ncookies)
			goto done;
	}
	if (error)
		goto done;

	if (saveoff == 1) {
		inum = ip->meta.inum & HAMMER2_DIRHASH_USERMSK;
		if (ip != ip->pmp->iroot)
			inum = ip->meta.iparent & HAMMER2_DIRHASH_USERMSK;
		r = hammer2_write_dirent(uio, inum, DT_DIR, 2, "..", &error);
		if (r)
			goto done;
		if (cookies)
			cookies[cookie_index] = saveoff;
		++saveoff;
		++cookie_index;
		if (cookie_index == ncookies)
			goto done;
	}
	if (error)
		goto done;

	/* Use XOP for remaining entries. */
	xop = hammer2_xop_alloc(ip, 0);
	xop->lkey = saveoff | HAMMER2_DIRHASH_VISIBLE;
	hammer2_xop_start(&xop->head, &hammer2_readdir_desc);

	for (;;) {
		error = hammer2_xop_collect(&xop->head, 0);
		error = hammer2_error_to_errno(error);
		if (error)
			break;
		if (cookie_index == ncookies)
			break;
		hammer2_cluster_bref(&xop->head.cluster, &bref);

		if (bref.type == HAMMER2_BREF_TYPE_INODE) {
			ripdata = &hammer2_xop_gdata(&xop->head)->ipdata;
			dtype = hammer2_get_dtype(ripdata->meta.type);
			saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
			r = hammer2_write_dirent(uio,
			    ripdata->meta.inum & HAMMER2_DIRHASH_USERMSK,
			    dtype, ripdata->meta.name_len, ripdata->filename,
			    &error);
			hammer2_xop_pdata(&xop->head);
			if (r)
				break;
			if (cookies)
				cookies[cookie_index] = saveoff;
			++cookie_index;
		} else if (bref.type == HAMMER2_BREF_TYPE_DIRENT) {
			dtype = hammer2_get_dtype(bref.embed.dirent.type);
			saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
			namlen = bref.embed.dirent.namlen;
			if (namlen <= sizeof(bref.check.buf))
				dname = bref.check.buf;
			else
				dname = hammer2_xop_gdata(&xop->head)->buf;
			r = hammer2_write_dirent(uio, bref.embed.dirent.inum,
			    dtype, namlen, dname, &error);
			if (namlen > sizeof(bref.check.buf))
				hammer2_xop_pdata(&xop->head);
			if (r)
				break;
			if (cookies)
				cookies[cookie_index] = saveoff;
			++cookie_index;
		} else {
			/* XXX chain error */
			hprintf("bad blockref type %d\n", bref.type);
		}
	}
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	if (error == ENOENT) {
		error = 0;
		eofflag = 1;
		saveoff = (hammer2_key_t)-1;
	} else {
		saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
	}
done:
	hammer2_inode_unlock(ip);

	if (ap->a_eofflag)
		*ap->a_eofflag = eofflag;
	/*
	 * XXX uio_offset value of 0x7fffffffffffffff known to not work with
	 * some user space libraries on 32 bit platforms.
	 */
	uio->uio_offset = saveoff & ~HAMMER2_DIRHASH_VISIBLE;

	if (error && cookie_index == 0) {
		if (cookies) {
			free(cookies, M_TEMP);
			*ap->a_ncookies = 0;
			*ap->a_cookies = NULL;
		}
	} else {
		if (cookies) {
			*ap->a_ncookies = cookie_index;
			*ap->a_cookies = cookies;
		}
	}

	return (error);
}

/*
 * Perform read operations on a file or symlink given an unlocked
 * inode and uio.
 */
static int
hammer2_read_file(hammer2_inode_t *ip, struct uio *uio, int ioflag)
{
	struct buf *bp;
	hammer2_off_t isize = ip->meta.size;
	hammer2_key_t lbase;
	daddr_t lbn;
	size_t n;
	int lblksize, loff, error = 0;

	while (uio->uio_resid > 0 && (hammer2_off_t)uio->uio_offset < isize) {
		lblksize = hammer2_calc_logical(ip, uio->uio_offset, &lbase,
		    NULL);
		lbn = lbase / lblksize;
		bp = NULL;

		if ((hammer2_off_t)(lbn + 1) * lblksize >= isize)
			error = bread(ip->vp, lbn, lblksize, 0, &bp);
		else
			error = bread(ip->vp, lbn, lblksize, 0, &bp);
		KKASSERT(error == 0 || bp == NULL);
		if (error) {
			bp = NULL;
			break;
		}

		loff = (int)(uio->uio_offset - lbase);
		n = lblksize - loff;
		if (n > uio->uio_resid)
			n = uio->uio_resid;
		if (n > isize - uio->uio_offset)
			n = (int)(isize - uio->uio_offset);
		error = uiomove((char *)bp->b_data + loff, n, uio);
		if (error) {
			brelse(bp, 0);
			bp = NULL;
			break;
		}
		brelse(bp, 0);
	}

	return (error);
}

static int
hammer2_readlink(void *v)
{
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (vp->v_type != VLNK)
		return (EINVAL);

	return (hammer2_read_file(ip, ap->a_uio, 0));
}

static int
hammer2_read(void *v)
{
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type != VREG)
		return (EINVAL);

	return (hammer2_read_file(ip, ap->a_uio, ap->a_ioflag));
}

static int
hammer2_bmap(void *v)
{
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap = v;
	hammer2_xop_bmap_t *xop;
	hammer2_dev_t *hmp;
	hammer2_inode_t *ip = VTOI(ap->a_vp);
	hammer2_volume_t *vol;
	int error;

	hmp = ip->pmp->pfs_hmps[0];
	if (ap->a_bnp == NULL)
		return (0);
	if (ap->a_runp != NULL)
		*ap->a_runp = 0; /* unsupported */

	/* Initialize with error or nonexistent case first. */
	if (ap->a_vpp != NULL)
		*ap->a_vpp = NULL;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = -1;

	xop = hammer2_xop_alloc(ip, 0);
	xop->lbn = ap->a_bn; /* logical block number */
	hammer2_xop_start(&xop->head, &hammer2_bmap_desc);

	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error) {
		/* No physical block assigned. */
		if (error == ENOENT)
			error = 0;
		goto done;
	}

	if (xop->offset != HAMMER2_OFF_MASK) {
		/* Get volume from the result offset. */
		KKASSERT((xop->offset & HAMMER2_OFF_MASK_RADIX) == 0);
		vol = hammer2_get_volume(hmp, xop->offset);
		KKASSERT(vol);
		KKASSERT(vol->dev);
		KKASSERT(vol->dev->devvp);

		/* Return devvp for this volume. */
		if (ap->a_vpp != NULL)
			*ap->a_vpp = vol->dev->devvp;
		/* Return physical block number within devvp. */
		if (ap->a_bnp != NULL)
			*ap->a_bnp = (xop->offset - vol->offset) / DEV_BSIZE;
	}
done:
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

static int
hammer2_nresolve(void *v)
{
	struct vop_lookup_v2_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct vnode *vp, *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	hammer2_xop_nresolve_t *xop;
	hammer2_inode_t *ip, *dip = VTOI(dvp);
	int error;

	KASSERT(VOP_ISLOCKED(dvp));
	KKASSERT(ap->a_vpp);
	*ap->a_vpp = NULL;

	/* Check accessibility of directory. */
	error = VOP_ACCESS(dvp, VEXEC, cnp->cn_cred);
	if (error)
		return (error);

	if ((cnp->cn_flags & ISLASTCN) &&
	    (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return (EROFS);

	/*
	 * We now have a segment name to search for, and a directory to search.
	 *
	 * Before tediously performing a linear scan of the directory,
	 * check the name cache to see if the directory/name pair
	 * we are looking for is known already.
	 */
	if (cache_lookup(dvp, cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_nameiop,
	    cnp->cn_flags, NULL, ap->a_vpp)) {
		if (*ap->a_vpp == NULLVP)
			return (ENOENT);
		else
			return (0);
	}

	/* May need to restart the lookup with an exclusive lock. */
	if (VOP_ISLOCKED(dvp) != LK_EXCLUSIVE)
		return (ENOLCK);

	/* NetBSD needs "." and ".." handling. */
	if (cnp->cn_flags & ISDOTDOT) {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == RENAME)
			return (EINVAL);
		/* NetBSD requires unlocked vnode. */
		error = VFS_VGET(dip->pmp->mp, dip->meta.iparent, LK_NONE, &vp);
		if (error)
			return (error);
		*ap->a_vpp = vp;
		cache_enter(dvp, vp, cnp->cn_nameptr, cnp->cn_namelen,
		    cnp->cn_flags);
		return (0);
	} else if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == RENAME)
			return (EISDIR);
		vref(dvp); /* We want ourself, i.e. ".". */
		*ap->a_vpp = dvp;
		cache_enter(dvp, dvp, cnp->cn_nameptr, cnp->cn_namelen,
		    cnp->cn_flags);
		return (0);
	}

	xop = hammer2_xop_alloc(dip, 0);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);

	hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);
	hammer2_xop_start(&xop->head, &hammer2_nresolve_desc);

	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error)
		ip = NULL;
	else
		ip = hammer2_inode_get(dip->pmp, &xop->head, -1, -1);
	hammer2_inode_unlock(dip);

	if (ip) {
		/* NetBSD requires unlocked vnode. */
		error = hammer2_igetv(dip->pmp->mp, ip, LK_NONE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			cache_enter(dvp, vp, cnp->cn_nameptr, cnp->cn_namelen,
			    cnp->cn_flags);
		} else if (error == ENOENT) {
			cache_enter(dvp, NULLVP, cnp->cn_nameptr, cnp->cn_namelen,
			    cnp->cn_flags);
		}
		hammer2_inode_unlock(ip);
	} else {
		cache_enter(dvp, NULLVP, cnp->cn_nameptr, cnp->cn_namelen,
		    cnp->cn_flags);
		if ((cnp->cn_flags & ISLASTCN) &&
		    (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME))
			error = EROFS;
		else
			error = ENOENT;
	}
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

static int
hammer2_open(void *v)
{
	struct vop_open_args /* {
		struct vnode *a_vp;
		int a_mode;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp __diagused = ap->a_vp;

	KASSERT(VOP_ISLOCKED(vp));
	return (0);
}

static int
hammer2_close(void *v)
{
	struct vop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp __diagused = ap->a_vp;

	KASSERT(VOP_ISLOCKED(vp));
	return (0);
}

static int
hammer2_ioctl(void *v)
{
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		void *a_data;
		int  a_fflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	hammer2_inode_t *ip = VTOI(ap->a_vp);

	return (hammer2_ioctl_impl(ip, ap->a_command, ap->a_data, ap->a_fflag,
	    ap->a_cred));
}

static int
hammer2_print(void *v)
{
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap = v;
	hammer2_inode_t *ip = VTOI(ap->a_vp);

	printf("tag VT_HAMMER2, ino %ju", (uintmax_t)ip->meta.inum);
	printf("\n");

	return (0);
}

static int
hammer2_pathconf(void *v)
{
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	int error = 0;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = INT_MAX;
		break;
	case _PC_NAME_MAX:
		*ap->a_retval = HAMMER2_INODE_MAXNAME;
		break;
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		break;
	case _PC_PIPE_BUF:
		if (vp->v_type == VDIR || vp->v_type == VFIFO)
			*ap->a_retval = PIPE_BUF;
		else
			error = EINVAL;
		break;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		break;
	case _PC_NO_TRUNC:
		*ap->a_retval = 0;
		break;
	case _PC_MIN_HOLE_SIZE:
		*ap->a_retval = vp->v_mount->mnt_stat.f_iosize;
		break;
	case _PC_SYNC_IO:
		*ap->a_retval = 0;
		break;
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;
		break;
	case _PC_SYMLINK_MAX:
		*ap->a_retval = HAMMER2_INODE_MAXNAME;
		break;
	default:
		error = genfs_pathconf(ap);
		break;
	}

	return (error);
}

/*
 * Initialize the vnode associated with a new inode, handle aliased vnodes.
 */
int
hammer2_vinit(struct mount *mntp, int (**specops)(void *),
    int (**fifoops)(void *), struct vnode **vpp)
{
	struct vnode *vp = *vpp;
	hammer2_inode_t *ip = VTOI(vp);

	vp->v_type = hammer2_get_vtype(ip->meta.type);
	switch (vp->v_type) {
	case VCHR:
	case VBLK:
		vp->v_op = specops;
		spec_node_init(vp, (dev_t)(uintptr_t)vp);
		break;
	case VFIFO:
		vp->v_op = fifoops;
		break;
	case VNON:
	case VBAD:
	case VSOCK:
	case VLNK:
	case VDIR:
	case VREG:
		break;
	default:
		KASSERT(0);
		break;
	}

	if (ip->meta.inum == 1)
                vp->v_vflag |= VV_ROOT;
	*vpp = vp;

	return (0);
}

int (**hammer2_vnodeop_p)(void *);
static const struct vnodeopv_entry_desc hammer2_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_parsepath_desc, genfs_parsepath },	/* parsepath */
	{ &vop_lookup_desc, hammer2_nresolve },		/* lookup */
	{ &vop_create_desc, genfs_eopnotsupp },		/* create */
	{ &vop_mknod_desc, genfs_eopnotsupp },		/* mknod */
	{ &vop_open_desc, hammer2_open },		/* open */
	{ &vop_close_desc, hammer2_close },		/* close */
	{ &vop_access_desc, hammer2_access },		/* access */
	{ &vop_accessx_desc, genfs_accessx },		/* accessx */
	{ &vop_getattr_desc, hammer2_getattr },		/* getattr */
	{ &vop_setattr_desc, hammer2_setattr },		/* setattr */
	{ &vop_read_desc, hammer2_read },		/* read */
	{ &vop_write_desc, genfs_eopnotsupp },		/* write */
	{ &vop_fallocate_desc, genfs_eopnotsupp },	/* fallocate */
	{ &vop_fdiscard_desc, genfs_eopnotsupp },	/* fdiscard */
	{ &vop_fcntl_desc, genfs_fcntl },		/* fcntl */
	{ &vop_ioctl_desc, hammer2_ioctl },		/* ioctl */
	{ &vop_poll_desc, genfs_poll },			/* poll */
	{ &vop_kqfilter_desc, genfs_kqfilter },		/* kqfilter */
	{ &vop_revoke_desc, genfs_revoke },		/* revoke */
	{ &vop_mmap_desc, genfs_mmap },			/* mmap */
	{ &vop_fsync_desc, genfs_nullop },		/* fsync */
	{ &vop_seek_desc, genfs_seek },			/* seek */
	{ &vop_remove_desc, genfs_eopnotsupp },		/* remove */
	{ &vop_link_desc, genfs_erofs_link },		/* link */
	{ &vop_rename_desc, genfs_eopnotsupp },		/* rename */
	{ &vop_mkdir_desc, genfs_eopnotsupp },		/* mkdir */
	{ &vop_rmdir_desc, genfs_eopnotsupp },		/* rmdir */
	{ &vop_symlink_desc, genfs_erofs_symlink },	/* symlink */
	{ &vop_readdir_desc, hammer2_readdir },		/* readdir */
	{ &vop_readlink_desc, hammer2_readlink },	/* readlink */
	{ &vop_abortop_desc, genfs_abortop },		/* abortop */
	{ &vop_inactive_desc, hammer2_inactive },	/* inactive */
	{ &vop_reclaim_desc, hammer2_reclaim },		/* reclaim */
	{ &vop_lock_desc, genfs_lock },			/* lock */
	{ &vop_unlock_desc, genfs_unlock },		/* unlock */
	{ &vop_bmap_desc, hammer2_bmap },		/* bmap */
	{ &vop_strategy_desc, hammer2_strategy },	/* strategy */
	{ &vop_print_desc, hammer2_print },		/* print */
	{ &vop_islocked_desc, genfs_islocked },		/* islocked */
	{ &vop_pathconf_desc, hammer2_pathconf },	/* pathconf */
	{ &vop_advlock_desc, genfs_einval },		/* advlock */
	{ &vop_bwrite_desc, vn_bwrite },		/* bwrite */
	{ &vop_getpages_desc, genfs_getpages },		/* getpages */
	{ &vop_putpages_desc, genfs_putpages },		/* putpages */
	{ NULL, NULL }
};
const struct vnodeopv_desc hammer2_vnodeop_opv_desc =
	{ &hammer2_vnodeop_p, hammer2_vnodeop_entries };

int (**hammer2_specop_p)(void *);
const struct vnodeopv_entry_desc hammer2_specop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	GENFS_SPECOP_ENTRIES,
	{ &vop_close_desc, spec_close },		/* close */
	{ &vop_access_desc, hammer2_access },		/* access */
	{ &vop_accessx_desc, genfs_accessx },		/* accessx */
	{ &vop_getattr_desc, hammer2_getattr },		/* getattr */
	{ &vop_setattr_desc, hammer2_setattr },		/* setattr */
	{ &vop_read_desc, spec_read },			/* read */
	{ &vop_write_desc, spec_write },		/* write */
	{ &vop_fcntl_desc, genfs_fcntl },		/* fcntl */
	{ &vop_fsync_desc, spec_fsync },		/* fsync */
	{ &vop_inactive_desc, hammer2_inactive },	/* inactive */
	{ &vop_reclaim_desc, hammer2_reclaim },		/* reclaim */
	{ &vop_lock_desc, genfs_lock },			/* lock */
	{ &vop_unlock_desc, genfs_unlock },		/* unlock */
	{ &vop_print_desc, hammer2_print },		/* print */
	{ &vop_islocked_desc, genfs_islocked },		/* islocked */
	{ &vop_bwrite_desc, vn_bwrite },		/* bwrite */
	{ NULL, NULL }
};
const struct vnodeopv_desc hammer2_specop_opv_desc =
	{ &hammer2_specop_p, hammer2_specop_entries };

int (**hammer2_fifoop_p)(void *);
const struct vnodeopv_entry_desc hammer2_fifoop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	GENFS_FIFOOP_ENTRIES,
	{ &vop_close_desc, vn_fifo_bypass },		/* close */
	{ &vop_access_desc, hammer2_access },		/* access */
	{ &vop_accessx_desc, genfs_accessx },		/* accessx */
	{ &vop_getattr_desc, hammer2_getattr },		/* getattr */
	{ &vop_setattr_desc, hammer2_setattr },		/* setattr */
	{ &vop_read_desc, vn_fifo_bypass },		/* read */
	{ &vop_write_desc, vn_fifo_bypass },		/* write */
	{ &vop_fcntl_desc, genfs_fcntl },		/* fcntl */
	{ &vop_fsync_desc, vn_fifo_bypass },		/* fsync */
	{ &vop_inactive_desc, hammer2_inactive },	/* inactive */
	{ &vop_reclaim_desc, hammer2_reclaim },		/* reclaim */
	{ &vop_lock_desc, genfs_lock },			/* lock */
	{ &vop_unlock_desc, genfs_unlock },		/* unlock */
	{ &vop_strategy_desc, vn_fifo_bypass },		/* strategy */
	{ &vop_print_desc, hammer2_print },		/* print */
	{ &vop_islocked_desc, genfs_islocked },		/* islocked */
	{ &vop_bwrite_desc, vn_bwrite },		/* bwrite */
	{ NULL, NULL }
};
const struct vnodeopv_desc hammer2_fifoop_opv_desc =
	{ &hammer2_fifoop_p, hammer2_fifoop_entries };
