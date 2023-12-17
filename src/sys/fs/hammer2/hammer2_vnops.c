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

#include <uvm/uvm_extern.h>

static void hammer2_truncate_file(hammer2_inode_t *, hammer2_key_t);
static void hammer2_extend_file(hammer2_inode_t *, hammer2_key_t);

static int
hammer2_inactive(void *v)
{
	struct vop_inactive_v2_args /* {
		struct vnode *a_vp;
		bool *a_recycle;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	/* degenerate case */
	if (ip->meta.mode == 0) {
		/*
		 * If we are done with the inode, reclaim it
		 * so that it can be reused immediately.
		 */
		*ap->a_recycle = true;
		return (0);
	}

	/*
	 * Aquire the inode lock to interlock against vp updates via
	 * the inode path and file deletions and such (which can be
	 * namespace-only operations that might not hold the vnode).
	 */
	hammer2_inode_lock(ip, 0);
	if (ip->flags & HAMMER2_INODE_ISUNLINKED) {
		/*
		 * If the inode has been unlinked we can throw away all
		 * buffers (dirty or not) and clean the file out.
		 *
		 * Because vrecycle() calls are not guaranteed, try to
		 * dispose of the inode as much as possible right here.
		 */
		uvm_vnp_setsize(vp, 0);
		vtruncbuf(vp, 0, 0, 0); /* NetBSD doesn't take blksize */

		/* Delete the file on-media. */
		if ((ip->flags & HAMMER2_INODE_DELETING) == 0) {
			atomic_set_int(&ip->flags, HAMMER2_INODE_DELETING);
			hammer2_inode_delayed_sideq(ip);
		}
		hammer2_inode_unlock(ip);

		/* Recycle immediately if possible. */
		*ap->a_recycle = true;
	} else {
		hammer2_inode_unlock(ip);
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

	if (ip == NULL)
		return (0);

	/* The inode lock is required to disconnect it. */
	hammer2_inode_lock(ip, 0);

	VOP_UNLOCK(vp);

	genfs_node_destroy(vp);

	vp->v_data = NULL;
	ip->vp = NULL;

	/*
	 * Delete the file on-media.  This should have been handled by the
	 * inactivation.  The operation is likely still queued on the inode
	 * though so only complain if the stars don't align.
	 */
	if ((ip->flags & (HAMMER2_INODE_ISUNLINKED | HAMMER2_INODE_DELETING)) ==
	    HAMMER2_INODE_ISUNLINKED) {
		atomic_set_int(&ip->flags, HAMMER2_INODE_DELETING);
		hammer2_inode_delayed_sideq(ip);
		hprintf("inum %016jx unlinked but not disposed\n",
		    (intmax_t)ip->meta.inum);
	}
	hammer2_inode_unlock(ip);

	/*
	 * Modified inodes will already be on SIDEQ or SYNCQ, no further
	 * action is needed.
	 *
	 * We cannot safely synchronize the inode from inside the reclaim
	 * due to potentially deep locks held as-of when the reclaim occurs.
	 * Interactions and potential deadlocks abound.  We also can't do it
	 * here without desynchronizing from the related directory entrie(s).
	 */
	hammer2_inode_drop(ip); /* vp ref */

	/*
	 * XXX handle background sync when ip dirty, kernel will no longer
	 * notify us regarding this inode because there is no longer a
	 * vnode attached to it.
	 */
	return (0);
}

/*
 * Currently this function synchronizes the front-end inode state to the
 * backend chain topology, then flushes the inode's chain and sub-topology
 * to backend media.  This function does not flush the root topology down to
 * the inode.
 */
static int
hammer2_fsync(void *v)
{
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		kauth_cred_t a_cred;
		int a_flags;
		off_t a_offlo;
		off_t a_offhi;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);
	int error1 = 0, error2;

	hammer2_trans_init(ip->pmp, 0);

	/*
	 * Flush dirty buffers in the file's logical buffer cache.
	 * It is best to wait for the strategy code to commit the
	 * buffers to the device's backing buffer cache before
	 * then trying to flush the inode.
	 *
	 * This should be quick, but certain inode modifications cached
	 * entirely in the hammer2_inode structure may not trigger a
	 * buffer read until the flush so the fsync can wind up also
	 * doing scattered reads.
	 */
	if (vp->v_type == VBLK)
		error1 = spec_fsync(v);
	else
		error1 = vflushbuf(vp, ap->a_flags);
	if (error1)
		goto fail;

	/* Flush any inode changes. */
	hammer2_inode_lock(ip, 0);
	if (ip->flags & (HAMMER2_INODE_RESIZED|HAMMER2_INODE_MODIFIED))
		error1 = hammer2_inode_chain_sync(ip);

	/*
	 * Flush dirty chains related to the inode.
	 *
	 * NOTE! We are not in a flush transaction.  The inode remains on
	 *	 the sideq so the filesystem syncer can synchronize it to
	 *	 the volume root.
	 */
	error2 = hammer2_inode_chain_flush(ip, HAMMER2_XOP_INODE_STOP);
	if (error2)
		error1 = error2;

	hammer2_inode_unlock(ip);
fail:
	hammer2_trans_done(ip->pmp, 0);

	return (error1);
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
	//bzero(&vap->va_birthtime, sizeof(vap->va_birthtime));
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
	kauth_cred_t cred = ap->a_cred;
	struct uuid uuid_uid, uuid_gid;
	hammer2_inode_t *ip = VTOI(vp);
	mode_t mode;
	gid_t uid, gid;
	uint64_t ctime;
	int error = 0;

	hammer2_update_time(&ctime);

	if (ip->pmp->rdonly)
		return (EROFS);
	/*
	 * Normally disallow setattr if there is no space, unless we
	 * are in emergency mode (might be needed to chflags -R noschg
	 * files prior to removal).
	 */
	if ((ip->pmp->flags & HAMMER2_PMPF_EMERG) == 0 &&
	    hammer2_vfs_enospace(ip, 0, cred) > 1)
		return (ENOSPC);

	if (vap->va_type != VNON ||
	    vap->va_nlink != (nlink_t)VNOVAL ||
	    vap->va_fsid != (dev_t)VNOVAL ||
	    vap->va_fileid != (ino_t)VNOVAL ||
	    vap->va_blocksize != (long)VNOVAL ||
	    vap->va_rdev != (dev_t)VNOVAL ||
	    vap->va_bytes != (u_quad_t)VNOVAL ||
	    vap->va_gen != (u_long)VNOVAL)
		return (EINVAL);

	hammer2_trans_init(ip->pmp, 0);
	hammer2_inode_lock(ip, 0);

	mode = ip->meta.mode;
	uid = hammer2_to_unix_xid(&ip->meta.uid);
	gid = hammer2_to_unix_xid(&ip->meta.gid);

	if (vap->va_flags != (u_long)VNOVAL) {
		if (vap->va_flags & ~(SF_APPEND | SF_IMMUTABLE | UF_NODUMP)) {
			error = EOPNOTSUPP;
			goto done;
		}
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_FLAGS, vp,
		    NULL, genfs_can_chflags(vp, cred, uid, false));
		if (error)
			goto done;

		if (ip->meta.uflags != vap->va_flags) {
			hammer2_inode_modify(ip);
			hammer2_spin_ex(&ip->cluster_spin);
			ip->meta.uflags = vap->va_flags;
			ip->meta.ctime = ctime;
			hammer2_spin_unex(&ip->cluster_spin);
		}
		if (ip->meta.uflags & (IMMUTABLE | APPEND))
			goto done;
	}
	if (ip->meta.uflags & (IMMUTABLE | APPEND)) {
		error = EPERM;
		goto done;
	}

	if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
		if (vap->va_uid == (uid_t)VNOVAL)
			vap->va_uid = uid;
		if (vap->va_gid == (gid_t)VNOVAL)
			vap->va_gid = gid;
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_CHANGE_OWNERSHIP,
		    vp, NULL, genfs_can_chown(vp, cred, uid, gid, vap->va_uid,
		    vap->va_gid));
		if (error)
			goto done;
		if (uid != vap->va_uid && (mode & S_ISUID) &&
		    kauth_authorize_vnode(cred, KAUTH_VNODE_RETAIN_SUID, vp,
		    NULL, EPERM) != 0)
			mode &= ~S_ISUID;
		if (gid != vap->va_gid && (mode & S_ISGID) &&
		    kauth_authorize_vnode(cred, KAUTH_VNODE_RETAIN_SGID, vp,
		    NULL, EPERM) != 0)
			mode &= ~S_ISGID;

		hammer2_guid_to_uuid(&uuid_uid, vap->va_uid);
		hammer2_guid_to_uuid(&uuid_gid, vap->va_gid);
		if (bcmp(&uuid_uid, &ip->meta.uid, sizeof(uuid_uid)) ||
		    bcmp(&uuid_gid, &ip->meta.gid, sizeof(uuid_gid)) ||
		    ip->meta.mode != mode) {
			hammer2_inode_modify(ip);
			hammer2_spin_ex(&ip->cluster_spin);
			ip->meta.uid = uuid_uid;
			ip->meta.gid = uuid_gid;
			ip->meta.mode = mode;
			ip->meta.ctime = ctime;
			hammer2_spin_unex(&ip->cluster_spin);
		}
	}

	if (vap->va_size != (u_quad_t)VNOVAL && ip->meta.size != vap->va_size) {
		switch (vp->v_type) {
		case VLNK:
		case VREG:
			if (vap->va_size == ip->meta.size)
				break;
			if (vap->va_size < ip->meta.size) {
				hammer2_mtx_ex(&ip->truncate_lock);
				hammer2_truncate_file(ip, vap->va_size);
				hammer2_mtx_unlock(&ip->truncate_lock);
			} else {
				hammer2_extend_file(ip, vap->va_size);
			}
			hammer2_inode_modify(ip);
			ip->meta.mtime = ctime;
			break;
		case VDIR:
			error = EISDIR;
			goto done;
		default:
			/*
			 * According to POSIX, the result is unspecified
			 * for file types other than regular files,
			 * directories and shared memory objects.  We
			 * don't support shared memory objects in the file
			 * system, and have dubious support for truncating
			 * symlinks.  Just ignore the request in other cases.
			 *
			 * Note that DragonFly HAMMER2 returns EINVAL for
			 * anything but VREG.
			 */
			break;
		}
	}

	if (vap->va_mode != (mode_t)VNOVAL) {
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_SECURITY,
		    vp, NULL, genfs_can_chmod(vp, cred, uid, gid, mode));
		if (error)
			goto done;

		mode &= ~ALLPERMS;
		mode |= vap->va_mode & ALLPERMS;
		if (ip->meta.mode != mode) {
			hammer2_inode_modify(ip);
			hammer2_spin_ex(&ip->cluster_spin);
			ip->meta.mode = mode;
			ip->meta.ctime = ctime;
			hammer2_spin_unex(&ip->cluster_spin);
		}
	}

	/* DragonFly HAMMER2 doesn't support atime either. */
	if (vap->va_mtime.tv_sec != (time_t)VNOVAL) {
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_TIMES, vp,
		    NULL, genfs_can_chtimes(vp, cred, uid, vap->va_vaflags));
		if (error)
			goto done;

		hammer2_inode_modify(ip);
		ip->meta.mtime = hammer2_timespec_to_time(&vap->va_mtime);
	}
done:
	/*
	 * If a truncation occurred we must call chain_sync() now in order
	 * to trim the related data chains, otherwise a later expansion can
	 * cause havoc.
	 *
	 * If an extend occured that changed the DIRECTDATA state, we must
	 * call inode_chain_sync now in order to prepare the inode's indirect
	 * block table.
	 *
	 * WARNING! This means we are making an adjustment to the inode's
	 * chain outside of sync/fsync, and not just to inode->meta, which
	 * may result in some consistency issues if a crash were to occur
	 * at just the wrong time.
	 */
	if (ip->flags & HAMMER2_INODE_RESIZED)
		hammer2_inode_chain_sync(ip);

	hammer2_inode_unlock(ip);
	hammer2_trans_done(ip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
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
		cookies = hmalloc(ncookies * sizeof(off_t), M_TEMP, M_WAITOK);
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
			hfree(cookies, M_TEMP, ncookies * sizeof(off_t));
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
 *
 * The passed ip is not locked.
 */
static int
hammer2_read_file(hammer2_inode_t *ip, struct uio *uio, int ioflag)
{
	struct vnode *vp = ip->vp;
	struct buf *bp;
	hammer2_off_t isize;
	hammer2_key_t lbase;
	daddr_t lbn;
	size_t n;
	int lblksize, loff, error = 0;

	KKASSERT(uio->uio_rw == UIO_READ);
	KKASSERT(uio->uio_offset >= 0);
	KKASSERT(uio->uio_resid >= 0);

	/*
	 * UIO read loop.
	 *
	 * WARNING! Assumes that the kernel interlocks size changes at the
	 *	    vnode level.
	 */
	hammer2_mtx_sh(&ip->lock);
	hammer2_mtx_sh(&ip->truncate_lock);
	isize = ip->meta.size;
	hammer2_mtx_unlock(&ip->lock);

	while (uio->uio_resid > 0 && (hammer2_off_t)uio->uio_offset < isize) {
		lblksize = hammer2_calc_logical(ip, uio->uio_offset, &lbase,
		    NULL);
		KKASSERT(lblksize <= MAXBSIZE);
		lbn = lbase / lblksize;
		error = bread(vp, lbn, lblksize, 0, &bp);
		KKASSERT(error == 0 || bp == NULL);
		if (error)
			break;
		loff = (int)(uio->uio_offset - lbase);
		n = lblksize - loff;
		if (n > uio->uio_resid)
			n = uio->uio_resid;
		if (n > isize - uio->uio_offset)
			n = (int)(isize - uio->uio_offset);
		error = uiomove((char *)bp->b_data + loff, n, uio);
		if (error) {
			brelse(bp, 0);
			break;
		}
		brelse(bp, 0);
	}
	hammer2_mtx_unlock(&ip->truncate_lock);

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

/*
 * Write to the file represented by the inode via the logical buffer cache.
 * The inode may represent a regular file or a symlink.
 *
 * The inode must not be locked.
 */
static int
hammer2_write_file(hammer2_inode_t *ip, struct uio *uio, int ioflag)
{
	struct vnode *vp = ip->vp;
	struct buf *bp;
	hammer2_key_t old_eof, new_eof, lbase;
	daddr_t lbn;
	size_t n;
	int lblksize, loff, trivial, endofblk;
	int modified = 0, error = 0;
	int async = vp->v_mount->mnt_flag & MNT_ASYNC;

	KKASSERT(uio->uio_rw == UIO_WRITE);
	KKASSERT(uio->uio_offset >= 0);
	KKASSERT(uio->uio_resid >= 0);

	/*
	 * Setup if append.
	 *
	 * WARNING! Assumes that the kernel interlocks size changes at the
	 *	    vnode level.
	 */
	hammer2_mtx_ex(&ip->lock);
	hammer2_mtx_sh(&ip->truncate_lock);
	if (ioflag & IO_APPEND)
		uio->uio_offset = ip->meta.size;
	old_eof = ip->meta.size;

	/*
	 * Extend the file if necessary.  If the write fails at some point
	 * we will truncate it back down to cover as much as we were able
	 * to write.
	 *
	 * Doing this now makes it easier to calculate buffer sizes in
	 * the loop.
	 */
	if (uio->uio_offset + uio->uio_resid > old_eof) {
		new_eof = uio->uio_offset + uio->uio_resid;
		modified = 1;
		hammer2_extend_file(ip, new_eof);
	} else {
		new_eof = old_eof;
	}
	hammer2_mtx_unlock(&ip->lock);

	/* UIO write loop. */
	while (uio->uio_resid > 0) {
		/*
		 * This nominally tells us how much we can cluster and
		 * what the logical buffer size needs to be.  Currently
		 * we don't try to cluster the write and just handle one
		 * block at a time.
		 */
		lblksize = hammer2_calc_logical(ip, uio->uio_offset, &lbase,
		    NULL);
		KKASSERT(lblksize <= MAXBSIZE);
		lbn = lbase / lblksize;
		loff = (int)(uio->uio_offset - lbase);

		/*
		 * Calculate bytes to copy this transfer and whether the
		 * copy completely covers the buffer or not.
		 */
		trivial = 0;
		n = lblksize - loff;
		if (n > uio->uio_resid) {
			n = uio->uio_resid;
			if (((hammer2_key_t)loff == lbase) &&
			    (uio->uio_offset + n == new_eof))
				trivial = 1;
			endofblk = 0;
		} else {
			if (loff == 0)
				trivial = 1;
			endofblk = 1;
		}
		if (lbase >= new_eof)
			trivial = 1;

		/* Get the buffer. */
		if (trivial) {
			/*
			 * Even though we are entirely overwriting the buffer
			 * we may still have to zero it out to avoid a
			 * mmap/write visibility issue.
			 */
			bp = getblk(vp, lbn, lblksize, 0, 0);
			if (1 /*(bp->b_flags & B_CACHE) == 0*/)
				clrbuf(bp);
		} else {
			/*
			 * Partial overwrite, read in any missing bits then
			 * replace the portion being written.
			 *
			 * (The strategy code will detect zero-fill physical
			 * blocks for this case).
			 */
			error = bread(vp, lbn, lblksize, 0, &bp);
		}
		if (error)
			break;

		/* Ok, copy the data in. */
		error = uiomove((char *)bp->b_data + loff, n, uio);
		modified = 1;
		if (error) {
			brelse(bp, 0);
			break;
		}

		/*
		 * WARNING: Pageout daemon will issue UIO_NOCOPY writes
		 *	    with IO_SYNC or IO_ASYNC set.  These writes
		 *	    must be handled as the pageout daemon expects.
		 *
		 * NOTE!    H2 relies on cluster_write() here because it
		 *	    cannot preallocate disk blocks at the logical
		 *	    level due to not knowing what the compression
		 *	    size will be at this time.
		 *
		 *	    We must use cluster_write() here and we depend
		 *	    on the write-behind feature to flush buffers
		 *	    appropriately.  If we let the buffer daemons do
		 *	    it the block allocations will be all over the
		 *	    map.
		 */
		/* No cluster_write() in NetBSD. */
		if (ioflag & IO_SYNC)
			bwrite(bp);
		else if ((ioflag & IO_DIRECT) && endofblk)
			bawrite(bp);
		else if (async)
			bawrite(bp);
		else
			bawrite(bp); /* XXX chlock: originally bdwrite */
	}

	/*
	 * Cleanup.  If we extended the file EOF but failed to write through
	 * the entire write is a failure and we have to back-up.
	 */
	if (error && new_eof != old_eof) {
		hammer2_mtx_unlock(&ip->truncate_lock);
		hammer2_mtx_ex(&ip->lock); /* note lock order */
		hammer2_mtx_ex(&ip->truncate_lock); /* note lock order */
		hammer2_truncate_file(ip, old_eof);
		if (ip->flags & HAMMER2_INODE_MODIFIED)
			hammer2_inode_chain_sync(ip);
		hammer2_mtx_unlock(&ip->lock);
	} else if (modified) {
		hammer2_mtx_ex(&ip->lock);
		hammer2_inode_modify(ip);
		hammer2_update_time(&ip->meta.mtime);
		hammer2_mtx_unlock(&ip->lock);
	}
	hammer2_trans_assert_strategy(ip->pmp);
	hammer2_mtx_unlock(&ip->truncate_lock);

	return (error);
}

static int
hammer2_write(void *v)
{
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	hammer2_inode_t *ip = VTOI(vp);
	int error, ioflag = ap->a_ioflag;
#ifndef HAMMER2_WRITE
	return (EOPNOTSUPP);
#endif
	if (vp->v_type != VREG)
		return (EINVAL);

	if (ip->pmp->rdonly || (ip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	switch (hammer2_vfs_enospace(ip, uio->uio_resid, ap->a_cred)) {
	case 2:
		return (ENOSPC);
	case 1:
		ioflag |= IO_DIRECT; /* semi-synchronous */
		break;
	default:
		break;
	}

	/*
	 * The transaction interlocks against flush initiations
	 * (note: but will run concurrently with the actual flush).
	 *
	 * To avoid deadlocking against the VM system, we must flag any
	 * transaction related to the buffer cache or other direct
	 * VM page manipulation.
	 */
	if (0)
		hammer2_trans_init(ip->pmp, HAMMER2_TRANS_BUFCACHE);
	else
		hammer2_trans_init(ip->pmp, 0);
	error = hammer2_write_file(ip, uio, ioflag);
	if (0)
		hammer2_trans_done(ip->pmp,
		    HAMMER2_TRANS_BUFCACHE | HAMMER2_TRANS_SIDEQ);
	else
		hammer2_trans_done(ip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

/*
 * Truncate the size of a file.  The inode must be locked.
 *
 * We must unconditionally set HAMMER2_INODE_RESIZED to properly
 * ensure that any on-media data beyond the new file EOF has been destroyed.
 *
 * WARNING: nvtruncbuf() can only be safely called without the inode lock
 *	    held due to the way our write thread works.  If the truncation
 *	    occurs in the middle of a buffer, nvtruncbuf() is responsible
 *	    for dirtying that buffer and zeroing out trailing bytes.
 *
 * WARNING! Assumes that the kernel interlocks size changes at the
 *	    vnode level.
 *
 * WARNING! Caller assumes responsibility for removing dead blocks
 *	    if INODE_RESIZED is set.
 */
static void
hammer2_truncate_file(hammer2_inode_t *ip, hammer2_key_t nsize)
{
	hammer2_mtx_assert_locked(&ip->lock);

	hammer2_mtx_unlock(&ip->lock);
	if (ip->vp)
		vtruncbuf(ip->vp, howmany(nsize, hammer2_get_logical()), 0, 0);
	hammer2_mtx_ex(&ip->lock);
	KKASSERT((ip->flags & HAMMER2_INODE_RESIZED) == 0);
	ip->osize = ip->meta.size;
	ip->meta.size = nsize;
	atomic_set_int(&ip->flags, HAMMER2_INODE_RESIZED);
	hammer2_inode_modify(ip);
}

/*
 * Extend the size of a file.  The inode must be locked.
 *
 * Even though the file size is changing, we do not have to set the
 * INODE_RESIZED bit unless the file size crosses the EMBEDDED_BYTES
 * boundary.  When this occurs a hammer2_inode_chain_sync() is required
 * to prepare the inode cluster's indirect block table, otherwise
 * async execution of the strategy code will implode on us.
 *
 * WARNING! Assumes that the kernel interlocks size changes at the
 *	    vnode level.
 *
 * WARNING! Caller assumes responsibility for transitioning out
 *	    of the inode DIRECTDATA mode if INODE_RESIZED is set.
 */
static void
hammer2_extend_file(hammer2_inode_t *ip, hammer2_key_t nsize)
{
	hammer2_key_t osize;
	struct buf *bp;
	int error;

	hammer2_mtx_assert_locked(&ip->lock);

	KKASSERT((ip->flags & HAMMER2_INODE_RESIZED) == 0);
	osize = ip->meta.size;

	hammer2_inode_modify(ip);
	ip->osize = osize;
	ip->meta.size = nsize;

	/*
	 * We must issue a chain_sync() when the DIRECTDATA state changes
	 * to prevent confusion between the flush code and the in-memory
	 * state.  This is not perfect because we are doing it outside of
	 * a sync/fsync operation, so it might not be fully synchronized
	 * with the meta-data topology flush.
	 *
	 * We must retain and re-dirty the buffer cache buffer containing
	 * the direct data so it can be written to a real block.  It should
	 * not be possible for a bread error to occur since the original data
	 * is extracted from the inode structure directly.
	 */
	if (osize <= HAMMER2_EMBEDDED_BYTES && nsize > HAMMER2_EMBEDDED_BYTES) {
		if (osize) {
			error = bread(ip->vp, 0, hammer2_get_logical(), 0, &bp);
			atomic_set_int(&ip->flags, HAMMER2_INODE_RESIZED);
			hammer2_inode_chain_sync(ip);
			if (error == 0)
				bawrite(bp); /* XXX chlock: originally bdwrite */
		} else {
			atomic_set_int(&ip->flags, HAMMER2_INODE_RESIZED);
			hammer2_inode_chain_sync(ip);
		}
	}
	hammer2_mtx_unlock(&ip->lock);
	if (ip->vp) {
		uvm_vnp_setsize(ip->vp, nsize);
		uvm_vnp_setwritesize(ip->vp, nsize);
	}
	hammer2_mtx_ex(&ip->lock);
}

/*
 * While bmap implementation itself works, HAMMER2 needs to force VFS to invoke
 * logical vnode strategy (rather than device vnode strategy) unless compression
 * type is set to none.
 */
static int use_nop_bmap = 1;

static __inline int
hammer2_nop_bmap(void *v)
{
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap = v;

	if (ap->a_vpp != NULL)
		*ap->a_vpp = ap->a_vp;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = ap->a_bn;
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;

	return (0);
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

	if (use_nop_bmap)
		return (hammer2_nop_bmap(v));

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
	struct componentname *cnp = ap->a_cnp;
	struct vnode *vp, *dvp = ap->a_dvp;
	kauth_cred_t cred = cnp->cn_cred;
	hammer2_xop_nresolve_t *xop;
	hammer2_inode_t *ip, *dip = VTOI(dvp);
	int nameiop, error;

	KASSERT(VOP_ISLOCKED(dvp));
	KKASSERT(ap->a_vpp);
	*ap->a_vpp = NULL;

	nameiop = cnp->cn_nameiop;

	/* Check accessibility of directory. */
	error = VOP_ACCESS(dvp, VEXEC, cred);
	if (error)
		return (error);

	if ((cnp->cn_flags & ISLASTCN) &&
	    (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
	    (nameiop == DELETE || nameiop == RENAME))
		return (EROFS);

	/*
	 * We now have a segment name to search for, and a directory to search.
	 *
	 * Before tediously performing a linear scan of the directory,
	 * check the name cache to see if the directory/name pair
	 * we are looking for is known already.
	 */
	if (cache_lookup(dvp, cnp->cn_nameptr, cnp->cn_namelen, nameiop,
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
		if ((cnp->cn_flags & ISLASTCN) && nameiop == RENAME)
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
		if ((cnp->cn_flags & ISLASTCN) && nameiop == RENAME)
			return (EISDIR);
		vref(dvp); /* we want ourself, ie "." */
		*ap->a_vpp = dvp;
		cache_enter(dvp, dvp, cnp->cn_nameptr, cnp->cn_namelen,
		    cnp->cn_flags);
		return (0);
	}

	hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);
	xop = hammer2_xop_alloc(dip, 0);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);
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
		error = hammer2_igetv(ip, LK_NONE, &vp);
		if (error == 0) {
			if (nameiop == DELETE && (cnp->cn_flags & ISLASTCN)) {
				error = VOP_ACCESS(dvp, VWRITE, cred);
				if (error) {
					vrele(vp);
					hammer2_inode_unlock(ip);
					goto out;
				}
				*ap->a_vpp = vp;
			} else if (nameiop == RENAME &&
			    (cnp->cn_flags & ISLASTCN)) {
				error = VOP_ACCESS(dvp, VWRITE, cred);
				if (error) {
					vrele(vp);
					hammer2_inode_unlock(ip);
					goto out;
				}
				*ap->a_vpp = vp;
			} else {
				*ap->a_vpp = vp;
				cache_enter(dvp, vp, cnp->cn_nameptr,
				    cnp->cn_namelen, cnp->cn_flags);
			}
		}
		hammer2_inode_unlock(ip);
	} else {
		if ((nameiop == CREATE || nameiop == RENAME) &&
		    (cnp->cn_flags & ISLASTCN)) {
			error = VOP_ACCESS(dvp, VWRITE, cred);
			if (error)
				goto out;
			error = EJUSTRETURN;
		} else {
			if (nameiop != CREATE)
				cache_enter(dvp, NULLVP, cnp->cn_nameptr,
				    cnp->cn_namelen, cnp->cn_flags);
			error = ENOENT;
		}
	}
out:
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

static int
hammer2_mknod(void *v)
{
	struct vop_mknod_v3_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * Create the device inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 * NetBSD VFS wants filesystem to use vcache_new() here.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			cache_enter(dvp, vp, cnp->cn_nameptr, cnp->cn_namelen,
			    cnp->cn_flags);
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	vp = *ap->a_vpp;
	if (error) {
		if (vp)
			vput(vp);
	} else {
		if (vp)
			VOP_UNLOCK(vp);
	}
	return (error);
}

static int
hammer2_mkdir(void *v)
{
	struct vop_mkdir_v3_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * Create the directory inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 * NetBSD VFS wants filesystem to use vcache_new() here.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			cache_enter(dvp, vp, cnp->cn_nameptr, cnp->cn_namelen,
			    cnp->cn_flags);
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	vp = *ap->a_vpp;
	if (error) {
		if (vp)
			vput(vp);
	} else {
		if (vp)
			VOP_UNLOCK(vp);
	}
	return (error);
}

static int
hammer2_create(void *v)
{
	struct vop_create_v3_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * Create the regular file inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 * NetBSD VFS wants filesystem to use vcache_new() here.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			cache_enter(dvp, vp, cnp->cn_nameptr, cnp->cn_namelen,
			    cnp->cn_flags);
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	vp = *ap->a_vpp;
	if (error) {
		if (vp)
			vput(vp);
	} else {
		if (vp)
			VOP_UNLOCK(vp);
	}
	return (error);
}

static int
hammer2_rmdir(void *v)
{
	struct vop_rmdir_v2_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *dip = VTOI(dvp), *ip;
	hammer2_xop_unlink_t *xop;
	uint64_t mtime;
	int error;

	/* No rmdir "." please. */
	if (dvp == vp) {
		vrele(vp);
		return (EINVAL);
	}

	if (dip->pmp->rdonly) {
		vrele(vp);
		return (EROFS);
	}

	/* DragonFly has this disabled, see 568c02c60c. */
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1) {
		vrele(vp);
		return (ENOSPC);
	}

	hammer2_trans_init(dip->pmp, 0);
	hammer2_inode_lock(dip, 0);

	xop = hammer2_xop_alloc(dip, HAMMER2_XOP_MODIFYING);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);
	xop->isdir = 1;
	xop->dopermanent = 0;
	hammer2_xop_start(&xop->head, &hammer2_unlink_desc);
	/*
	 * Collect the real inode and adjust nlinks, destroy the real
	 * inode if nlinks transitions to 0 and it was the real inode
	 * (else it has already been removed).
	 */
	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error == 0) {
		ip = hammer2_inode_get(dip->pmp, &xop->head, -1, -1);
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		if (ip) {
			/*
			 * Note that ->a_vp isn't provided in DragonFly,
			 * hence vprecycle.
			 */
			KKASSERT(ip->vp == vp);
			hammer2_inode_unlink_finisher(ip, NULL);
			hammer2_inode_depend(dip, ip); /* after modified */
			hammer2_inode_unlock(ip);
		}
	} else {
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	if (error == 0) {
		cache_purge(dvp);
		cache_purge(vp);
	}

	vput(vp);
	return (error);
}

static int
hammer2_remove(void *v)
{
	struct vop_remove_v3_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		nlink_t ctx_vp_new_nlink;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *dip = VTOI(dvp), *ip;
	hammer2_xop_unlink_t *xop;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly) {
		vrele(vp);
		return (EROFS);
	}

	/* DragonFly has this disabled, see 568c02c60c. */
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1) {
		vrele(vp);
		return (ENOSPC);
	}

	hammer2_trans_init(dip->pmp, 0);
	hammer2_inode_lock(dip, 0);

	xop = hammer2_xop_alloc(dip, HAMMER2_XOP_MODIFYING);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);
	xop->isdir = 0;
	xop->dopermanent = 0;
	hammer2_xop_start(&xop->head, &hammer2_unlink_desc);
	/*
	 * Collect the real inode and adjust nlinks, destroy the real
	 * inode if nlinks transitions to 0 and it was the real inode
	 * (else it has already been removed).
	 */
	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error == 0) {
		ip = hammer2_inode_get(dip->pmp, &xop->head, -1, -1);
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		if (ip) {
			/*
			 * Note that ->a_vp isn't provided in DragonFly,
			 * hence vprecycle.
			 */
			KKASSERT(ip->vp == vp);
			hammer2_inode_unlink_finisher(ip, NULL);
			hammer2_inode_depend(dip, ip); /* after modified */
			hammer2_inode_unlock(ip);
		}
	} else {
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	if (dvp == vp)
		vrele(vp);
	else
		vput(vp);
	return (error);
}

static int
hammer2_rename(void *v)
{
	struct vop_rename_args /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
	} */ *ap = v;
	struct componentname *fcnp = ap->a_fcnp;
	struct componentname *tcnp = ap->a_tcnp;
	struct vnode *fdvp = ap->a_fdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *tvp = ap->a_tvp;
	hammer2_inode_t *fdip = VTOI(fdvp); /* source directory */
	hammer2_inode_t *fip = VTOI(fvp); /* file being renamed */
	hammer2_inode_t *tdip = VTOI(tdvp); /* target directory */
	hammer2_inode_t *tip; /* replaced target during rename or NULL */
	hammer2_inode_t *ip1, *ip2, *ip3, *ip4;
	hammer2_xop_scanlhc_t *sxop;
	hammer2_xop_nrename_t *xop4;
	hammer2_key_t tlhc, lhcbase;
	uint64_t mtime;
	int error, update_fdip = 0, update_tdip = 0;

	KKASSERT(fdvp != fvp);
	KKASSERT(tdvp != tvp); /* if not how ? */

	KKASSERT(fdvp == tdvp || VOP_ISLOCKED(fdvp) == 0);
	KKASSERT(VOP_ISLOCKED(fvp) == 0);
	KKASSERT(VOP_ISLOCKED(tdvp) == LK_EXCLUSIVE);
	KKASSERT(tvp == NULL || VOP_ISLOCKED(tvp) == LK_EXCLUSIVE);

	/* Check for cross-device rename. */
	if (fdvp->v_mount != fvp->v_mount || fvp->v_mount != tdvp->v_mount ||
	    tdvp->v_mount != fdvp->v_mount ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		error = EXDEV;
		goto abortit;
	}
	/* If source and dest are the same, do nothing. */
	if (tvp == fvp) {
		error = 0;
		goto abortit;
	}

	if (fdip->pmp->rdonly || (fdip->pmp->flags & HAMMER2_PMPF_EMERG)) {
		error = EROFS;
		goto abortit;
	}
	if (hammer2_vfs_enospace(fdip, 0, fcnp->cn_cred) > 1) {
		error = ENOSPC;
		goto abortit;
	}

	error = vn_lock(fvp, LK_EXCLUSIVE);
	if (error)
		goto abortit;
	if (fdvp != tdvp) {
		error = vn_lock(fdvp, LK_EXCLUSIVE);
		if (error) {
			VOP_UNLOCK(fvp);
			goto abortit;
		}
	}

	hammer2_trans_init(tdip->pmp, 0);
	hammer2_inode_ref(fip); /* extra ref */

	/*
	 * Lookup the target name to determine if a directory entry
	 * is being overwritten.  We only hold related inode locks
	 * temporarily, the operating system is expected to protect
	 * against rename races.
	 */
	tip = tvp ? VTOI(tvp) : NULL;
	if (tip)
		hammer2_inode_ref(tip); /* extra ref */

	/*
	 * For now try to avoid deadlocks with a simple pointer address
	 * test.  (tip) can be NULL.
	 */
	ip1 = fdip;
	ip2 = tdip;
	ip3 = fip;
	ip4 = tip; /* may be NULL */

	if (fdip > tdip) {
		ip1 = tdip;
		ip2 = fdip;
	}
	if (tip && fip > tip) {
		ip3 = tip;
		ip4 = fip;
	}
	hammer2_inode_lock4(ip1, ip2, ip3, ip4);

	/*
	 * Resolve the collision space for (tdip, tname, tname_len).
	 *
	 * tdip must be held exclusively locked to prevent races since
	 * multiple filenames can end up in the same collision space.
	 */
	tlhc = hammer2_dirhash(tcnp->cn_nameptr, tcnp->cn_namelen);
	lhcbase = tlhc;
	sxop = hammer2_xop_alloc(tdip, HAMMER2_XOP_MODIFYING);
	sxop->lhc = tlhc;
	hammer2_xop_start(&sxop->head, &hammer2_scanlhc_desc);
	while ((error = hammer2_xop_collect(&sxop->head, 0)) == 0) {
		if (tlhc != sxop->head.cluster.focus->bref.key)
			break;
		++tlhc;
	}
	error = hammer2_error_to_errno(error);
	hammer2_xop_retire(&sxop->head, HAMMER2_XOPMASK_VOP);
	if (error) {
		if (error != ENOENT)
			goto done2;
		++tlhc;
		error = 0;
	}
	if ((lhcbase ^ tlhc) & ~HAMMER2_DIRHASH_LOMASK) {
		error = ENOSPC;
		goto done2;
	}

	/*
	 * Ready to go, issue the rename to the backend.  Note that meta-data
	 * updates to the related inodes occur separately from the rename
	 * operation.  ip1|2|3|4 are fdip, fip, tdip, tip in this order.
	 *
	 * NOTE: While it is not necessary to update ip->meta.name*, doing
	 *	 so aids catastrophic recovery and debugging.
	 */
	if (error == 0) {
		xop4 = hammer2_xop_alloc(fdip, HAMMER2_XOP_MODIFYING);
		xop4->lhc = tlhc;
		xop4->ip_key = fip->meta.name_key;
		hammer2_xop_setip2(&xop4->head, fip);
		hammer2_xop_setip3(&xop4->head, tdip);
		if (tip && tip->meta.type == HAMMER2_OBJTYPE_DIRECTORY)
		    hammer2_xop_setip4(&xop4->head, tip);
		hammer2_xop_setname(&xop4->head, fcnp->cn_nameptr,
		    fcnp->cn_namelen);
		hammer2_xop_setname2(&xop4->head, tcnp->cn_nameptr,
		    tcnp->cn_namelen);
		hammer2_xop_start(&xop4->head, &hammer2_nrename_desc);
		error = hammer2_xop_collect(&xop4->head, 0);
		error = hammer2_error_to_errno(error);
		hammer2_xop_retire(&xop4->head, HAMMER2_XOPMASK_VOP);
		if (error == ENOENT)
			error = 0;
		/*
		 * Update inode meta-data.
		 *
		 * WARNING!  The in-memory inode (ip) structure does not
		 *	     maintain a copy of the inode's filename buffer.
		 */
		if (error == 0 &&
		    (fip->meta.name_key & HAMMER2_DIRHASH_VISIBLE)) {
			hammer2_inode_modify(fip);
			fip->meta.name_len = tcnp->cn_namelen;
			fip->meta.name_key = tlhc;
		}
		if (error == 0) {
			hammer2_inode_modify(fip);
			fip->meta.iparent = tdip->meta.inum;
		}
		update_fdip = 1;
		update_tdip = 1;
	}
done2:
	/*
	 * If no error, the backend has replaced the target directory entry.
	 * We must adjust nlinks on the original replace target if it exists.
	 * DragonFly HAMMER2 passes vprecycle here instead of NULL.
	 */
	if (error == 0 && tip)
		hammer2_inode_unlink_finisher(tip, NULL);

	/* Update directory mtimes to represent the something changed. */
	if (update_fdip || update_tdip) {
		hammer2_update_time(&mtime);
		if (update_fdip) {
			hammer2_inode_modify(fdip);
			fdip->meta.mtime = mtime;
		}
		if (update_tdip) {
			hammer2_inode_modify(tdip);
			tdip->meta.mtime = mtime;
		}
	}
	if (tip) {
		hammer2_inode_unlock(tip);
		hammer2_inode_drop(tip);
	}
	hammer2_inode_unlock(fip);
	/*
	 * XXX iplock: NetBSD HAMMER2 specific.
	 * If tdip == fdip, hammer2_inode_lock4() locked only once.
	 */
	hammer2_inode_unlock(tdip);
	if (tdip != fdip)
		hammer2_inode_unlock(fdip);
	else
		hammer2_inode_drop(fdip); /* not locked, but ref'd */
	hammer2_inode_drop(fip);
	hammer2_trans_done(tdip->pmp, HAMMER2_TRANS_SIDEQ);

	genfs_rename_cache_purge(fdvp, fvp, tdvp, tvp);

	if (fdvp != tdvp)
		vput(fdvp);
	else
		vrele(fdvp);
	vput(fvp);
	vput(tdvp);
	if (tvp != NULL) {
		if (tvp != tdvp)
			vput(tvp);
		else /* how ? */
			vrele(tvp);
	}
	return (error);
abortit:
	vrele(fdvp);
	vrele(fvp);
	vput(tdvp);
	if (tvp != NULL) {
		if (tvp != tdvp)
			vput(tvp);
		else /* how ? */
			vrele(tvp);
	}
	return (error);
}

static int
hammer2_link(void *v)
{
	struct vop_link_v2_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *tdip = VTOI(dvp); /* target directory to create link in */
	hammer2_inode_t *ip = VTOI(vp); /* inode we are hardlinking to */
	uint64_t cmtime;
	int error;

	if (dvp->v_mount != vp->v_mount)
		return (EXDEV);

	if (tdip->pmp->rdonly || (tdip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(tdip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * ip represents the file being hardlinked.  The file could be a
	 * normal file or a hardlink target if it has already been hardlinked.
	 * (with the new semantics, it will almost always be a hardlink
	 * target).
	 *
	 * Bump nlinks and potentially also create or move the hardlink
	 * target in the parent directory common to (ip) and (tdip).  The
	 * consolidation code can modify ip->cluster.  The returned cluster
	 * is locked.
	 */
	KKASSERT(ip->pmp);
	hammer2_trans_init(ip->pmp, 0);

	/*
	 * Target should be an indexed inode or there's no way we will ever
	 * be able to find it!
	 */
	KKASSERT((ip->meta.name_key & HAMMER2_DIRHASH_VISIBLE) == 0);

	hammer2_inode_lock4(tdip, ip, NULL, NULL);
	hammer2_update_time(&cmtime);

	/*
	 * Create the directory entry and bump nlinks.
	 * Also update ip's ctime.
	 */
	error = hammer2_dirent_create(tdip, cnp->cn_nameptr, cnp->cn_namelen,
	    ip->meta.inum, ip->meta.type);
	hammer2_inode_modify(ip);
	++ip->meta.nlinks;
	ip->meta.ctime = cmtime;

	if (error == 0) {
		/* Update dip's [cm]time. */
		hammer2_inode_modify(tdip);
		tdip->meta.mtime = cmtime;
		tdip->meta.ctime = cmtime;
	}
	hammer2_inode_unlock(ip);
	hammer2_inode_unlock(tdip);

	hammer2_trans_done(ip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

static int
hammer2_symlink(void *v)
{
	struct vop_symlink_v3_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
		char *a_target;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	struct uio auio;
	struct iovec aiov;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	ap->a_vap->va_type = VLNK; /* enforce type */

	/*
	 * Create the softlink as an inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
		hammer2_inode_unlock(dip);
		hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);
		return (error);
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 * NetBSD VFS wants filesystem to use vcache_new() here.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			cache_enter(dvp, vp, cnp->cn_nameptr, cnp->cn_namelen,
			    cnp->cn_flags);
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/* Build the softlink. */
	if (error == 0) {
		bzero(&auio, sizeof(auio));
		bzero(&aiov, sizeof(aiov));
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_resid = strlen(ap->a_target);
		auio.uio_rw = UIO_WRITE;
		aiov.iov_base = __DECONST(void *, ap->a_target);
		aiov.iov_len = strlen(ap->a_target);
		UIO_SETUP_SYSSPACE(&auio);
		error = hammer2_write_file(nip, &auio, IO_APPEND);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	vp = *ap->a_vpp;
	if (error) {
		if (vp)
			vput(vp);
	} else {
		if (vp)
			VOP_UNLOCK(vp);
	}
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

static void
hammer2_itimes_locked(struct vnode *vp)
{
}

static int
hammer2_close(void *v)
{
	struct vop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;

	KASSERT(VOP_ISLOCKED(vp));

	if (vrefcnt(vp) > 1)
		hammer2_itimes_locked(vp);

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
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);
	int error;

	/*
	 * XXX2 The ioctl implementation is expected to lock vp here,
	 * but fs sync from ioctl causes deadlock loop.
	 */
	error = 0; /* vn_lock(vp, LK_EXCLUSIVE); */
	if (error == 0) {
		error = hammer2_ioctl_impl(ip, ap->a_command, ap->a_data,
		    ap->a_fflag, ap->a_cred);
		/* VOP_UNLOCK(vp); */
	} else {
		error = EBADF;
	}

	return (error);
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
hammer2_vinit(struct mount *mp, struct vnode **vpp)
{
	struct vnode *vp = *vpp;
	hammer2_inode_t *ip = VTOI(vp);

	vp->v_type = hammer2_get_vtype(ip->meta.type);
	switch (vp->v_type) {
	case VCHR:
	case VBLK:
		vp->v_op = hammer2_specop_p;
		spec_node_init(vp, (dev_t)(uintptr_t)vp);
		break;
	case VFIFO:
		vp->v_op = hammer2_fifoop_p;
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
	{ &vop_create_desc, hammer2_create },		/* create */
	{ &vop_mknod_desc, hammer2_mknod },		/* mknod */
	{ &vop_open_desc, hammer2_open },		/* open */
	{ &vop_close_desc, hammer2_close },		/* close */
	{ &vop_access_desc, hammer2_access },		/* access */
	{ &vop_accessx_desc, genfs_accessx },		/* accessx */
	{ &vop_getattr_desc, hammer2_getattr },		/* getattr */
	{ &vop_setattr_desc, hammer2_setattr },		/* setattr */
	{ &vop_read_desc, hammer2_read },		/* read */
	{ &vop_write_desc, hammer2_write },		/* write */
	{ &vop_fallocate_desc, genfs_eopnotsupp },	/* fallocate */
	{ &vop_fdiscard_desc, genfs_eopnotsupp },	/* fdiscard */
	{ &vop_fcntl_desc, genfs_fcntl },		/* fcntl */
	{ &vop_ioctl_desc, hammer2_ioctl },		/* ioctl */
	{ &vop_poll_desc, genfs_poll },			/* poll */
	{ &vop_kqfilter_desc, genfs_kqfilter },		/* kqfilter */
	{ &vop_revoke_desc, genfs_revoke },		/* revoke */
	{ &vop_mmap_desc, genfs_mmap },			/* mmap */
	{ &vop_fsync_desc, hammer2_fsync },		/* fsync */
	{ &vop_seek_desc, genfs_seek },			/* seek */
	{ &vop_remove_desc, hammer2_remove },		/* remove */
	{ &vop_link_desc, hammer2_link },		/* link */
	{ &vop_rename_desc, hammer2_rename },		/* rename */
	{ &vop_mkdir_desc, hammer2_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, hammer2_rmdir },		/* rmdir */
	{ &vop_symlink_desc, hammer2_symlink },		/* symlink */
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
	{ &vop_fsync_desc, hammer2_fsync },		/* fsync */
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
	{ &vop_fsync_desc, hammer2_fsync },		/* fsync */
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
