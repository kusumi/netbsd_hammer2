/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2023 The DragonFly Project.  All rights reserved.
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

#include <miscfs/genfs/genfs.h>

static void hammer2_inode_repoint(hammer2_inode_t *, hammer2_cluster_t *);
static void hammer2_inode_repoint_one(hammer2_inode_t *, hammer2_cluster_t *,
    int);

/*
 * Initialize inum hash in fresh structure.
 */
void
hammer2_inum_hash_init(hammer2_pfs_t *pmp)
{
	hammer2_inum_hash_t *hash;
	int i;

	for (i = 0; i < HAMMER2_INUMHASH_SIZE; ++i) {
		hash = &pmp->inumhash[i];
		hammer2_spin_init(&hash->spin, "h2mp_inum");
	}
}

void
hammer2_inum_hash_destroy(hammer2_pfs_t *pmp)
{
	hammer2_inum_hash_t *hash;
	int i;

	for (i = 0; i < HAMMER2_INUMHASH_SIZE; ++i) {
		hash = &pmp->inumhash[i];
		hammer2_spin_destroy(&hash->spin);
	}
}

/*
 * Caller holds pmp->list_spin and the inode should be locked.  Merge ip
 * with the specified depend.
 *
 * If the ip is on SYNCQ it stays there and (void *)-1 is returned, indicating
 * that successive calls must ensure the ip is on a pass2 depend (or they are
 * all SYNCQ).  If the passed-in depend is not NULL and not (void *)-1 then
 * we can set pass2 on it and return.
 *
 * If the ip is not on SYNCQ it is merged with the passed-in depend, creating
 * a self-depend if necessary, and depend->pass2 is set according
 * to the PASS2 flag.  SIDEQ is set.
 */
static hammer2_depend_t *
hammer2_inode_setdepend_locked(hammer2_inode_t *ip, hammer2_depend_t *depend)
{
	hammer2_pfs_t *pmp = ip->pmp;
	hammer2_depend_t *dtmp;
	hammer2_inode_t *iptmp;
#ifdef INVARIANTS
	int sanitychk = 0;
#endif
	/*
	 * If ip is SYNCQ its entry is used for the syncq list and it will
	 * no longer be associated with a dependency.  Merging this status
	 * with a passed-in depend implies PASS2.
	 */
	if (ip->flags & HAMMER2_INODE_SYNCQ) {
		if (depend == (void *)-1 || depend == NULL)
			return ((void *)-1);
		depend->pass2 = 1;
		hammer2_trans_setflags(pmp, HAMMER2_TRANS_RESCAN);
		return (depend);
	}

	/*
	 * If ip is already SIDEQ, merge ip->depend into the passed-in depend.
	 * If it is not, associate the ip with the passed-in depend, creating
	 * a single-entry dependency using depend_static if necessary.
	 *
	 * NOTE: The use of ip->depend_static always requires that the
	 *	 specific ip containing the structure is part of that
	 *	 particular depend_static's dependency group.
	 */
	if (ip->flags & HAMMER2_INODE_SIDEQ) {
		/*
		 * Merge ip->depend with the passed-in depend.  If the
		 * passed-in depend is not a special case, all ips associated
		 * with ip->depend (including the original ip) must be moved
		 * to the passed-in depend.
		 */
		if (depend == NULL) {
			depend = ip->depend;
		} else if (depend == (void *)-1) {
			depend = ip->depend;
			depend->pass2 = 1;
		} else if (depend != ip->depend) {
			dtmp = ip->depend;
			while ((iptmp = TAILQ_FIRST(&dtmp->sideq)) != NULL) {
#ifdef INVARIANTS
				if (iptmp == ip)
					sanitychk = 1;
#endif
				TAILQ_REMOVE(&dtmp->sideq, iptmp, qentry);
				TAILQ_INSERT_TAIL(&depend->sideq, iptmp, qentry);
				iptmp->depend = depend;
			}
			KKASSERT(sanitychk == 1);
			depend->count += dtmp->count;
			depend->pass2 |= dtmp->pass2;
			TAILQ_REMOVE(&pmp->depq, dtmp, entry);
			dtmp->count = 0;
			dtmp->pass2 = 0;
		}
	} else {
		/*
		 * Add ip to the sideq, creating a self-dependency if
		 * necessary.
		 */
		hammer2_inode_ref(ip);
		atomic_set_int(&ip->flags, HAMMER2_INODE_SIDEQ);
		if (depend == NULL) {
			depend = &ip->depend_static;
			TAILQ_INSERT_TAIL(&pmp->depq, depend, entry);
		} else if (depend == (void *)-1) {
			depend = &ip->depend_static;
			depend->pass2 = 1;
			TAILQ_INSERT_TAIL(&pmp->depq, depend, entry);
		} /* else add ip to passed-in depend */
		TAILQ_INSERT_TAIL(&depend->sideq, ip, qentry);
		ip->depend = depend;
		++depend->count;
		++pmp->sideq_count;
	}

	if (ip->flags & HAMMER2_INODE_SYNCQ_PASS2)
		depend->pass2 = 1;
	if (depend->pass2)
		hammer2_trans_setflags(pmp, HAMMER2_TRANS_RESCAN);

	return (depend);
}

/*
 * Put a solo inode on the SIDEQ (meaning that its dirty).
 * This can also occur from inode_lock4() and inode_depend().
 *
 * Caller must pass-in a locked inode.
 */
void
hammer2_inode_delayed_sideq(hammer2_inode_t *ip)
{
	hammer2_pfs_t *pmp = ip->pmp;

	/* Optimize case to avoid pmp spinlock. */
	if ((ip->flags & (HAMMER2_INODE_SYNCQ | HAMMER2_INODE_SIDEQ)) == 0) {
		hammer2_spin_ex(&pmp->list_spin);
		hammer2_inode_setdepend_locked(ip, NULL);
		hammer2_spin_unex(&pmp->list_spin);
	}
}

/*
 * Lock an inode, with SYNCQ semantics.
 *
 * HAMMER2 offers shared and exclusive locks on inodes.  Pass a mask of
 * flags for options:
 *
 *	- pass HAMMER2_RESOLVE_SHARED if a shared lock is desired.
 *	  shared locks are not subject to SYNCQ semantics, exclusive locks
 *	  are.
 *
 *	- pass HAMMER2_RESOLVE_ALWAYS if you need the inode's meta-data.
 *	  Most front-end inode locks do.
 *
 * This function, along with lock4, has SYNCQ semantics.  If the inode being
 * locked is on the SYNCQ, that is it has been staged by the syncer, we must
 * block until the operation is complete (even if we can lock the inode).  In
 * order to reduce the stall time, we re-order the inode to the front of the
 * pmp->syncq prior to blocking.  This reordering VERY significantly improves
 * performance.
 */
void
hammer2_inode_lock(hammer2_inode_t *ip, int how)
{
	hammer2_pfs_t *pmp;

	hammer2_inode_ref(ip);
	pmp = ip->pmp;

	/* Inode structure mutex - Shared lock */
	if (how & HAMMER2_RESOLVE_SHARED) {
		hammer2_mtx_sh(&ip->lock);
		return;
	}

	/*
	 * Inode structure mutex - Exclusive lock
	 *
	 * An exclusive lock (if not recursive) must wait for inodes on
	 * SYNCQ to flush first, to ensure that meta-data dependencies such
	 * as the nlink count and related directory entries are not split
	 * across flushes.
	 *
	 * If the vnode is locked by the current thread it must be unlocked
	 * across the tsleep() to avoid a deadlock.
	 */
	hammer2_mtx_ex(&ip->lock);
	if (hammer2_mtx_refs(&ip->lock) > 1)
		return;
	while ((ip->flags & HAMMER2_INODE_SYNCQ) && pmp) {
		hammer2_spin_ex(&pmp->list_spin);
		if (ip->flags & HAMMER2_INODE_SYNCQ) {
			/* XXX2 condvar(9) with rwlock(9)? */
			/* tsleep_interlock(&ip->flags, 0); */
			atomic_set_int(&ip->flags, HAMMER2_INODE_SYNCQ_WAKEUP);
			TAILQ_REMOVE(&pmp->syncq, ip, qentry);
			TAILQ_INSERT_HEAD(&pmp->syncq, ip, qentry);
			hammer2_spin_unex(&pmp->list_spin);
			hammer2_mtx_unlock(&ip->lock);
			/* race window here */
			tsleep(&ip->flags, 0, "h2sync",
			    hz / 10 /* 0 in DragonFly */);
			hammer2_mtx_ex(&ip->lock);
			continue;
		}
		hammer2_spin_unex(&pmp->list_spin);
		hammer2_mtx_assert_ex(&ip->lock);
		break;
	}
}

/*
 * Exclusively lock up to four inodes, in order, with SYNCQ semantics.
 * ip1 and ip2 must not be NULL.  ip3 and ip4 may be NULL, but if ip3 is
 * NULL then ip4 must also be NULL.
 *
 * This creates a dependency between up to four inodes.
 */
void
hammer2_inode_lock4(hammer2_inode_t *ip1, hammer2_inode_t *ip2,
    hammer2_inode_t *ip3, hammer2_inode_t *ip4)
{
	hammer2_inode_t *ips[4], *iptmp, *ipslp, *iplk[4];
	hammer2_depend_t *depend;
	hammer2_pfs_t *pmp;
	size_t count, i, j, iplkd;

	pmp = ip1->pmp; /* may be NULL */
	KKASSERT(pmp == ip2->pmp);

	ips[0] = ip1;
	ips[1] = ip2;
	if (ip3 == NULL) {
		count = 2;
	} else if (ip4 == NULL) {
		count = 3;
		ips[2] = ip3;
		KKASSERT(pmp == ip3->pmp);
	} else {
		count = 4;
		ips[2] = ip3;
		ips[3] = ip4;
		KKASSERT(pmp == ip3->pmp);
		KKASSERT(pmp == ip4->pmp);
	}

	for (i = 0; i < count; ++i)
		hammer2_inode_ref(ips[i]);
restart:
	/* Lock the inodes in order. */
	/* XXX iplock: NetBSD HAMMER2 inode lock can't recurse. */
	iplk[0] = iplk[1] = iplk[2] = iplk[3] = NULL;
	for (i = 0; i < count; ++i) {
		iplkd = 0;
		for (j = 0; j < i; j++)
			if (iplk[j] == ips[i])
				iplkd = 1;
		if (!iplkd) {
			hammer2_mtx_ex(&ips[i]->lock);
			iplk[i] = ips[i];
		}
	}

	/*
	 * Associate dependencies, record the first inode found on SYNCQ
	 * (operation is allowed to proceed for inodes on PASS2) for our
	 * sleep operation, this inode is theoretically the last one sync'd
	 * in the sequence.
	 *
	 * All inodes found on SYNCQ are moved to the head of the syncq
	 * to reduce stalls.
	 */
	hammer2_spin_ex(&pmp->list_spin);
	depend = NULL;
	ipslp = NULL;
	for (i = 0; i < count; ++i) {
		iptmp = ips[i];
		depend = hammer2_inode_setdepend_locked(iptmp, depend);
		if (iptmp->flags & HAMMER2_INODE_SYNCQ) {
			TAILQ_REMOVE(&pmp->syncq, iptmp, qentry);
			TAILQ_INSERT_HEAD(&pmp->syncq, iptmp, qentry);
			if (ipslp == NULL)
				ipslp = iptmp;
		}
	}
	hammer2_spin_unex(&pmp->list_spin);

	/*
	 * Block and retry if any of the inodes are on SYNCQ.  It is
	 * important that we allow the operation to proceed in the
	 * PASS2 case, to avoid deadlocking against the vnode.
	 */
	if (ipslp) {
		for (i = 0; i < count; ++i)
			if (iplk[i])
				hammer2_mtx_unlock(&iplk[i]->lock);
		tsleep(&ipslp->flags, 0, "h2sync", 2);
		goto restart;
	}
}

/*
 * Release an inode lock.  If another thread is blocked on SYNCQ_WAKEUP
 * we wake them up.
 */
void
hammer2_inode_unlock(hammer2_inode_t *ip)
{
	if (ip->flags & HAMMER2_INODE_SYNCQ_WAKEUP) {
		atomic_clear_int(&ip->flags, HAMMER2_INODE_SYNCQ_WAKEUP);
		hammer2_mtx_unlock(&ip->lock);
		wakeup(&ip->flags);
	} else {
		hammer2_mtx_unlock(&ip->lock);
	}
	hammer2_inode_drop(ip);
}

/*
 * If either ip1 or ip2 have been tapped by the syncer, make sure that both
 * are.  This ensure that dependencies (e.g. dirent-v-inode) are synced
 * together.  For dirent-v-inode depends, pass the dirent as ip1.
 *
 * If neither ip1 or ip2 have been tapped by the syncer, merge them into a
 * single dependency.  Dependencies are entered into pmp->depq.  This
 * effectively flags the inodes SIDEQ.
 *
 * Both ip1 and ip2 must be locked by the caller.  This also ensures
 * that we can't race the end of the syncer's queue run.
 */
void
hammer2_inode_depend(hammer2_inode_t *ip1, hammer2_inode_t *ip2)
{
	hammer2_pfs_t *pmp;
	hammer2_depend_t *depend;

	pmp = ip1->pmp;
	hammer2_spin_ex(&pmp->list_spin);
	depend = hammer2_inode_setdepend_locked(ip1, NULL);
	depend = hammer2_inode_setdepend_locked(ip2, depend);
	hammer2_spin_unex(&pmp->list_spin);
}

/*
 * Select a chain out of an inode's cluster and lock it.
 * The inode does not have to be locked.
 */
hammer2_chain_t *
hammer2_inode_chain(hammer2_inode_t *ip, int clindex, int how)
{
	hammer2_chain_t *chain;
	hammer2_cluster_t *cluster;

	hammer2_spin_sh(&ip->cluster_spin);
	cluster = &ip->cluster;
	if (clindex >= cluster->nchains)
		chain = NULL;
	else
		chain = cluster->array[clindex].chain;
	if (chain) {
		hammer2_chain_ref(chain);
		hammer2_spin_unsh(&ip->cluster_spin);
		hammer2_chain_lock(chain, how);
	} else {
		hammer2_spin_unsh(&ip->cluster_spin);
	}

	return (chain);
}

hammer2_chain_t *
hammer2_inode_chain_and_parent(hammer2_inode_t *ip, int clindex,
    hammer2_chain_t **parentp, int how)
{
	hammer2_chain_t *chain, *parent;

	for (;;) {
		hammer2_spin_sh(&ip->cluster_spin);
		if (clindex >= ip->cluster.nchains)
			chain = NULL;
		else
			chain = ip->cluster.array[clindex].chain;
		if (chain) {
			hammer2_chain_ref(chain);
			hammer2_spin_unsh(&ip->cluster_spin);
			hammer2_chain_lock(chain, how);
		} else {
			hammer2_spin_unsh(&ip->cluster_spin);
		}

		/* Get parent, lock order must be (parent, chain). */
		parent = chain->parent;
		if (parent) {
			hammer2_chain_ref(parent);
			hammer2_chain_unlock(chain);
			hammer2_chain_lock(parent, how);
			hammer2_chain_lock(chain, how);
		}
		if (ip->cluster.array[clindex].chain == chain &&
		    chain->parent == parent)
			break;

		/* Retry. */
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		if (parent) {
			hammer2_chain_unlock(parent);
			hammer2_chain_drop(parent);
		}
	}
	*parentp = parent;

	return (chain);
}

/*
 * Temporarily release a lock held shared or exclusive.  Caller must
 * hold the lock shared or exclusive on call and lock will be released
 * on return.
 *
 * Restore a lock that was temporarily released.
 */
static int
hammer2_inode_lock_temp_release(hammer2_inode_t *ip)
{
	return (hammer2_mtx_temp_release(&ip->lock));
}

static void
hammer2_inode_lock_temp_restore(hammer2_inode_t *ip, int ostate)
{
	hammer2_mtx_temp_restore(&ip->lock, ostate);
}

static __inline hammer2_inum_hash_t *
inumhash(hammer2_pfs_t *pmp, hammer2_tid_t inum)
{
	int hv;

	hv = (int)inum;
	return (&pmp->inumhash[hv & HAMMER2_INUMHASH_MASK]);
}

/*
 * Lookup an inode by inode number.
 */
hammer2_inode_t *
hammer2_inode_lookup(hammer2_pfs_t *pmp, hammer2_tid_t inum)
{
	hammer2_inum_hash_t *hash;
	hammer2_inode_t *ip;

	KKASSERT(pmp);
	if (pmp->spmp_hmp) {
		ip = NULL;
	} else {
		hash = inumhash(pmp, inum);
		hammer2_spin_sh(&hash->spin);
		for (ip = hash->base; ip; ip = ip->next) {
			if (ip->meta.inum == inum) {
				hammer2_inode_ref(ip);
				break;
			}
		}
		hammer2_spin_unsh(&hash->spin);
	}

	return (ip);
}

/*
 * Adding a ref to an inode is only legal if the inode already has at least
 * one ref.
 * Can be called with spinlock held.
 */
void
hammer2_inode_ref(hammer2_inode_t *ip)
{
	atomic_add_int(&ip->refs, 1);
}

/*
 * Drop an inode reference, freeing the inode when the last reference goes
 * away.
 */
void
hammer2_inode_drop(hammer2_inode_t *ip)
{
	hammer2_pfs_t *pmp;
	hammer2_inum_hash_t *hash;
	hammer2_inode_t **xipp;
	unsigned int refs;

	while (ip) {
		refs = ip->refs;
		cpu_ccfence();
		if (refs == 1) {
			/*
			 * Transition to zero, must interlock with
			 * the inode inumber lookup tree (if applicable).
			 * It should not be possible for anyone to race
			 * the transition to 0.
			 */
			pmp = ip->pmp;
			KKASSERT(pmp);
			hash = inumhash(pmp, ip->meta.inum);

			hammer2_spin_ex(&hash->spin);
			if (atomic_cmpset_int(&ip->refs, 1, 0)) {
				KKASSERT(hammer2_mtx_refs(&ip->lock) == 0);
				if (ip->flags & HAMMER2_INODE_ONHASH) {
					xipp = &hash->base;
					while (*xipp != ip)
						xipp = &(*xipp)->next;
					*xipp = ip->next;
					ip->next = NULL;
					atomic_clear_int(&ip->flags,
					    HAMMER2_INODE_ONHASH);
				}
				hammer2_spin_unex(&hash->spin);
				ip->pmp = NULL;

				/*
				 * Cleaning out ip->cluster isn't entirely
				 * trivial.
				 */
				hammer2_inode_repoint(ip, NULL);
				hammer2_mtx_destroy(&ip->lock);
				hammer2_mtx_destroy(&ip->truncate_lock);
				hammer2_mtx_destroy(&ip->vhold_lock);
				hammer2_spin_destroy(&ip->cluster_spin);
				/* ip->vhold isn't necessarily zero. */

				pool_put(&hammer2_pool_inode, ip);
				atomic_add_int(&hammer2_count_inode_allocated,
				    -1);
				ip = NULL; /* Will terminate loop. */
			} else {
				hammer2_spin_unex(&hash->spin);
			}
		} else {
			/* Non zero transition. */
			if (atomic_cmpset_int(&ip->refs, refs, refs - 1))
				break;
		}
	}
}

/*
 * Get the vnode associated with the given inode, allocating the vnode if
 * necessary.  The vnode will be returned exclusively locked.
 *
 * The caller must lock the inode (shared or exclusive).
 */
int
hammer2_igetv(hammer2_inode_t *ip, int lktype, struct vnode **vpp)
{
	struct mount *mp;
	struct vnode *vp = NULL;
	hammer2_tid_t inum;
	int error, ostate;

	KKASSERT(ip);
	KKASSERT(ip->pmp);
	KKASSERT(ip->pmp->mp);
	mp = ip->pmp->mp;

	hammer2_mtx_assert_locked(&ip->lock);
	hammer2_assert_inode_meta(ip);
	inum = ip->meta.inum; /* without HAMMER2_DIRHASH_USERMSK mask */

	/* Unlock inode, otherwise deadlocks vs syscall processes. */
	ostate = hammer2_inode_lock_temp_release(ip);
	error = vcache_get(mp, &inum, sizeof(inum), &vp);
	hammer2_inode_lock_temp_restore(ip, ostate);
	if (error) {
		*vpp = NULL;
		return (error);
	}
	KKASSERT(vp);
	KKASSERT(VOP_ISLOCKED(vp) == 0);
	KKASSERT(vp->v_op);

	if (lktype != LK_NONE) {
		error = vn_lock(vp, lktype);
		if (error) {
			vrele(vp);
			*vpp = NULL;
			return (error);
		}
	} else {
		KASSERT(VOP_ISLOCKED(vp) == 0);
	}

	KASSERTMSG(vp->v_type != VBAD, "VBAD");
	KASSERTMSG(vp->v_type != VNON, "VNON");

	*vpp = vp;
	return (0);
}

/*
 * Returns the inode associated with the arguments, allocating a new
 * hammer2_inode structure if necessary, then synchronizing it to the passed
 * xop cluster.  When synchronizing, if idx >= 0, only cluster index (idx)
 * is synchronized.  Otherwise the whole cluster is synchronized.  inum will
 * be extracted from the passed-in xop and the inum argument will be ignored.
 *
 * If xop is passed as NULL then a new hammer2_inode is allocated with the
 * specified inum, and returned.   For normal inodes, the inode will be
 * indexed in memory and if it already exists the existing ip will be
 * returned instead of allocating a new one.  The superroot and PFS inodes
 * are not indexed in memory.
 *
 * The returned inode will be locked and the caller may dispose of both
 * via hammer2_inode_unlock() + hammer2_inode_drop().
 *
 * The hammer2_inode structure regulates the interface between the high level
 * kernel VNOPS API and the filesystem backend (the chains).
 */
hammer2_inode_t *
hammer2_inode_get(hammer2_pfs_t *pmp, hammer2_xop_head_t *xop,
    hammer2_tid_t inum, int idx)
{
	hammer2_inum_hash_t *hash;
	hammer2_inode_t *nip, *xip, **xipp;
	const hammer2_inode_data_t *iptmp, *nipdata;

	KKASSERT(xop == NULL ||
	    hammer2_cluster_type(&xop->cluster) == HAMMER2_BREF_TYPE_INODE);
	KKASSERT(pmp);

	if (xop) {
		iptmp = &hammer2_xop_gdata(xop)->ipdata;
		inum = iptmp->meta.inum;
		hammer2_xop_pdata(xop);
	}
again:
	nip = hammer2_inode_lookup(pmp, inum);
	if (nip) {
		/*
		 * We may have to unhold the cluster to avoid a deadlock
		 * against vnlru (and possibly other XOPs).
		 */
		if (xop) {
			if (hammer2_mtx_ex_try(&nip->lock) != 0) {
				hammer2_cluster_unhold(&xop->cluster);
				hammer2_mtx_ex(&nip->lock);
				hammer2_cluster_rehold(&xop->cluster);
			}
		} else {
			hammer2_mtx_ex(&nip->lock);
		}

		/*
		 * Handle SMP race (not applicable to the super-root spmp
		 * which can't index inodes due to duplicative inode numbers).
		 */
		if (pmp->spmp_hmp == NULL &&
		    (nip->flags & HAMMER2_INODE_ONHASH) == 0) {
			hammer2_mtx_unlock(&nip->lock);
			hammer2_inode_drop(nip);
			goto again;
		}
		if (xop) {
			if (idx >= 0)
				hammer2_inode_repoint_one(nip, &xop->cluster,
				    idx);
			else
				hammer2_inode_repoint(nip, &xop->cluster);
		}
		return (nip);
	}

	/*
	 * We couldn't find the inode number, create a new inode and try to
	 * insert it, handle insertion races.
	 */
	nip = pool_get(&hammer2_pool_inode, PR_WAITOK | PR_ZERO);
	atomic_add_int(&hammer2_count_inode_allocated, 1);
	hammer2_spin_init(&nip->cluster_spin, "h2ip_cl");

	nip->cluster.pmp = pmp;
	if (xop) {
		nipdata = &hammer2_xop_gdata(xop)->ipdata;
		nip->meta = nipdata->meta;
		hammer2_xop_pdata(xop);
		hammer2_inode_repoint(nip, &xop->cluster);
	} else {
		nip->meta.inum = inum;
	}

	nip->pmp = pmp;

	/* Calculate ipdep index. */
	nip->ipdep_idx = nip->meta.inum % HAMMER2_IHASH_SIZE;
	KKASSERT(nip->ipdep_idx >= 0 && nip->ipdep_idx < HAMMER2_IHASH_SIZE);

	/*
	 * ref and lock on nip gives it state compatible to after a
	 * hammer2_inode_lock() call.
	 * Note that hammer2_inactive() via vput() from hammer2_vfs_sync_pmp()
	 * recursively locks ip->lock in DragonFly and FreeBSD, but in NetBSD
	 * this gets unlocked once and relocked.
	 * This unlock / relock also applies to hammer2_vfs_sync_pmp() ->
	 * vflushbuf() -> VOP_PUTPAGES() -> genfs_compat_gop_write() ->
	 * VOP_WRITE() -> hammer2_write_file().
	 */
	nip->refs = 1;
	hammer2_mtx_init(&nip->lock, "h2ip"); /* XXX iplock */
	hammer2_mtx_init(&nip->truncate_lock, "h2ip_tr");
	hammer2_mtx_init(&nip->vhold_lock, "h2ip_vh");
	hammer2_mtx_ex(&nip->lock);
	TAILQ_INIT(&nip->depend_static.sideq);

	/*
	 * Attempt to add the inode.  If it fails we raced another inode
	 * get.  Undo all the work and try again.
	 */
	if (pmp->spmp_hmp == NULL) {
		hash = inumhash(pmp, nip->meta.inum);
		hammer2_spin_ex(&hash->spin);
		for (xipp = &hash->base;
		    (xip = *xipp) != NULL;
		    xipp = &xip->next) {
			if (xip->meta.inum == nip->meta.inum) {
				hammer2_spin_unex(&hash->spin);
				hammer2_mtx_unlock(&nip->lock);
				hammer2_inode_drop(nip);
				goto again;
			}
		}
		nip->next = NULL;
		*xipp = nip;
		atomic_set_int(&nip->flags, HAMMER2_INODE_ONHASH);
		hammer2_spin_unex(&hash->spin);
	}

	return (nip);
}

/*
 * Create a PFS inode under the superroot.  This function will create the
 * inode, its media chains, and also insert it into the media.
 *
 * Caller must be in a flush transaction because we are inserting the inode
 * onto the media.
 */
hammer2_inode_t *
hammer2_inode_create_pfs(hammer2_pfs_t *spmp, const char *name, size_t name_len,
    int *errorp)
{
	hammer2_xop_create_t *xop;
	hammer2_xop_scanlhc_t *sxop;
	hammer2_inode_t *pip, *nip;
	hammer2_tid_t pip_inum;
	hammer2_key_t lhc, lhcbase;
	uint8_t pip_comp_algo, pip_check_algo;
	int error;

	pip = spmp->iroot;
	nip = NULL;

	lhc = hammer2_dirhash(name, name_len);
	*errorp = 0;

	/*
	 * Locate the inode or indirect block to create the new
	 * entry in.  At the same time check for key collisions
	 * and iterate until we don't get one.
	 *
	 * Lock the directory exclusively for now to guarantee that
	 * we can find an unused lhc for the name.  Due to collisions,
	 * two different creates can end up with the same lhc so we
	 * cannot depend on the OS to prevent the collision.
	 */
	hammer2_inode_lock(pip, 0);

	pip_comp_algo = pip->meta.comp_algo;
	pip_check_algo = pip->meta.check_algo;
	pip_inum = (pip == pip->pmp->iroot) ? 1 : pip->meta.inum;

	/* Locate an unused key in the collision space. */
	lhcbase = lhc;
	sxop = hammer2_xop_alloc(pip, HAMMER2_XOP_MODIFYING);
	sxop->lhc = lhc;
	hammer2_xop_start(&sxop->head, &hammer2_scanlhc_desc);
	while ((error = hammer2_xop_collect(&sxop->head, 0)) == 0) {
		if (lhc != sxop->head.cluster.focus->bref.key)
			break;
		++lhc;
	}
	hammer2_xop_retire(&sxop->head, HAMMER2_XOPMASK_VOP);
	if (error) {
		if (error != HAMMER2_ERROR_ENOENT)
			goto done2;
		++lhc;
		error = 0;
	}
	if ((lhcbase ^ lhc) & ~HAMMER2_DIRHASH_LOMASK) {
		error = HAMMER2_ERROR_ENOSPC;
		goto done2;
	}

	/* Create the inode with the lhc as the key. */
	xop = hammer2_xop_alloc(pip, HAMMER2_XOP_MODIFYING);
	xop->lhc = lhc;
	xop->flags = HAMMER2_INSERT_PFSROOT;
	bzero(&xop->meta, sizeof(xop->meta));
	xop->meta.type = HAMMER2_OBJTYPE_DIRECTORY;
	xop->meta.inum = 1;
	xop->meta.iparent = pip_inum;
	/* Inherit parent's inode compression mode. */
	xop->meta.comp_algo = pip_comp_algo;
	xop->meta.check_algo = pip_check_algo;
	xop->meta.version = HAMMER2_INODE_VERSION_ONE;
	hammer2_update_time(&xop->meta.ctime);
	xop->meta.mtime = xop->meta.ctime;
	xop->meta.atime = xop->meta.ctime;
	xop->meta.btime = xop->meta.ctime;
	xop->meta.mode = 0755;
	xop->meta.nlinks = 1;
	hammer2_xop_setname(&xop->head, name, name_len);
	xop->meta.name_len = name_len;
	xop->meta.name_key = lhc;
	KKASSERT(name_len < HAMMER2_INODE_MAXNAME);
	hammer2_xop_start(&xop->head, &hammer2_inode_create_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	if (error) {
		*errorp = error;
		goto done;
	}

	/*
	 * Set up the new inode if not a hardlink pointer.
	 *
	 * NOTE: *_get() integrates chain's lock into the inode lock.
	 *
	 * NOTE: Only one new inode can currently be created per
	 *	 transaction.  If the need arises we can adjust
	 *	 hammer2_trans_init() to allow more.
	 *
	 * NOTE: nipdata will have chain's blockset data.
	 */
	nip = hammer2_inode_get(pip->pmp, &xop->head, -1, -1);
	nip->comp_heuristic = 0;
done:
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
done2:
	hammer2_inode_unlock(pip);

	return (nip);
}

/*
 * Create a new, normal inode.  This function will create the inode,
 * the media chains, but will not insert the chains onto the media topology
 * (doing so would require a flush transaction and cause long stalls).
 *
 * Caller must be in a normal transaction.
 */
hammer2_inode_t *
hammer2_inode_create_normal(hammer2_inode_t *pip, struct vattr *vap,
    kauth_cred_t cred, hammer2_key_t inum, int *errorp)
{
	hammer2_xop_create_t *xop;
	hammer2_inode_t *dip, *nip;
	hammer2_tid_t pip_inum;
	struct uuid pip_gid;
	uint8_t pip_comp_algo, pip_check_algo;
	int error;

	dip = pip->pmp->iroot;
	KKASSERT(dip != NULL);

	*errorp = 0;

	pip_gid = pip->meta.gid;
	pip_comp_algo = pip->meta.comp_algo;
	pip_check_algo = pip->meta.check_algo;
	pip_inum = (pip == pip->pmp->iroot) ? 1 : pip->meta.inum;

	/* Create the in-memory inode structure for the specified inode. */
	nip = hammer2_inode_get(dip->pmp, NULL, inum, -1);
	nip->comp_heuristic = 0;
	KKASSERT((nip->flags & HAMMER2_INODE_CREATING) == 0 &&
	    nip->cluster.nchains == 0);
	atomic_set_int(&nip->flags, HAMMER2_INODE_CREATING);

	/* Setup the inode meta-data. */
	nip->meta.type = hammer2_get_obj_type(vap->va_type);

	switch (nip->meta.type) {
	case HAMMER2_OBJTYPE_CDEV:
	case HAMMER2_OBJTYPE_BDEV:
		nip->meta.rmajor = major(vap->va_rdev);
		nip->meta.rminor = minor(vap->va_rdev);
		break;
	default:
		break;
	}

	KKASSERT(nip->meta.inum == inum);
	nip->meta.iparent = pip_inum;

	/* Inherit parent's inode compression mode. */
	nip->meta.comp_algo = pip_comp_algo;
	nip->meta.check_algo = pip_check_algo;
	nip->meta.version = HAMMER2_INODE_VERSION_ONE;
	hammer2_update_time(&nip->meta.ctime);
	nip->meta.mtime = nip->meta.ctime;
	nip->meta.atime = nip->meta.ctime;
	nip->meta.btime = nip->meta.ctime;
	nip->meta.mode = vap->va_mode;
	nip->meta.nlinks = nip->meta.type == HAMMER2_OBJTYPE_DIRECTORY ? 2 : 1;
#if 0
	/* Authorize setting SGID if needed. */
	if (nip->meta.mode & S_ISGID) {
		if (kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_SECURITY,
		    nip->vp, NULL, genfs_can_chmod(nip->vp, cred,
		    hammer2_inode_to_uid(nip), hammer2_inode_to_gid(nip),
		    vap->va_mode)))
			nip->meta.mode &= ~S_ISGID;
	}
#endif
	if (vap->va_uid != (uid_t)VNOVAL)
		hammer2_guid_to_uuid(&nip->meta.uid, vap->va_uid);
	else
		hammer2_guid_to_uuid(&nip->meta.uid, kauth_cred_geteuid(cred));

	if (vap->va_gid != (gid_t)VNOVAL)
		hammer2_guid_to_uuid(&nip->meta.gid, vap->va_gid);
	else
		nip->meta.gid = pip_gid;

	/*
	 * Regular files and softlinks allow a small amount of data to be
	 * directly embedded in the inode.  This flag will be cleared if
	 * the size is extended past the embedded limit.
	 */
	/* XXX chlock: HAMMER2_OPFLAG_DIRECTDATA is currently disabled. */
#if 0
	if (nip->meta.type == HAMMER2_OBJTYPE_REGFILE ||
	    nip->meta.type == HAMMER2_OBJTYPE_SOFTLINK)
		nip->meta.op_flags |= HAMMER2_OPFLAG_DIRECTDATA;
#endif
	/*
	 * Create the inode using (inum) as the key.  Pass pip for
	 * method inheritance.
	 */
	xop = hammer2_xop_alloc(pip, HAMMER2_XOP_MODIFYING);
	xop->lhc = inum;
	xop->flags = 0;
	xop->meta = nip->meta;
	xop->meta.name_len = hammer2_xop_setname_inum(&xop->head, inum);
	xop->meta.name_key = inum;
	nip->meta.name_len = xop->meta.name_len;
	nip->meta.name_key = xop->meta.name_key;
	hammer2_inode_modify(nip);
	/*
	 * Create the inode media chains but leave them detached.  We are
	 * not in a flush transaction so we can't mess with media topology
	 * above normal inodes (i.e. the index of the inodes themselves).
	 *
	 * We've already set the INODE_CREATING flag.  The inode's media
	 * chains will be inserted onto the media topology on the next
	 * filesystem sync.
	 */
	hammer2_xop_start(&xop->head, &hammer2_inode_create_det_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	if (error) {
		*errorp = error;
		goto done;
	}

	/*
	 * Associate the media chains created by the backend with the
	 * frontend inode.
	 */
	hammer2_inode_repoint(nip, &xop->head.cluster);
done:
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (nip);
}

/*
 * Create a directory entry under dip with the specified name, inode number,
 * and OBJTYPE (type).
 *
 * This returns a UNIX errno code, not a HAMMER2_ERROR_* code.
 *
 * Caller must hold dip locked.
 */
int
hammer2_dirent_create(hammer2_inode_t *dip, const char *name, size_t name_len,
    hammer2_key_t inum, uint8_t type)
{
	hammer2_xop_mkdirent_t *xop;
	hammer2_xop_scanlhc_t *sxop;
	hammer2_key_t lhc, lhcbase;
	int error = 0;

	KKASSERT(name != NULL);
	lhc = hammer2_dirhash(name, name_len);

	/*
	 * Locate the inode or indirect block to create the new
	 * entry in.  At the same time check for key collisions
	 * and iterate until we don't get one.
	 *
	 * Lock the directory exclusively for now to guarantee that
	 * we can find an unused lhc for the name.  Due to collisions,
	 * two different creates can end up with the same lhc so we
	 * cannot depend on the OS to prevent the collision.
	 */
	hammer2_inode_modify(dip);

	/*
	 * If name specified, locate an unused key in the collision space.
	 * Otherwise use the passed-in lhc directly.
	 */
	lhcbase = lhc;
	sxop = hammer2_xop_alloc(dip, HAMMER2_XOP_MODIFYING);
	sxop->lhc = lhc;
	hammer2_xop_start(&sxop->head, &hammer2_scanlhc_desc);
	while ((error = hammer2_xop_collect(&sxop->head, 0)) == 0) {
		if (lhc != sxop->head.cluster.focus->bref.key)
			break;
		++lhc;
	}
	hammer2_xop_retire(&sxop->head, HAMMER2_XOPMASK_VOP);
	if (error) {
		if (error != HAMMER2_ERROR_ENOENT)
			goto done2;
		++lhc;
		error = 0;
	}
	if ((lhcbase ^ lhc) & ~HAMMER2_DIRHASH_LOMASK) {
		error = HAMMER2_ERROR_ENOSPC;
		goto done2;
	}

	/* Create the directory entry with the lhc as the key. */
	xop = hammer2_xop_alloc(dip, HAMMER2_XOP_MODIFYING);
	xop->lhc = lhc;
	bzero(&xop->dirent, sizeof(xop->dirent));
	xop->dirent.inum = inum;
	xop->dirent.type = type;
	xop->dirent.namlen = name_len;
	KKASSERT(name_len < HAMMER2_INODE_MAXNAME);
	hammer2_xop_setname(&xop->head, name, name_len);
	hammer2_xop_start(&xop->head, &hammer2_inode_mkdirent_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
done2:
	return (hammer2_error_to_errno(error));
}

/*
 * Repoint ip->cluster's chains to cluster's chains and fixup the default
 * focus.  All items, valid or invalid, are repointed.
 *
 * Cluster may be NULL to clean out any chains in ip->cluster.
 */
static void
hammer2_inode_repoint(hammer2_inode_t *ip, hammer2_cluster_t *cluster)
{
	hammer2_chain_t *dropch[HAMMER2_MAXCLUSTER];
	hammer2_chain_t *ochain, *nchain;
	int i;

	bzero(dropch, sizeof(dropch));

	/* Drop any cached (typically data) chains related to this inode. */
	hammer2_spin_ex(&ip->cluster_spin);
	for (i = 0; i < ip->ccache_nchains; ++i) {
		dropch[i] = ip->ccache[i].chain;
		ip->ccache[i].flags = 0;
		ip->ccache[i].chain = NULL;
	}
	ip->ccache_nchains = 0;
	hammer2_spin_unex(&ip->cluster_spin);

	while (--i >= 0)
		if (dropch[i]) {
			hammer2_chain_drop(dropch[i]);
			dropch[i] = NULL;
		}

	/*
	 * Replace chains in ip->cluster with chains from cluster and
	 * adjust the focus if necessary.
	 *
	 * NOTE: nchain and/or ochain can be NULL due to gaps
	 *	 in the cluster arrays.
	 */
	hammer2_spin_ex(&ip->cluster_spin);
	for (i = 0; cluster && i < cluster->nchains; ++i) {
		/* Do not replace elements which are the same. */
		nchain = cluster->array[i].chain;
		if (i < ip->cluster.nchains) {
			ochain = ip->cluster.array[i].chain;
			if (ochain == nchain)
				continue;
		} else {
			ochain = NULL;
		}

		/* Make adjustments. */
		ip->cluster.array[i].chain = nchain;
		if (nchain)
			hammer2_chain_ref(nchain);
		dropch[i] = ochain;
	}

	/* Release any left-over chains in ip->cluster. */
	while (i < ip->cluster.nchains) {
		nchain = ip->cluster.array[i].chain;
		if (nchain)
			ip->cluster.array[i].chain = NULL;
		dropch[i] = nchain;
		++i;
	}

	/*
	 * Fixup fields.  Note that the inode-embedded cluster is never
	 * directly locked.
	 */
	if (cluster) {
		ip->cluster.nchains = cluster->nchains;
		ip->cluster.focus = cluster->focus;
		hammer2_assert_cluster(&ip->cluster);
	} else {
		ip->cluster.nchains = 0;
		ip->cluster.focus = NULL;
	}

	hammer2_spin_unex(&ip->cluster_spin);

	/* Cleanup outside of spinlock. */
	while (--i >= 0)
		if (dropch[i])
			hammer2_chain_drop(dropch[i]);
}

/*
 * Repoint a single element from the cluster to the ip.  Does not change
 * focus and requires inode to be re-locked to clean-up flags.
 */
static void
hammer2_inode_repoint_one(hammer2_inode_t *ip, hammer2_cluster_t *cluster,
    int idx)
{
	hammer2_chain_t *dropch[HAMMER2_MAXCLUSTER];
	hammer2_chain_t *ochain, *nchain;
	int i;

	/* Drop any cached (typically data) chains related to this inode. */
	hammer2_spin_ex(&ip->cluster_spin);
	for (i = 0; i < ip->ccache_nchains; ++i) {
		dropch[i] = ip->ccache[i].chain;
		ip->ccache[i].chain = NULL;
	}
	ip->ccache_nchains = 0;
	hammer2_spin_unex(&ip->cluster_spin);

	while (--i >= 0)
		if (dropch[i])
			hammer2_chain_drop(dropch[i]);

	/* Replace inode chain at index. */
	hammer2_spin_ex(&ip->cluster_spin);
	KKASSERT(idx < cluster->nchains);
	if (idx < ip->cluster.nchains) {
		ochain = ip->cluster.array[idx].chain;
		nchain = cluster->array[idx].chain;
	} else {
		ochain = NULL;
		nchain = cluster->array[idx].chain;
		for (i = ip->cluster.nchains; i <= idx; ++i)
			bzero(&ip->cluster.array[i],
			    sizeof(ip->cluster.array[i]));
		ip->cluster.nchains = idx + 1;
		hammer2_assert_cluster(&ip->cluster);
	}
	if (ochain != nchain) {
		/* Make adjustments. */
		ip->cluster.array[idx].chain = nchain;
	}
	hammer2_spin_unex(&ip->cluster_spin);

	if (ochain != nchain) {
		if (nchain)
			hammer2_chain_ref(nchain);
		if (ochain)
			hammer2_chain_drop(ochain);
	}
}

hammer2_key_t
hammer2_inode_data_count(const hammer2_inode_t *ip)
{
	hammer2_chain_t *chain;
	hammer2_key_t count = 0;
	int i;

	for (i = 0; i < ip->cluster.nchains; ++i) {
		chain = ip->cluster.array[i].chain;
		if (chain == NULL)
			continue;
		if (count < chain->bref.embed.stats.data_count)
			count = chain->bref.embed.stats.data_count;
	}

	return (count);
}

hammer2_key_t
hammer2_inode_inode_count(const hammer2_inode_t *ip)
{
	hammer2_chain_t *chain;
	hammer2_key_t count = 0;
	int i;

	for (i = 0; i < ip->cluster.nchains; ++i) {
		chain = ip->cluster.array[i].chain;
		if (chain == NULL)
			continue;
		if (count < chain->bref.embed.stats.inode_count)
			count = chain->bref.embed.stats.inode_count;
	}

	return (count);
}

/*
 * Called with a locked inode to finish unlinking an inode after xop_unlink
 * had been run.  This function is responsible for decrementing nlinks.
 */
int
hammer2_inode_unlink_finisher(hammer2_inode_t *ip, struct vnode **vprecyclep)
{
	struct vnode *vp;
	uint64_t ctime;
	int has_links;

	has_links = ip->meta.type != HAMMER2_OBJTYPE_DIRECTORY &&
	    (int64_t)ip->meta.nlinks > 1;

	/*
	 * Decrement nlinks.  Catch a bad nlinks count here too (e.g. 0 or
	 * negative), and just assume a transition to 0.
	 */
	if (has_links) {
		hammer2_update_time(&ctime);
	} else {
		atomic_set_int(&ip->flags, HAMMER2_INODE_ISUNLINKED);

		/*
		 * Scrap the vnode as quickly as possible.  The vp association
		 * stays intact while we hold the inode locked.  However, vp
		 * can be NULL here.
		 */
		vp = ip->vp;
		cpu_ccfence();

		/*
		 * If no vp is associated there is no high-level state to
		 * deal with and we can scrap the inode immediately.
		 */
		if (vp == NULL) {
			if ((ip->flags & HAMMER2_INODE_DELETING) == 0) {
				atomic_set_int(&ip->flags,
				    HAMMER2_INODE_DELETING);
				hammer2_inode_delayed_sideq(ip);
			}
			return (0);
		}

		/*
		 * Because INODE_ISUNLINKED is set with the inode lock
		 * held, the vnode cannot be ripped up from under us.
		 * There may still be refs so knote anyone waiting for
		 * a delete notification.
		 *
		 * The vnode is not necessarily ref'd due to the unlinking
		 * itself, so we have to defer handling to the end of the
		 * VOP, which will then call hammer2_inode_vprecycle().
		 */
		KKASSERT(vprecyclep == NULL);
	}

	/* Adjust nlinks and retain the inode on the media for now. */
	hammer2_inode_modify(ip);
	if (has_links) {
		--ip->meta.nlinks;
		ip->meta.ctime = ctime;
	} else {
		ip->meta.nlinks = 0;
	}

	return (0);
}

/*
 * Mark an inode as being modified, meaning that the caller will modify
 * ip->meta.
 *
 * If a vnode is present we set the vnode dirty and the nominal filesystem
 * sync will also handle synchronizing the inode meta-data.  Unless NOSIDEQ
 * we must ensure that the inode is on pmp->sideq.
 *
 * NOTE: We must always queue the inode to the sideq.  This allows H2 to
 *	 shortcut vsyncscan() and flush inodes and their related vnodes
 *	 in a two stages.  H2 still calls vfsync() for each vnode.
 *
 * NOTE: No mtid (modify_tid) is passed into this routine.  The caller is
 *	 only modifying the in-memory inode.  A modify_tid is synchronized
 *	 later when the inode gets flushed.
 *
 * NOTE: As an exception to the general rule, the inode MAY be locked
 *	 shared for this particular call.
 */
void
hammer2_inode_modify(hammer2_inode_t *ip)
{
	atomic_set_int(&ip->flags, HAMMER2_INODE_MODIFIED);
	/* DragonFly uses DragonFly's vsyncscan specific vsetisdirty() here. */

	hammer2_inode_vhold(ip);
	if (ip->pmp && (ip->flags & HAMMER2_INODE_NOSIDEQ) == 0)
		hammer2_inode_delayed_sideq(ip);
}

/*
 * This function was originally required by NetBSD VFS sync.
 * This doesn't exist in DragonFly HAMMER2.
 */
void
hammer2_inode_vhold(hammer2_inode_t *ip)
{
	KKASSERT(ip->refs > 0);
	KKASSERT(ip->vhold >= 0);

	/* ip->vp can still be NULL on inode creation. */
	if (ip->vp) {
		hammer2_mtx_ex(&ip->vhold_lock);
		if (ip->vhold == 0) { /* optimization */
			vref(ip->vp);
			ip->vhold++;
		}
		KKASSERT(ip->vhold > 0);
		hammer2_mtx_unlock(&ip->vhold_lock);
	}
}

/*
 * This function was originally required by NetBSD VFS sync.
 * This doesn't exist in DragonFly HAMMER2.
 */
void
hammer2_inode_vdrop(hammer2_inode_t *ip, int n)
{
	KKASSERT(ip->refs > 0);
	KKASSERT(ip->vhold >= 0);
	KKASSERT(ip->vp);

	if (n > ip->vhold)
		hpanic("arg %d > vhold %d", n, ip->vhold);

	hammer2_mtx_ex(&ip->vhold_lock);
	while (n > 0) {
		vrele(ip->vp);
		ip->vhold--;
		n--;
	}
	KKASSERT(ip->vhold >= 0);
	hammer2_mtx_unlock(&ip->vhold_lock);
}

/*
 * Synchronize the inode's frontend state with the chain state prior
 * to any explicit flush of the inode or any strategy write call.  This
 * does not flush the inode's chain or its sub-topology to media (higher
 * level layers are responsible for doing that).
 *
 * Called with a locked inode inside a normal transaction.
 * Inode must be locked.
 */
int
hammer2_inode_chain_sync(hammer2_inode_t *ip)
{
	hammer2_xop_fsync_t *xop;
	int error = 0;

	if (ip->flags & (HAMMER2_INODE_RESIZED | HAMMER2_INODE_MODIFIED)) {
		xop = hammer2_xop_alloc(ip, HAMMER2_XOP_MODIFYING);
		xop->clear_directdata = 0;
		if (ip->flags & HAMMER2_INODE_RESIZED) {
			if ((ip->meta.op_flags & HAMMER2_OPFLAG_DIRECTDATA) &&
			    ip->meta.size > HAMMER2_EMBEDDED_BYTES) {
				ip->meta.op_flags &= ~HAMMER2_OPFLAG_DIRECTDATA;
				xop->clear_directdata = 1;
			}
			xop->osize = ip->osize;
		} else {
			xop->osize = ip->meta.size; /* safety */
		}
		xop->ipflags = ip->flags;
		xop->meta = ip->meta;
		atomic_clear_int(&ip->flags,
		    HAMMER2_INODE_RESIZED | HAMMER2_INODE_MODIFIED);
		hammer2_xop_start(&xop->head, &hammer2_inode_chain_sync_desc);
		error = hammer2_xop_collect(&xop->head, 0);
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		if (error == HAMMER2_ERROR_ENOENT)
			error = 0;
		if (error) {
			hprintf("unable to fsync inode %016llx\n",
			    (long long)ip->meta.inum);
			/* XXX return error somehow? */
		}
	}

	return (error);
}

/*
 * When an inode is flagged INODE_CREATING its chains have not actually
 * been inserting into the on-media tree yet.
 */
int
hammer2_inode_chain_ins(hammer2_inode_t *ip)
{
	hammer2_xop_create_t *xop;
	int error = 0;

	if (ip->flags & HAMMER2_INODE_CREATING) {
		atomic_clear_int(&ip->flags, HAMMER2_INODE_CREATING);
		xop = hammer2_xop_alloc(ip, HAMMER2_XOP_MODIFYING);
		xop->lhc = ip->meta.inum;
		xop->flags = 0;
		hammer2_xop_start(&xop->head, &hammer2_inode_create_ins_desc);
		error = hammer2_xop_collect(&xop->head, 0);
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		if (error == HAMMER2_ERROR_ENOENT)
			error = 0;
		if (error) {
			hprintf("backend unable to insert inum %016llx\n",
			    (long long)ip->meta.inum);
			/* XXX return error somehow? */
		}
	}
	return (error);
}

/*
 * When an inode is flagged INODE_DELETING it has been deleted (no directory
 * entry or open refs are left, though as an optimization H2 might leave
 * nlinks == 1 to avoid unnecessary block updates).  The backend flush then
 * needs to actually remove it from the topology.
 *
 * NOTE: backend flush must still sync and flush the deleted inode to clean
 *	 out related chains.
 *
 * NOTE: We must clear not only INODE_DELETING, but also INODE_ISUNLINKED
 *	 to prevent the vnode reclaim code from trying to delete it twice.
 */
int
hammer2_inode_chain_des(hammer2_inode_t *ip)
{
	hammer2_xop_destroy_t *xop;
	int error = 0;

	if (ip->flags & HAMMER2_INODE_DELETING) {
		atomic_clear_int(&ip->flags,
		    HAMMER2_INODE_DELETING | HAMMER2_INODE_ISUNLINKED);
		xop = hammer2_xop_alloc(ip, HAMMER2_XOP_MODIFYING);
		hammer2_xop_start(&xop->head, &hammer2_inode_destroy_desc);
		error = hammer2_xop_collect(&xop->head, 0);
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		if (error == HAMMER2_ERROR_ENOENT)
			error = 0;
		if (error) {
			hprintf("backend unable to delete inode %016llx\n",
			    (long long)ip->meta.inum);
			/* XXX return error somehow? */
		}
	}
	return (error);
}

/*
 * Flushes the inode's chain and its sub-topology to media.  Interlocks
 * HAMMER2_INODE_DIRTYDATA by clearing it prior to the flush.  Any strategy
 * function creating or modifying a chain under this inode will re-set the
 * flag.
 *
 * Inode must be locked.
 */
int
hammer2_inode_chain_flush(hammer2_inode_t *ip, int flags)
{
	hammer2_xop_flush_t *xop;
	int error;

	atomic_clear_int(&ip->flags, HAMMER2_INODE_DIRTYDATA);
	xop = hammer2_xop_alloc(ip, HAMMER2_XOP_MODIFYING | flags);
	hammer2_xop_start(&xop->head, &hammer2_inode_flush_desc);
	error = hammer2_xop_collect(&xop->head, HAMMER2_XOP_COLLECT_WAITALL);
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	if (error == HAMMER2_ERROR_ENOENT)
		error = 0;

	return (error);
}

/*
 * Check if source directory is in the path of the target directory.
 */
int
hammer2_checkpath(const hammer2_inode_t *dip, hammer2_inode_t *tdip)
{
	hammer2_xop_lookup_t *xop;
	hammer2_chain_t *chain;
	hammer2_inode_t *ip;
	const hammer2_inode_data_t *ipdata;
	hammer2_tid_t inum = tdip->meta.inum;
	int error;

	KKASSERT(dip != tdip);
	KKASSERT(dip->meta.type == HAMMER2_OBJTYPE_DIRECTORY);
	KKASSERT(tdip->meta.type == HAMMER2_OBJTYPE_DIRECTORY);

	while (inum != 1) {
		if (inum == tdip->meta.inum) {
			ip = tdip;
			hammer2_inode_ref(ip);
		} else {
			ip = hammer2_inode_lookup(dip->pmp, inum);
		}
		if (ip) {
			if (dip->meta.inum == ip->meta.iparent) {
				hammer2_inode_drop(ip);
				return (EINVAL);
			}
			inum = ip->meta.iparent;
			hammer2_inode_drop(ip);
			ip = NULL;
			continue;
		}
		if (inum == tdip->meta.inum) {
			chain = hammer2_inode_chain(tdip, 0,
			    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
			if (chain) {
				ipdata = &chain->data->ipdata;
				if (dip->meta.inum == ipdata->meta.iparent) {
					hammer2_chain_unlock(chain);
					hammer2_chain_drop(chain);
					return (EINVAL);
				}
				inum = ipdata->meta.iparent;
				hammer2_chain_unlock(chain);
				hammer2_chain_drop(chain);
			} else {
				return (EIO);
			}
		} else {
			xop = hammer2_xop_alloc(dip->pmp->iroot, 0);
			xop->lhc = inum;
			hammer2_xop_start(&xop->head, &hammer2_lookup_desc);
			error = hammer2_xop_collect(&xop->head, 0);
			if (error == 0) {
				ipdata = &hammer2_xop_gdata(&xop->head)->ipdata;
				if (dip->meta.inum == ipdata->meta.iparent) {
					hammer2_xop_pdata(&xop->head);
					hammer2_xop_retire(&xop->head,
					    HAMMER2_XOPMASK_VOP);
					return (EINVAL);
				}
				inum = ipdata->meta.iparent;
				hammer2_xop_pdata(&xop->head);
			}
			hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
			if (error) {
				error = hammer2_error_to_errno(error);
				switch (error) {
				case ENOENT:
					hprintf("inum %016llx chain not found\n",
					    (long long)inum);
					return (0); /* XXX not synced yet */
				default:
					return (error);
				}
			}
		}
	}

	return (0);
}
