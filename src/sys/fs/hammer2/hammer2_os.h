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

#ifndef _FS_HAMMER2_OS_H_
#define _FS_HAMMER2_OS_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/pool.h>
#include <sys/vnode.h>
#include <sys/atomic.h>

#include "hammer2_compat.h"

#ifdef INVARIANTS
#define HFMT	"%s(%s|%d): "
#define HARGS	__func__, \
    curproc ? curproc->p_comm : "-", \
    curlwp ? curlwp->l_lid : -1
#else
#define HFMT	"%s: "
#define HARGS	__func__
#endif

#define hprintf(X, ...)	printf(HFMT X, HARGS, ## __VA_ARGS__)
#define hpanic(X, ...)	panic(HFMT X, HARGS, ## __VA_ARGS__)

#ifdef INVARIANTS
#if 0
#define debug_hprintf	hprintf
#else
#define debug_hprintf(X, ...)	do {} while (0)
#endif
#else
#define debug_hprintf(X, ...)	do {} while (0)
#endif

/* hammer2_lk is lockmgr(9) in DragonFly. */
typedef kmutex_t hammer2_lk_t;

#define hammer2_lk_init(p, s)		mutex_init(p, MUTEX_DEFAULT, IPL_NONE)
#define hammer2_lk_ex(p)		mutex_enter(p)
#define hammer2_lk_unlock(p)		mutex_exit(p)
#define hammer2_lk_destroy(p)		mutex_destroy(p)

#define hammer2_lk_assert_ex(p)		KASSERT(mutex_owned(p))
//#define hammer2_lk_assert_unlocked(p)

typedef kcondvar_t hammer2_lkc_t;

#define hammer2_lkc_init(c, s)		cv_init(c, s)
#define hammer2_lkc_destroy(c)		cv_destroy(c)
#define hammer2_lkc_sleep(c, p, s)	cv_wait(c, p)
#define hammer2_lkc_wakeup(c)		cv_broadcast(c)

/*
 * Mutex and spinlock shims.
 * Normal synchronous non-abortable locks can be substituted for spinlocks.
 * NetBSD HAMMER2 currently uses rwlock(9) for both mtx and spinlock.
 */
struct krwlock_t_wrapper {
	krwlock_t lock;
	int refs;
};
typedef struct krwlock_t_wrapper hammer2_mtx_t;

#define hammer2_mtx_init(p, s)		\
	do { bzero(p, sizeof(*(p))); rw_init(&(p)->lock); } while (0)
#define hammer2_mtx_ex(p)		\
	do { rw_enter(&(p)->lock, RW_WRITER); (p)->refs++; } while (0)
#define hammer2_mtx_sh(p)		\
	do { rw_enter(&(p)->lock, RW_READER); (p)->refs++; } while (0)
#define hammer2_mtx_unlock(p)		\
	do { (p)->refs--; rw_exit(&(p)->lock); } while (0)
#define hammer2_mtx_refs(p)		((p)->refs)
#define hammer2_mtx_destroy(p)		rw_destroy(&(p)->lock)

/* Non-zero if exclusively locked by the calling thread. */
#define hammer2_mtx_owned(p)		rw_write_held(&(p)->lock)

#define hammer2_mtx_assert_ex(p)	KASSERT(rw_write_held(&(p)->lock))
#define hammer2_mtx_assert_sh(p)	KASSERT(rw_read_held(&(p)->lock))
#define hammer2_mtx_assert_locked(p)	KASSERT(rw_lock_held(&(p)->lock))
#define hammer2_mtx_assert_unlocked(p)	KASSERT(!rw_lock_held(&(p)->lock))

static __inline int
hammer2_mtx_ex_try(hammer2_mtx_t *p)
{
	if (rw_tryenter(&p->lock, RW_WRITER)) {
		p->refs++;
		return (0);
	} else {
		return (1);
	}
}

static __inline int
hammer2_mtx_sh_try(hammer2_mtx_t *p)
{
	if (rw_tryenter(&p->lock, RW_READER)) {
		p->refs++;
		return (0);
	} else {
		return (1);
	}
}

static __inline int
hammer2_mtx_upgrade_try(hammer2_mtx_t *p)
{
	/* rw_tryupgrade() panics with DIAGNOSTIC if already ex-locked. */
	if (hammer2_mtx_owned(p))
		return (0);

	if (rw_tryupgrade(&p->lock))
		return (0);
	else
		return (1);
}

static __inline int
hammer2_mtx_temp_release(hammer2_mtx_t *p)
{
	int x;

	x = hammer2_mtx_owned(p);
	hammer2_mtx_unlock(p);

	return (x);
}

static __inline void
hammer2_mtx_temp_restore(hammer2_mtx_t *p, int x)
{
	if (x)
		hammer2_mtx_ex(p);
	else
		hammer2_mtx_sh(p);
}

typedef krwlock_t hammer2_spin_t;

#define hammer2_spin_init(p, s)		rw_init(p)
#define hammer2_spin_ex(p)		rw_enter(p, RW_WRITER)
#define hammer2_spin_sh(p)		rw_enter(p, RW_READER)
#define hammer2_spin_unex(p)		rw_exit(p)
#define hammer2_spin_unsh(p)		rw_exit(p)
#define hammer2_spin_destroy(p)		rw_destroy(p)

#define hammer2_spin_assert_ex(p)	KASSERT(rw_write_held(p))
#define hammer2_spin_assert_sh(p)	KASSERT(rw_read_held(p))
#define hammer2_spin_assert_locked(p)	KASSERT(rw_lock_held(p))
#define hammer2_spin_assert_unlocked(p)	KASSERT(!rw_lock_held(p))

MALLOC_DECLARE(M_HAMMER2);
MALLOC_DECLARE(M_HAMMER2_RBUF);
MALLOC_DECLARE(M_HAMMER2_WBUF);
MALLOC_DECLARE(M_HAMMER2_LZ4);
MALLOC_DECLARE(M_TEMP); /* nonexistent in sys/sys/malloc.h */
extern struct pool hammer2_pool_inode;
extern struct pool hammer2_pool_xops;

extern int malloc_leak_m_hammer2;
extern int malloc_leak_m_hammer2_rbuf;
extern int malloc_leak_m_hammer2_wbuf;
extern int malloc_leak_m_hammer2_lz4;
extern int malloc_leak_m_temp;

#ifdef HAMMER2_MALLOC
static __inline void
adjust_malloc_leak(int delta, struct malloc_type *type)
{
	int *lp;

	if (type == M_HAMMER2)
		lp = &malloc_leak_m_hammer2;
	else if (type == M_HAMMER2_RBUF)
		lp = &malloc_leak_m_hammer2_rbuf;
	else if (type == M_HAMMER2_WBUF)
		lp = &malloc_leak_m_hammer2_wbuf;
	else if (type == M_HAMMER2_LZ4)
		lp = &malloc_leak_m_hammer2_lz4;
	else if (type == M_TEMP)
		lp = &malloc_leak_m_temp;
	else
		hpanic("bad malloc type");

	atomic_add_int(lp, delta);
}

static __inline void *
hmalloc(size_t size, struct malloc_type *type, int flags)
{
	void *addr;

	flags &= ~M_WAITOK;
	flags |= M_NOWAIT;

	addr = malloc(size, type, flags);
	KASSERTMSG(addr, "size %ld flags %x malloc_leak %d,%d,%d,%d,%d",
	    (long)size, flags,
	    malloc_leak_m_hammer2,
	    malloc_leak_m_hammer2_rbuf,
	    malloc_leak_m_hammer2_wbuf,
	    malloc_leak_m_hammer2_lz4,
	    malloc_leak_m_temp);
	if (addr) {
		KKASSERT(size > 0);
		adjust_malloc_leak(size, type);
	}

	return (addr);
}

static __inline void *
hrealloc(void *addr, size_t size, struct malloc_type *type, int flags)
{
	flags &= ~M_WAITOK;
	flags |= M_NOWAIT;

	addr = realloc(addr, size, type, flags);
	KASSERTMSG(addr, "size %ld flags %x malloc_leak %d,%d,%d",
	    (long)size, flags,
	    malloc_leak_m_hammer2,
	    malloc_leak_m_hammer2_lz4,
	    malloc_leak_m_temp);
	if (addr) {
		KKASSERT(size > 0);
		adjust_malloc_leak(size, type);
	}

	return (addr);
}

/* OpenBSD style free(9) with 3 arguments */
static __inline void
hfree(void *addr, struct malloc_type *type, size_t freedsize)
{
	if (addr) {
		KKASSERT(freedsize > 0);
		adjust_malloc_leak(-(int)freedsize, type);
	}
	free(addr, type);
}

static __inline char *
hstrdup(const char *str)
{
	size_t len;
	char *copy;

	len = strlen(str) + 1;
	copy = hmalloc(len, M_TEMP, M_NOWAIT);
	if (copy == NULL)
		return (NULL);
	bcopy(str, copy, len);

	return (copy);
}

static __inline void
hstrfree(char *str)
{
	hfree(str, M_TEMP, strlen(str) + 1);
}
#else
static __inline void
adjust_malloc_leak(int delta __unused, struct malloc_type *type __unused)
{
}
#define hmalloc(size, type, flags)		malloc(size, type, flags)
#define hrealloc(addr, size, type, flags)	realloc(addr, size, type, flags)
#define hfree(addr, type, freedsize)		free(addr, type)
#define hstrdup(str)				kmem_strdup(str, KM_SLEEP)
#define hstrfree(str)				kmem_strfree(str)
#endif

extern int (**hammer2_vnodeop_p)(void *);
extern int (**hammer2_specop_p)(void *);
extern int (**hammer2_fifoop_p)(void *);

extern const struct vnodeopv_desc hammer2_vnodeop_opv_desc;
extern const struct vnodeopv_desc hammer2_specop_opv_desc;
extern const struct vnodeopv_desc hammer2_fifoop_opv_desc;

#endif /* !_FS_HAMMER2_OS_H_ */
