/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
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

#include "hammer2.h"

struct hammer2_fiterate {
	hammer2_off_t	bpref;
	hammer2_off_t	bnext;
	int		loops;
	int		relaxed;
};

typedef struct hammer2_fiterate hammer2_fiterate_t;

static int hammer2_freemap_try_alloc(hammer2_chain_t **, hammer2_blockref_t *,
    int, hammer2_fiterate_t *, hammer2_tid_t);
static void hammer2_freemap_init(hammer2_dev_t *, hammer2_key_t,
    hammer2_chain_t *);
static int hammer2_bmap_alloc(hammer2_dev_t *, hammer2_bmap_data_t *, uint16_t,
    int, int, int, hammer2_key_t *);
static int hammer2_freemap_iterate(hammer2_chain_t **, hammer2_chain_t **,
    hammer2_fiterate_t *);

/*
 * Calculate the device offset for the specified FREEMAP_NODE or FREEMAP_LEAF
 * bref.  Return a combined media offset and physical size radix.  Freemap
 * chains use fixed storage offsets in the 4MB reserved area at the
 * beginning of each 1GB zone.
 *
 * Rotate between eight possibilities.  Theoretically this means we have seven
 * good freemaps in case of a crash which we can use as a base for the fixup
 * scan at mount-time.
 */
static int
hammer2_freemap_reserve(hammer2_chain_t *chain, int radix)
{
	hammer2_blockref_t *bref = &chain->bref;
	hammer2_off_t off;
	int index, index_inc;
#ifdef INVARIANTS
	size_t bytes;

	/* Physical allocation size. */
	bytes = (size_t)1 << radix;
#endif
	/*
	 * Calculate block selection index 0..7 of current block.  If this
	 * is the first allocation of the block (verses a modification of an
	 * existing block), we use index 0, otherwise we use the next rotating
	 * index.
	 */
	if ((bref->data_off & ~HAMMER2_OFF_MASK_RADIX) == 0) {
		index = 0;
	} else {
		off = bref->data_off & ~HAMMER2_OFF_MASK_RADIX &
		    HAMMER2_SEGMASK;
		off = off / HAMMER2_PBUFSIZE;
		KKASSERT(off >= HAMMER2_ZONE_FREEMAP_00 &&
		    off < HAMMER2_ZONE_FREEMAP_END);
		index = (int)(off - HAMMER2_ZONE_FREEMAP_00) /
		    HAMMER2_ZONE_FREEMAP_INC;
		KKASSERT(index >= 0 && index < HAMMER2_NFREEMAPS);
		if (++index == HAMMER2_NFREEMAPS)
			index = 0;
	}

	/*
	 * Calculate the block offset of the reserved block.  This will
	 * point into the 4MB reserved area at the base of the appropriate
	 * 2GB zone, once added to the FREEMAP_x selection above.
	 */
	index_inc = index * HAMMER2_ZONE_FREEMAP_INC;

	switch (bref->keybits) {
	/* case HAMMER2_FREEMAP_LEVEL6_RADIX: not applicable */
	case HAMMER2_FREEMAP_LEVEL5_RADIX:	/* 4EB */
		KKASSERT(bref->type == HAMMER2_BREF_TYPE_FREEMAP_NODE);
		KKASSERT(bytes == HAMMER2_FREEMAP_LEVELN_PSIZE);
		off = H2FMBASE(bref->key, HAMMER2_FREEMAP_LEVEL5_RADIX) +
		    (index_inc + HAMMER2_ZONE_FREEMAP_00 +
		    HAMMER2_ZONEFM_LEVEL5) * HAMMER2_PBUFSIZE;
		break;
	case HAMMER2_FREEMAP_LEVEL4_RADIX:	/* 16PB */
		KKASSERT(bref->type == HAMMER2_BREF_TYPE_FREEMAP_NODE);
		KKASSERT(bytes == HAMMER2_FREEMAP_LEVELN_PSIZE);
		off = H2FMBASE(bref->key, HAMMER2_FREEMAP_LEVEL4_RADIX) +
		    (index_inc + HAMMER2_ZONE_FREEMAP_00 +
		    HAMMER2_ZONEFM_LEVEL4) * HAMMER2_PBUFSIZE;
		break;
	case HAMMER2_FREEMAP_LEVEL3_RADIX:	/* 64TB */
		KKASSERT(bref->type == HAMMER2_BREF_TYPE_FREEMAP_NODE);
		KKASSERT(bytes == HAMMER2_FREEMAP_LEVELN_PSIZE);
		off = H2FMBASE(bref->key, HAMMER2_FREEMAP_LEVEL3_RADIX) +
		    (index_inc + HAMMER2_ZONE_FREEMAP_00 +
		    HAMMER2_ZONEFM_LEVEL3) * HAMMER2_PBUFSIZE;
		break;
	case HAMMER2_FREEMAP_LEVEL2_RADIX:	/* 256GB */
		KKASSERT(bref->type == HAMMER2_BREF_TYPE_FREEMAP_NODE);
		KKASSERT(bytes == HAMMER2_FREEMAP_LEVELN_PSIZE);
		off = H2FMBASE(bref->key, HAMMER2_FREEMAP_LEVEL2_RADIX) +
		    (index_inc + HAMMER2_ZONE_FREEMAP_00 +
		    HAMMER2_ZONEFM_LEVEL2) * HAMMER2_PBUFSIZE;
		break;
	case HAMMER2_FREEMAP_LEVEL1_RADIX:	/* 1GB */
		KKASSERT(bref->type == HAMMER2_BREF_TYPE_FREEMAP_LEAF);
		KKASSERT(bytes == HAMMER2_FREEMAP_LEVELN_PSIZE);
		off = H2FMBASE(bref->key, HAMMER2_FREEMAP_LEVEL1_RADIX) +
		    (index_inc + HAMMER2_ZONE_FREEMAP_00 +
		    HAMMER2_ZONEFM_LEVEL1) * HAMMER2_PBUFSIZE;
		break;
	default:
		hpanic("bad radix %d", bref->keybits);
		break;
	}
	bref->data_off = off | radix;

	return (0);
}

/*
 * Normal freemap allocator.
 *
 * Use available hints to allocate space using the freemap.  Create missing
 * freemap infrastructure on-the-fly as needed (including marking initial
 * allocations using the iterator as allocated, instantiating new 2GB zones,
 * and dealing with the end-of-media edge case).
 *
 * bpref is only used as a heuristic to determine locality of reference.
 * This function is a NOP if bytes is 0.
 */
int
hammer2_freemap_alloc(hammer2_chain_t *chain, size_t bytes)
{
	hammer2_dev_t *hmp = chain->hmp;
	hammer2_blockref_t *bref = &chain->bref;
	hammer2_chain_t *parent;
	hammer2_tid_t mtid;
	hammer2_fiterate_t iter;
	int radix, error;
	unsigned int hindex;

	/*
	 * If allocating or downsizing to zero we just get rid of whatever
	 * data_off we had.
	 */
	if (bytes == 0) {
		bref->data_off = 0;
		return (0);
	}

	KKASSERT(hmp->spmp);
	mtid = hammer2_trans_sub(hmp->spmp);

	/*
	 * Validate the allocation size.  It must be a power of 2.
	 * For now require that the caller be aware of the minimum
	 * allocation (1K).
	 */
	radix = hammer2_getradix(bytes);
	KKASSERT((size_t)1 << radix == bytes);

	if (bref->type == HAMMER2_BREF_TYPE_FREEMAP_NODE ||
	    bref->type == HAMMER2_BREF_TYPE_FREEMAP_LEAF) {
		/*
		 * Freemap blocks themselves are assigned from the reserve
		 * area, not allocated from the freemap.
		 */
		return (hammer2_freemap_reserve(chain, radix));
	}

	KKASSERT(bytes >= HAMMER2_ALLOC_MIN && bytes <= HAMMER2_ALLOC_MAX);

	/*
	 * Heuristic tracking index.  We would like one for each distinct
	 * bref type if possible.  heur_freemap[] has room for two classes
	 * for each type.  At a minimum we have to break-up our heuristic
	 * by device block sizes.
	 */
	hindex = HAMMER2_PBUFRADIX - HAMMER2_LBUFRADIX;
	KKASSERT(hindex < HAMMER2_FREEMAP_HEUR_NRADIX);
	hindex += bref->type * HAMMER2_FREEMAP_HEUR_NRADIX;
	hindex &= HAMMER2_FREEMAP_HEUR_TYPES * HAMMER2_FREEMAP_HEUR_NRADIX - 1;
	KKASSERT(hindex < HAMMER2_FREEMAP_HEUR_SIZE);

	iter.bpref = hmp->heur_freemap[hindex];
	iter.relaxed = hmp->freemap_relaxed;

	/*
	 * Make sure bpref is in-bounds.  It's ok if bpref covers a zone's
	 * reserved area, the try code will iterate past it.
	 */
	if (iter.bpref > hmp->total_size)
		iter.bpref = hmp->total_size - 1;

	/* Iterate the freemap looking for free space before and after. */
	parent = &hmp->fchain;
	hammer2_chain_ref(parent);
	hammer2_chain_lock(parent, HAMMER2_RESOLVE_ALWAYS);
	error = HAMMER2_ERROR_EAGAIN;
	iter.bnext = iter.bpref;
	iter.loops = 0;

	while (error == HAMMER2_ERROR_EAGAIN)
		error = hammer2_freemap_try_alloc(&parent, bref, radix, &iter,
		    mtid);
	hmp->freemap_relaxed |= iter.relaxed; /* heuristical, SMP race ok */
	hmp->heur_freemap[hindex] = iter.bnext;
	hammer2_chain_unlock(parent);
	hammer2_chain_drop(parent);

	return (error);
}

static int
hammer2_freemap_try_alloc(hammer2_chain_t **parentp, hammer2_blockref_t *bref,
    int radix, hammer2_fiterate_t *iter, hammer2_tid_t mtid)
{
	hammer2_dev_t *hmp = (*parentp)->hmp;
	hammer2_off_t l0size, l1size, l1mask, key;
	hammer2_key_t key_dummy, base_key;
	hammer2_chain_t *chain;
	hammer2_bmap_data_t *bmap;
	uint16_t class;
	int error, count, start, n, availchk;
#ifdef INVARIANTS
	size_t bytes;

	/* Calculate the number of bytes being allocated. */
	bytes = (size_t)1 << radix;
#endif
	class = (bref->type << 8) | HAMMER2_PBUFRADIX;

	/*
	 * Lookup the level1 freemap chain, creating and initializing one
	 * if necessary.  Intermediate levels will be created automatically
	 * when necessary by hammer2_chain_create().
	 */
	key = H2FMBASE(iter->bnext, HAMMER2_FREEMAP_LEVEL1_RADIX);
	l0size = HAMMER2_FREEMAP_LEVEL0_SIZE;
	l1size = HAMMER2_FREEMAP_LEVEL1_SIZE;
	l1mask = l1size - 1;

	chain = hammer2_chain_lookup(parentp, &key_dummy, key, key + l1mask,
	    &error, HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_MATCHIND);
	if (chain == NULL) {
		/*
		 * Create the missing leaf, be sure to initialize
		 * the auxillary freemap tracking information in
		 * the bref.check.freemap structure.
		 */
		error = hammer2_chain_create(parentp, &chain, NULL, hmp->spmp,
		    HAMMER2_METH_DEFAULT, key, HAMMER2_FREEMAP_LEVEL1_RADIX,
		    HAMMER2_BREF_TYPE_FREEMAP_LEAF, HAMMER2_FREEMAP_LEVELN_PSIZE,
		    mtid, 0, 0);
		KKASSERT(error == 0);
		if (error == 0) {
			hammer2_chain_modify(chain, mtid, 0, 0);
			bzero(&chain->data->bmdata[0],
			    HAMMER2_FREEMAP_LEVELN_PSIZE);
			chain->bref.check.freemap.bigmask = (uint32_t)-1;
			chain->bref.check.freemap.avail = l1size;
			/* bref.methods should already be inherited. */
			hammer2_freemap_init(hmp, key, chain);
		}
	} else if (chain->error) {
		/* Error during lookup. */
		hprintf("error %d at data_off %016llx\n",
		    chain->error, (long long)bref->data_off);
		error = HAMMER2_ERROR_EIO;
	} else if ((chain->bref.check.freemap.bigmask &
	    ((size_t)1 << radix)) == 0) {
		/* Already flagged as not having enough space. */
		error = HAMMER2_ERROR_ENOSPC;
	} else {
		/* Modify existing chain to setup for adjustment. */
		hammer2_chain_modify(chain, mtid, 0, 0);
	}

	/* Scan 4MB entries. */
	if (error == 0) {
		KKASSERT(chain->bref.type == HAMMER2_BREF_TYPE_FREEMAP_LEAF);
		start = (int)((iter->bnext - key) >>
		    HAMMER2_FREEMAP_LEVEL0_RADIX);
		KKASSERT(start >= 0 && start < HAMMER2_FREEMAP_COUNT);
		hammer2_chain_modify(chain, mtid, 0, 0);

		error = HAMMER2_ERROR_ENOSPC;
		for (count = 0; count < HAMMER2_FREEMAP_COUNT; ++count) {
			if (start + count >= HAMMER2_FREEMAP_COUNT &&
			    start - count < 0)
				break;

			/*
			 * Calculate bmap pointer from thart starting index
			 * forwards.
			 * NOTE: bmap pointer is invalid if n >= FREEMAP_COUNT.
			 */
			n = start + count;
			bmap = &chain->data->bmdata[n];
			if (n >= HAMMER2_FREEMAP_COUNT)
				availchk = 0;
			else if (bmap->avail)
				availchk = 1;
			else if (radix < HAMMER2_FREEMAP_BLOCK_RADIX &&
			    (bmap->linear & HAMMER2_FREEMAP_BLOCK_MASK))
				availchk = 1;
			else
				availchk = 0;

			/*
			 * Try to allocate from a matching freemap class
			 * superblock.  If we are in relaxed mode we allocate
			 * from any freemap class superblock.
			 * NOTE: superblock ???
			 */
			if (availchk && (bmap->class == 0 ||
			    bmap->class == class || iter->relaxed)) {
				base_key = key + n * l0size;
				error = hammer2_bmap_alloc(hmp, bmap, class, n,
				    (int)bref->key, radix, &base_key);
				if (error != HAMMER2_ERROR_ENOSPC) {
					key = base_key;
					break;
				}
			}

			/*
			 * Calculate bmap pointer from the starting index
			 * backwards (locality).
			 *
			 * Must recalculate after potentially having called
			 * hammer2_bmap_alloc() above in case chain was
			 * reallocated.
			 * NOTE: bmap pointer is invalid if n < 0.
			 */
			n = start - count;
			bmap = &chain->data->bmdata[n];
			if (n < 0)
				availchk = 0;
			else if (bmap->avail)
				availchk = 1;
			else if (radix < HAMMER2_FREEMAP_BLOCK_RADIX &&
			    (bmap->linear & HAMMER2_FREEMAP_BLOCK_MASK))
				availchk = 1;
			else
				availchk = 0;

			/*
			 * Try to allocate from a matching freemap class
			 * superblock.  If we are in relaxed mode we allocate
			 * from any freemap class superblock.
			 * NOTE: superblock ???
			 */
			if (availchk && (bmap->class == 0 ||
			    bmap->class == class || iter->relaxed)) {
				base_key = key + n * l0size;
				error = hammer2_bmap_alloc(hmp, bmap, class, n,
				    (int)bref->key, radix, &base_key);
				if (error != HAMMER2_ERROR_ENOSPC) {
					key = base_key;
					break;
				}
			}
		}

		/*
		 * We only know for sure that we can clear the bitmap bit
		 * if we scanned the entire array (start == 0) in relaxed mode.
		 */
		if (error == HAMMER2_ERROR_ENOSPC && start == 0 &&
		    iter->relaxed)
			chain->bref.check.freemap.bigmask &=
			    (uint32_t)~((size_t)1 << radix);

		/* XXX also scan down from original count. */
	}

	if (error == 0) {
		/*
		 * Assert validity.  Must be beyond the static allocator used
		 * by newfs_hammer2 (and thus also beyond the aux area),
		 * not go past the volume size, and must not be in the
		 * reserved segment area for a zone.
		 */
		KKASSERT(key >= hmp->voldata.allocator_beg &&
		    key + bytes <= hmp->total_size);
		KKASSERT((key & HAMMER2_ZONE_MASK64) >= HAMMER2_ZONE_SEG);
		bref->data_off = key | radix;

		/*
		 * Record dedupability.  The dedup bits are cleared
		 * when bulkfree transitions the freemap from 11->10,
		 * and asserted to be clear on the 10->00 transition.
		 *
		 * We must record the bitmask with the chain locked
		 * at the time we set the allocation bits to avoid
		 * racing a bulkfree.
		 */
		if (bref->type == HAMMER2_BREF_TYPE_DATA)
			hammer2_io_dedup_set(hmp, bref);
	} else if (error == HAMMER2_ERROR_ENOSPC) {
		/*
		 * Return EAGAIN with next iteration in iter->bnext, or
		 * return ENOSPC if the allocation map has been exhausted.
		 */
		error = hammer2_freemap_iterate(parentp, &chain, iter);
	}

	/* Cleanup. */
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	return (error);
}

/*
 * Allocate (1<<radix) bytes from the bmap whos base data offset is (*basep).
 *
 * If the linear iterator is mid-block we use it directly (the bitmap should
 * already be marked allocated), otherwise we search for a block in the
 * bitmap that fits the allocation request.
 *
 * A partial bitmap allocation sets the minimum bitmap granularity (16KB)
 * to fully allocated and adjusts the linear allocator to allow the
 * remaining space to be allocated.
 *
 * sub_key is the lower 32 bits of the chain->bref.key for the chain whos
 * bref is being allocated.  If the radix represents an allocation >= 16KB
 * (aka HAMMER2_FREEMAP_BLOCK_RADIX) we try to use this key to select the
 * blocks directly out of the bmap.
 */
static int
hammer2_bmap_alloc(hammer2_dev_t *hmp, hammer2_bmap_data_t *bmap,
    uint16_t class, int n, int sub_key, int radix, hammer2_key_t *basep)
{
	hammer2_bitmap_t bmmask, pbmmask;
	hammer2_io_t *dio;
	size_t size, bgsize;
	int bmradix, offset, i, j, pbmradix;

	size = (size_t)1 << radix;

	/* Take into account 2-bits per block when calculating bmradix. */
	if (radix <= HAMMER2_FREEMAP_BLOCK_RADIX) {
		bmradix = 2;
		/* (16K) 2 bits per allocation block */
	} else {
		bmradix = (hammer2_bitmap_t)2 <<
		    (radix - HAMMER2_FREEMAP_BLOCK_RADIX);
		/* (32K-64K) 4, 8 bits per allocation block */
	}

	/*
	 * Use the linear iterator to pack small allocations, otherwise
	 * fall-back to finding a free 16KB chunk.  The linear iterator
	 * is only valid when *NOT* on a freemap chunking boundary (16KB).
	 * If it is the bitmap must be scanned.  It can become invalid
	 * once we pack to the boundary.  We adjust it after a bitmap
	 * allocation only for sub-16KB allocations (so the perfectly good
	 * previous value can still be used for fragments when 16KB+
	 * allocations are made inbetween fragmentary allocations).
	 *
	 * Beware of hardware artifacts when bmradix == 64 (intermediate
	 * result can wind up being '1' instead of '0' if hardware masks
	 * bit-count & 63).
	 *
	 * NOTE: j needs to be even in the j= calculation.  As an artifact
	 *	 of the /2 division, our bitmask has to clear bit 0.
	 *
	 * NOTE: TODO this can leave little unallocatable fragments lying
	 *	 around.
	 */
	if (((uint32_t)bmap->linear & HAMMER2_FREEMAP_BLOCK_MASK) + size <=
	    HAMMER2_FREEMAP_BLOCK_SIZE &&
	    (bmap->linear & HAMMER2_FREEMAP_BLOCK_MASK) &&
	    bmap->linear < HAMMER2_SEGSIZE) {
		/*
		 * Use linear iterator if it is not block-aligned to avoid
		 * wasting space.
		 *
		 * Calculate the bitmapq[] index (i) and calculate the
		 * shift count within the 64-bit bitmapq[] entry.
		 *
		 * The freemap block size is 16KB, but each bitmap
		 * entry is two bits so use a little trick to get
		 * a (j) shift of 0, 2, 4, ... 62 in 16KB chunks.
		 */
		KKASSERT(bmap->linear >= 0);
		KKASSERT(bmap->linear + size <= HAMMER2_SEGSIZE);
		KKASSERT((bmap->linear & (HAMMER2_ALLOC_MIN - 1)) == 0);
		offset = bmap->linear;
		i = offset / (HAMMER2_SEGSIZE / HAMMER2_BMAP_ELEMENTS);
		j = (offset / (HAMMER2_FREEMAP_BLOCK_SIZE / 2)) & 62;
		bmmask = (bmradix == HAMMER2_BMAP_BITS_PER_ELEMENT) ?
		    HAMMER2_BMAP_ALLONES : ((hammer2_bitmap_t)1 << bmradix) - 1;
		bmmask <<= j;
		bmap->linear = offset + size;
	} else {
		/*
		 * Try to index a starting point based on sub_key.  This
		 * attempts to restore sequential block ordering on-disk
		 * whenever possible, even if data is committed out of
		 * order.
		 *
		 * i - Index bitmapq[], full data range represented is
		 *     HAMMER2_BMAP_SIZE.
		 *
		 * j - Index within bitmapq[i], full data range represented is
		 *     HAMMER2_BMAP_INDEX_SIZE.
		 */
		i = -1;
		j = -1;

		switch (class >> 8) {
		case HAMMER2_BREF_TYPE_DATA:
			if (radix >= HAMMER2_FREEMAP_BLOCK_RADIX) {
				i = (sub_key & HAMMER2_BMAP_MASK) /
				    (HAMMER2_BMAP_SIZE / HAMMER2_BMAP_ELEMENTS);
				j = (sub_key & HAMMER2_BMAP_INDEX_MASK) /
				    (HAMMER2_BMAP_INDEX_SIZE /
				    HAMMER2_BMAP_BLOCKS_PER_ELEMENT);
				j = j * 2;
			}
			break;
		default:
			break;
		}
		if (i >= 0) {
			KKASSERT(i < HAMMER2_BMAP_ELEMENTS);
			KKASSERT(j < 2 * HAMMER2_BMAP_BLOCKS_PER_ELEMENT);
			KKASSERT(j + bmradix <= HAMMER2_BMAP_BITS_PER_ELEMENT);
			bmmask = (bmradix == HAMMER2_BMAP_BITS_PER_ELEMENT) ?
			    HAMMER2_BMAP_ALLONES :
			    ((hammer2_bitmap_t)1 << bmradix) - 1;
			bmmask <<= j;

			if ((bmap->bitmapq[i] & bmmask) == 0)
				goto success;
		}

		/*
		 * General element scan.
		 * WARNING: (j) is iterating a bit index (by 2's)
		 */
		for (i = 0; i < HAMMER2_BMAP_ELEMENTS; ++i) {
			bmmask = (bmradix == HAMMER2_BMAP_BITS_PER_ELEMENT) ?
			    HAMMER2_BMAP_ALLONES : ((hammer2_bitmap_t)1 << bmradix) - 1;
			for (j = 0; j < HAMMER2_BMAP_BITS_PER_ELEMENT; j += bmradix) {
				if ((bmap->bitmapq[i] & bmmask) == 0)
					goto success;
				bmmask <<= bmradix;
			}
		}
		/* Fragments might remain. */
		/* KKASSERT(bmap->avail == 0); */
		return (HAMMER2_ERROR_ENOSPC);
success:
		offset = i * (HAMMER2_SEGSIZE / HAMMER2_BMAP_ELEMENTS) +
		    (j * (HAMMER2_FREEMAP_BLOCK_SIZE / 2));
		if (size & HAMMER2_FREEMAP_BLOCK_MASK)
			bmap->linear = offset + size;
	}

	/* 8 x (64/2) -> 256 x 16K -> 4MB */
	KKASSERT(i >= 0 && i < HAMMER2_BMAP_ELEMENTS);

	/*
	 * Optimize the buffer cache to avoid unnecessary read-before-write
	 * operations.
	 *
	 * The device block size could be larger than the allocation size
	 * so the actual bitmap test is somewhat more involved.  We have
	 * to use a compatible buffer size for this operation.
	 */
	if ((bmap->bitmapq[i] & bmmask) == 0 && HAMMER2_PBUFSIZE != size) {
		pbmradix = (hammer2_bitmap_t)2 <<
		    (HAMMER2_PBUFRADIX - HAMMER2_FREEMAP_BLOCK_RADIX);
		pbmmask = (pbmradix == HAMMER2_BMAP_BITS_PER_ELEMENT) ?
		    HAMMER2_BMAP_ALLONES : ((hammer2_bitmap_t)1 << pbmradix) - 1;

		while ((pbmmask & bmmask) == 0)
			pbmmask <<= pbmradix;

		if ((bmap->bitmapq[i] & pbmmask) == 0) {
			hammer2_io_newnz(hmp, class >> 8,
			    (*basep + (offset & ~HAMMER2_PBUFMASK)) |
			    hammer2_getradix(HAMMER2_PBUFSIZE),
			    HAMMER2_PBUFSIZE, &dio);
			hammer2_io_putblk(&dio);
		}
	}

	/*
	 * Calculate the bitmap-granular change in bgsize for the volume
	 * header.  We cannot use the fine-grained change here because
	 * the bulkfree code can't undo it.  If the bitmap element is already
	 * marked allocated it has already been accounted for.
	 */
	if (radix < HAMMER2_FREEMAP_BLOCK_RADIX) {
		if (bmap->bitmapq[i] & bmmask)
			bgsize = 0;
		else
			bgsize = HAMMER2_FREEMAP_BLOCK_SIZE;
	} else {
		bgsize = size;
	}

	/*
	 * Adjust the bitmap, set the class (it might have been 0),
	 * and available bytes, update the allocation offset (*basep)
	 * from the L0 base to the actual offset.
	 *
	 * Do not override the class if doing a relaxed class allocation.
	 *
	 * avail must reflect the bitmap-granular availability.  The allocator
	 * tests will also check the linear iterator.
	 */
	bmap->bitmapq[i] |= bmmask;
	if (bmap->class == 0)
		bmap->class = class;
	bmap->avail -= bgsize;
	*basep += offset;

	/*
	 * Adjust the volume header's allocator_free parameter.  This
	 * parameter has to be fixed up by bulkfree which has no way to
	 * figure out sub-16K chunking, so it must be adjusted by the
	 * bitmap-granular size.
	 */
	if (bgsize) {
		hammer2_voldata_lock(hmp);
		hammer2_voldata_modify(hmp);
		hmp->voldata.allocator_free -= bgsize;
		hammer2_voldata_unlock(hmp);
	}

	return (0);
}

/*
 * Initialize a freemap for the storage area (in bytes) that begins at (key).
 */
static void
hammer2_freemap_init(hammer2_dev_t *hmp, hammer2_key_t key,
    hammer2_chain_t *chain)
{
	hammer2_off_t lokey, hikey;
	hammer2_bmap_data_t *bmap;
	int count;

	/*
	 * Calculate the portion of the 1GB map that should be initialized
	 * as free.  Portions below or after will be initialized as allocated.
	 * SEGMASK-align the areas so we don't have to worry about sub-scans
	 * or endianess when using memset.
	 *
	 * WARNING! It is possible for lokey to be larger than hikey if the
	 *	    entire 2GB segment is within the static allocation.
	 */
	/*
	 * (1) Ensure that all statically allocated space from newfs_hammer2
	 *     is marked allocated, and take it up to the level1 base for
	 *     this key.
	 */
	lokey = (hmp->voldata.allocator_beg + HAMMER2_SEGMASK64) &
	    ~HAMMER2_SEGMASK64;
	if (lokey < H2FMBASE(key, HAMMER2_FREEMAP_LEVEL1_RADIX))
		lokey = H2FMBASE(key, HAMMER2_FREEMAP_LEVEL1_RADIX);

	/*
	 * (2) Ensure that the reserved area is marked allocated (typically
	 *     the first 4MB of each 2GB area being represented).  Since
	 *     each LEAF represents 1GB of storage and the zone is 2GB, we
	 *     have to adjust lowkey upward every other LEAF sequentially.
	 */
	if (lokey < H2FMZONEBASE(key) + HAMMER2_ZONE_SEG64)
		lokey = H2FMZONEBASE(key) + HAMMER2_ZONE_SEG64;

	/*
	 * (3) Ensure that any trailing space at the end-of-volume is marked
	 *     allocated.
	 */
	hikey = key + HAMMER2_FREEMAP_LEVEL1_SIZE;
	if (hikey > hmp->total_size)
		hikey = hmp->total_size & ~HAMMER2_SEGMASK64;

	/* Heuristic highest possible value. */
	chain->bref.check.freemap.avail = HAMMER2_FREEMAP_LEVEL1_SIZE;
	bmap = &chain->data->bmdata[0];

	/* Initialize bitmap (bzero'd by caller). */
	for (count = 0; count < HAMMER2_FREEMAP_COUNT; ++count) {
		if (key < lokey || key >= hikey) {
			memset(bmap->bitmapq, -1, sizeof(bmap->bitmapq));
			bmap->avail = 0;
			bmap->linear = HAMMER2_SEGSIZE;
			chain->bref.check.freemap.avail -=
			    HAMMER2_FREEMAP_LEVEL0_SIZE;
		} else {
			bmap->avail = HAMMER2_FREEMAP_LEVEL0_SIZE;
		}
		key += HAMMER2_FREEMAP_LEVEL0_SIZE;
		++bmap;
	}
}

/*
 * The current level1 freemap has been exhausted, iterate to the next
 * one, return ENOSPC if no freemaps remain.
 *
 * At least two loops are required.  If we are not in relaxed mode and
 * we run out of storage we enter relaxed mode and do a third loop.
 * The relaxed mode is recorded back in the hmp so once we enter the mode
 * we remain relaxed until stuff begins to get freed and only do 2 loops.
 *
 * XXX This should rotate back to the beginning to handle freed-up space
 * XXX or use intermediate entries to locate free space. TODO
 */
static int
hammer2_freemap_iterate(hammer2_chain_t **parentp, hammer2_chain_t **chainp,
    hammer2_fiterate_t *iter)
{
	hammer2_dev_t *hmp = (*parentp)->hmp;

	iter->bnext &= ~HAMMER2_FREEMAP_LEVEL1_MASK;
	iter->bnext += HAMMER2_FREEMAP_LEVEL1_SIZE;

	if (iter->bnext >= hmp->total_size) {
		iter->bnext = 0;
		if (++iter->loops >= 2) {
			if (iter->relaxed == 0)
				iter->relaxed = 1;
			else
				return (HAMMER2_ERROR_ENOSPC);
		}
	}
	return (HAMMER2_ERROR_EAGAIN);
}

/*
 * Adjust the bit-pattern for data in the freemap bitmap according to
 * (how).  This code is called from on-mount recovery to fixup (mark
 * as allocated) blocks whos freemap upates might not have been committed
 * in the last crash and is used by the bulk freemap scan to stage frees.
 *
 * WARNING! Cannot be called with a empty-data bref (radix == 0).
 *
 * XXX Currently disabled when how == 0 (the normal real-time case).
 * At the moment we depend on the bulk freescan to actually free blocks.
 * It will still call this routine with a non-zero how to stage possible
 * frees and to do the actual free.
 */
void
hammer2_freemap_adjust(hammer2_dev_t *hmp, hammer2_blockref_t *bref, int how)
{
	hammer2_off_t data_off = bref->data_off;
	hammer2_chain_t *chain, *parent;
	hammer2_bmap_data_t *bmap;
	hammer2_key_t key, key_dummy;
	hammer2_off_t l1size, l1mask;
	hammer2_tid_t mtid;
	hammer2_bitmap_t *bitmap;
	const hammer2_bitmap_t bmmask00 = 0;
	//hammer2_bitmap_t bmmask01;
	//hammer2_bitmap_t bmmask10;
	hammer2_bitmap_t bmmask11;
	uint16_t class;
	int error, radix, start, count, modified = 0;
	size_t bgsize = 0;

	KKASSERT(how == HAMMER2_FREEMAP_DORECOVER);

	KKASSERT(hmp->spmp);
	mtid = hammer2_trans_sub(hmp->spmp);

	radix = (int)data_off & HAMMER2_OFF_MASK_RADIX;
	KKASSERT(radix != 0);
	KKASSERT(radix <= HAMMER2_RADIX_MAX);

	data_off &= ~HAMMER2_OFF_MASK_RADIX;

	class = (bref->type << 8) | HAMMER2_PBUFRADIX;

	/*
	 * We can't adjust the freemap for data allocations made by
	 * newfs_hammer2.
	 */
	if (data_off < hmp->voldata.allocator_beg)
		return;

	KKASSERT((data_off & HAMMER2_ZONE_MASK64) >= HAMMER2_ZONE_SEG);

	/* Lookup the level1 freemap chain.  The chain must exist. */
	key = H2FMBASE(data_off, HAMMER2_FREEMAP_LEVEL1_RADIX);
	l1size = HAMMER2_FREEMAP_LEVEL1_SIZE;
	l1mask = l1size - 1;

	parent = &hmp->fchain;
	hammer2_chain_ref(parent);
	hammer2_chain_lock(parent, HAMMER2_RESOLVE_ALWAYS);

	chain = hammer2_chain_lookup(&parent, &key_dummy, key, key + l1mask,
	    &error, HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_MATCHIND);

	/* Stop early if we are trying to free something but no leaf exists. */
	if (chain == NULL && how != HAMMER2_FREEMAP_DORECOVER) {
		hprintf("no chain at data_off %016llx\n",
		    (long long)bref->data_off);
		goto done;
	}
	if (chain->error) {
		hprintf("error %d at data_off %016llx\n",
		    chain->error, (long long)bref->data_off);
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		chain = NULL;
		goto done;
	}

	/*
	 * Create any missing leaf(s) if we are doing a recovery (marking
	 * the block(s) as being allocated instead of being freed).  Be sure
	 * to initialize the auxillary freemap tracking info in the
	 * bref.check.freemap structure.
	 */
	if (chain == NULL && how == HAMMER2_FREEMAP_DORECOVER) {
		error = hammer2_chain_create(&parent, &chain, NULL, hmp->spmp,
		    HAMMER2_METH_DEFAULT, key, HAMMER2_FREEMAP_LEVEL1_RADIX,
		    HAMMER2_BREF_TYPE_FREEMAP_LEAF,
		    HAMMER2_FREEMAP_LEVELN_PSIZE, mtid, 0, 0);
		if (error == 0) {
			error = hammer2_chain_modify(chain, mtid, 0, 0);
			KKASSERT(error == 0);
			bzero(&chain->data->bmdata[0],
			    HAMMER2_FREEMAP_LEVELN_PSIZE);
			chain->bref.check.freemap.bigmask = (uint32_t)-1;
			chain->bref.check.freemap.avail = l1size;
			/* bref.methods should already be inherited. */
			hammer2_freemap_init(hmp, key, chain);
		}
		/* XXX handle error */
	}

	/* Calculate the bitmask (runs in 2-bit pairs). */
	start = ((int)(data_off >> HAMMER2_FREEMAP_BLOCK_RADIX) & 15) * 2;
	//bmmask01 = (hammer2_bitmap_t)1 << start;
	//bmmask10 = (hammer2_bitmap_t)2 << start;
	bmmask11 = (hammer2_bitmap_t)3 << start;

	/*
	 * Fixup the bitmap.  Partial blocks cannot be fully freed unless
	 * a bulk scan is able to roll them up.
	 */
	if (radix < HAMMER2_FREEMAP_BLOCK_RADIX)
		count = 1;
	else
		count = 1 << (radix - HAMMER2_FREEMAP_BLOCK_RADIX);

	/*
	 * [re]load the bmap and bitmap pointers.  Each bmap entry covers
	 * a 4MB swath.  The bmap itself (LEVEL1) covers 2GB.
	 *
	 * Be sure to reset the linear iterator to ensure that the adjustment
	 * is not ignored.
	 */
again:
	bmap = &chain->data->bmdata[(int)(data_off >> HAMMER2_SEGRADIX) &
	    (HAMMER2_FREEMAP_COUNT - 1)];
	bitmap = &bmap->bitmapq[(int)(data_off >> (HAMMER2_SEGRADIX - 3)) & 7];

	if (modified)
		bmap->linear = 0;

	while (count) {
		KKASSERT(bmmask11);
		if (how == HAMMER2_FREEMAP_DORECOVER) {
			/* Recovery request, mark as allocated. */
			if ((*bitmap & bmmask11) != bmmask11) {
				if (modified == 0) {
					hammer2_chain_modify(chain, mtid, 0, 0);
					modified = 1;
					goto again;
				}
				if ((*bitmap & bmmask11) == bmmask00) {
					bmap->avail -=
					    HAMMER2_FREEMAP_BLOCK_SIZE;
					bgsize += HAMMER2_FREEMAP_BLOCK_SIZE;
				}
				if (bmap->class == 0)
					bmap->class = class;
				*bitmap |= bmmask11;
			}
		}
		--count;
		//bmmask01 <<= 2;
		//bmmask10 <<= 2;
		bmmask11 <<= 2;
	}

	/*
	 * chain->bref.check.freemap.bigmask (XXX)
	 *
	 * Setting bigmask is a hint to the allocation code that there might
	 * be something allocatable.  We also set this in recovery... it
	 * doesn't hurt and we might want to use the hint for other validation
	 * operations later on.
	 *
	 * We could calculate the largest possible allocation and set the
	 * radixes that could fit, but its easier just to set bigmask to -1.
	 */
	if (modified) {
		chain->bref.check.freemap.bigmask = -1;
		hmp->freemap_relaxed = 0; /* reset heuristic */
	}

	hammer2_chain_unlock(chain);
	hammer2_chain_drop(chain);
done:
	hammer2_chain_unlock(parent);
	hammer2_chain_drop(parent);

	if (bgsize) {
		hammer2_voldata_lock(hmp);
		hammer2_voldata_modify(hmp);
		hmp->voldata.allocator_free -= bgsize;
		hammer2_voldata_unlock(hmp);
	}
}

/*
 * Validate the freemap, in three stages.
 *
 * stage-1	ALLOCATED     -> POSSIBLY FREE
 *		POSSIBLY FREE -> POSSIBLY FREE (type corrected)
 *
 *	This transitions bitmap entries from ALLOCATED to POSSIBLY FREE.
 *	The POSSIBLY FREE state does not mean that a block is actually free
 *	and may be transitioned back to ALLOCATED in stage-2.
 *
 *	This is typically done during normal filesystem operations when
 *	something is deleted or a block is replaced.
 *
 *	This is done by bulkfree in-bulk after a memory-bounded meta-data
 *	scan to try to determine what might be freeable.
 *
 *	This can be done unconditionally through a freemap scan when the
 *	intention is to brute-force recover the proper state of the freemap.
 *
 * stage-2	POSSIBLY FREE -> ALLOCATED	(scan metadata topology)
 *
 *	This is done by bulkfree during a meta-data scan to ensure that
 *	all blocks still actually allocated by the filesystem are marked
 *	as such.
 *
 *	NOTE! Live filesystem transitions to POSSIBLY FREE can occur while
 *	      the bulkfree stage-2 and stage-3 is running.  The live filesystem
 *	      will use the alternative POSSIBLY FREE type (2) to prevent
 *	      stage-3 from improperly transitioning unvetted possibly-free
 *	      blocks to FREE.
 *
 * stage-3	POSSIBLY FREE (type 1) -> FREE	(scan freemap)
 *
 *	This is done by bulkfree to finalize POSSIBLY FREE states.
 *
 */
