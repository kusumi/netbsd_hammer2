.include "/usr/src/sys/modules/Makefile.inc"

KMOD=	hammer2
SRCS=	hammer2_admin.c hammer2_bulkfree.c hammer2_chain.c hammer2_cluster.c \
	hammer2_flush.c hammer2_freemap.c hammer2_inode.c hammer2_io.c \
	hammer2_ioctl.c hammer2_lz4.c hammer2_ondisk.c hammer2_strategy.c \
	hammer2_subr.c hammer2_vfsops.c hammer2_vnops.c hammer2_xops.c \
	xxhash/xxhash.c icrc32.c

.PATH:	../../libkern

.if defined(INVARIANTS)
DBG+=	-DDIAGNOSTIC -DLOCKDEBUG
.endif
.if defined(HAMMER2_INVARIANTS)
CFLAGS+=-DHAMMER2_INVARIANTS
.endif
.if defined(HAMMER2_MALLOC)
DBG+=	-DHAMMER2_MALLOC
.endif
.if defined(HAMMER2_WRITE)
DBG+=	-DHAMMER2_WRITE
.endif

WARNS=	5

.include <bsd.kmodule.mk>
