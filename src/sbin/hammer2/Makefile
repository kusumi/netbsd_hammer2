.include <bsd.own.mk>

PROG=	hammer2
SRCS=	cmd_debug.c cmd_pfs.c cmd_stat.c cmd_volume.c main.c ondisk.c \
	print_inode.c subs.c xxhash.c icrc32.c
MAN=	hammer2.8

.PATH:	../../sys/libkern ../../sys/fs/hammer2/xxhash

WARNS=	5

CFLAGS+=	-I${NETBSDSRCDIR}/sys
CFLAGS+=	-I../../sys

.include <bsd.prog.mk>
