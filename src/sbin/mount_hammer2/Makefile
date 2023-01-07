.include <bsd.own.mk>

PROG=	mount_hammer2
SRCS=	mount_hammer2.c pathadj.c
MAN=	mount_hammer2.8

WARNS?=	3

CFLAGS+=	-I${NETBSDSRCDIR}/sys
CFLAGS+=	-I../../sys

MOUNT=		${NETBSDSRCDIR}/sbin/mount
CFLAGS+=	-I${MOUNT}
.PATH:		${MOUNT}

DPADD+=		${LIBUTIL}
LDADD+=		-lutil

.include <bsd.prog.mk>
