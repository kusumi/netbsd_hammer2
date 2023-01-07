#.include "../Makefile.inc"

#.PATH:	${S}/fs/autofs

KMOD=	hammer2
#IOCONF= autofs.ioconf
#SRCS=	autofs.c autofs_vfsops.c autofs_vnops.c
SRCS=	hammer2_lz4.c hammer2_subr.c hammer2_vfsops.c xxhash/xxhash.c icrc32.c

CPPFLAGS+=	-DDIAGNOSTIC
DBG+=		-DDEBUG -DLOCKDEBUG

WARNS=	3

.include <bsd.kmodule.mk>
