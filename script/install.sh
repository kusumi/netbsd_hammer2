#!/usr/pkg/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=/usr/local
fi
if [ ! -d ${DIR} ]; then
	echo "No such directory ${DIR}"
	exit 1
fi
if [ ! -d ${DIR}/sbin ]; then
	mkdir -p ${DIR}/sbin || exit 1
fi
if [ ! -d ${DIR}/man/man8 ]; then
	mkdir -p ${DIR}/man/man8 || exit 1
fi

[ -e /usr/bin/install ] || exit 1
#[ -e /usr/sbin/kldxref ] || exit 1
[ -e /usr/bin/strip ] || exit 1

#/usr/bin/install -o root -g wheel -m 555 ./src/sys/fs/hammer2/hammer2.ko /boot/modules/
#/usr/sbin/kldxref /boot/modules/

/usr/bin/install -s -m 555 ./src/sbin/hammer2/hammer2 ${DIR}/sbin/
/usr/bin/install -s -m 555 ./src/sbin/newfs_hammer2/newfs_hammer2 ${DIR}/sbin/
/usr/bin/install -s -m 555 ./src/sbin/mount_hammer2/mount_hammer2 ${DIR}/sbin/
/usr/bin/install -s -m 555 ./src/sbin/fsck_hammer2/fsck_hammer2 ${DIR}/sbin/

/usr/bin/install -m 444 ./src/sbin/hammer2/hammer2.8 ${DIR}/man/man8/
/usr/bin/install -m 444 ./src/sbin/newfs_hammer2/newfs_hammer2.8 ${DIR}/man/man8/
/usr/bin/install -m 444 ./src/sbin/mount_hammer2/mount_hammer2.8 ${DIR}/man/man8/
/usr/bin/install -m 444 ./src/sbin/fsck_hammer2/fsck_hammer2.8 ${DIR}/man/man8/

/usr/bin/strip --strip-debug ${DIR}/sbin/hammer2
/usr/bin/strip --strip-debug ${DIR}/sbin/newfs_hammer2
/usr/bin/strip --strip-debug ${DIR}/sbin/mount_hammer2
/usr/bin/strip --strip-debug ${DIR}/sbin/fsck_hammer2

echo "install success"

# XXX
KMOD="src/sys/fs/hammer2/hammer2.kmod"
if [ -f ${KMOD} ]; then
	echo "note: ${KMOD} is not installed"
fi
