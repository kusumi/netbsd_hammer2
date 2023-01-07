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
	echo "No such directory ${DIR}/sbin"
	exit 1
fi

[ -e /usr/bin/install ] || exit 1
#[ -e /usr/sbin/kldxref ] || exit 1

#[ ! -f /boot/modules/hammer2.ko ] || /bin/rm /boot/modules/hammer2.ko
#/usr/sbin/kldxref /boot/modules/

[ ! -f ${DIR}/sbin/hammer2 ] || /bin/rm ${DIR}/sbin/hammer2
[ ! -f ${DIR}/sbin/newfs_hammer2 ] || /bin/rm ${DIR}/sbin/newfs_hammer2
[ ! -f ${DIR}/sbin/mount_hammer2 ] || /bin/rm ${DIR}/sbin/mount_hammer2
[ ! -f ${DIR}/sbin/fsck_hammer2 ] || /bin/rm ${DIR}/sbin/fsck_hammer2

[ ! -f ${DIR}/man/man8/hammer2.8 ] || /bin/rm ${DIR}/man/man8/hammer2.8
[ ! -f ${DIR}/man/man8/hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/hammer2.8.gz
[ ! -f ${DIR}/man/man8/newfs_hammer2.8 ] || /bin/rm ${DIR}/man/man8/newfs_hammer2.8
[ ! -f ${DIR}/man/man8/newfs_hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/newfs_hammer2.8.gz
[ ! -f ${DIR}/man/man8/mount_hammer2.8 ] || /bin/rm ${DIR}/man/man8/mount_hammer2.8
[ ! -f ${DIR}/man/man8/mount_hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/mount_hammer2.8.gz
[ ! -f ${DIR}/man/man8/fsck_hammer2.8 ] || /bin/rm ${DIR}/man/man8/fsck_hammer2.8
[ ! -f ${DIR}/man/man8/fsck_hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/fsck_hammer2.8.gz

echo "uninstall success"
