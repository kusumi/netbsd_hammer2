#!/usr/pkg/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=/usr/local
fi

[ -e /usr/bin/uname ] || exit 1

KMOD_DIR=/stand/`/usr/bin/uname -m`/`/usr/bin/uname -r`/modules
[ -d ${KMOD_DIR} ] || exit 1

[ ! -f ${KMOD_DIR}/hammer2/hammer2.kmod ] || /bin/rm ${KMOD_DIR}/hammer2/hammer2.kmod
[ ! -d ${KMOD_DIR}/hammer2 ] || /bin/rmdir ${KMOD_DIR}/hammer2

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
