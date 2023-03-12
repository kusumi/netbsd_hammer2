NetBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for NetBSD (currently read-only support)

+ NetBSD version of https://github.com/kusumi/freebsd_hammer2

## Requirements

+ Recent NetBSD release

    + Compiles and tested with -CURRENT

    + Does not support 9.X or below (due to changes that require too many \_\_NetBSD\_Version\_\_ ifdefs compared to relatively stable FreeBSD kernel API)

+ NetBSD src tree under /usr/src by default

+ Bash

## Build

        $ cd netbsd_hammer2
        $ make

## Install

        $ cd netbsd_hammer2
        $ make install

## Uninstall

        $ cd netbsd_hammer2
        $ make uninstall

## Bugs

+ Does not compile on NetBSD/i386 due to a toolchain bug and other issues on this arch. Note that HAMMER2 implementation is not specific to certain architecture.

## Notes

+ Write support is planned in future.

+ Tags are merely for packaging, nothing directly to do with file system version.

+ -CURRENT aka upstream NetBSD is the only tier 1 support branch at the moment.

+ [makefs(8) for Linux](https://github.com/kusumi/makefs) supports HAMMER2 image creation from a directory contents on Linux. There is currently no way to do this on NetBSD.
