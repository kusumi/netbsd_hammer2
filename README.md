NetBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for NetBSD

## Requirements

+ Recent NetBSD

    + Compiles and tested with -CURRENT

    + Does not support 9.X or below (due to changes that require too many \_\_NetBSD\_Version\_\_ ifdefs compared to relatively stable FreeBSD kernel API)

+ NetBSD src tree under /usr/src

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

+ VOP\_READDIR implementation is known to not work with some user space libraries on 32 bit platforms.

+ Does not compile on NetBSD/i386 due to a toolchain bug and other issues on this arch. Note that HAMMER2 implementation is not specific to certain architecture.

## Notes

+ Tags are merely for packaging, nothing directly to do with file system version.

+ [makefs](https://github.com/kusumi/makefs) supports HAMMER2 image creation from a directory contents.

+ This repository will be abandoned once Linux or FreeBSD is stabilized with write support. NetBSD is not the main target.
