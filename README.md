NetBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## Requirements

+ Recent NetBSD -CURRENT

+ src tree under /usr/src

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

+ Does not compile on NetBSD/i386 due to a toolchain bug and other issues on this arch.

## Notes

+ This repository will be abandoned once Linux or FreeBSD is stabilized with write support. NetBSD is not the main target.
