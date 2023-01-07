NetBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for NetBSD

+ NetBSD version of https://github.com/kusumi/freebsd_hammer2

## Requirements

+ Recent NetBSD release

+ NetBSD src tree under /usr/src by default

## Build

        $ cd netbsd_hammer2
        $ make

## Install

        $ sudo bash -x ./script/install.sh

## Uninstall

        $ sudo bash -x ./script/uninstall.sh

## Notes

+ Initial target is read-only support, but write support is also planned once read-only support is accomplished.

+ Tags are merely for packaging, nothing directly to do with file system version.

+ -CURRENT aka upstream NetBSD is the only tier 1 support branch at the moment.
