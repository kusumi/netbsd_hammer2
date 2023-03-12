/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2015 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 * by Venkatesh Srinivas <vsrinivas@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/mount.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <mntopts.h>

#include "mountprog.h"
#include "mount_hammer2.h"

static void usage(const char *ctl, ...);

static struct mntopt mopts[] = {
	MOPT_STDOPTS,
	MOPT_UPDATE,
	MOPT_GETARGS,
	MOPT_NULL,
};

#ifndef MOUNT_NOMAIN
int
main(int argc, char **argv)
{
	setprogname(argv[0]);
	return mount_hammer2(argc, argv);
}
#endif

void
mount_hammer2_parseargs(int argc, char *argv[],
	struct hammer2_mount_info *args, int *mntflags,
	char *canon_dev, char *canon_dir)
{
	int ch;
	mntoptparse_t mp;

	memset(args, 0, sizeof(*args));
	*mntflags = 0;
	optind = optreset = 1; /* Reset for parse of new argv. */
	while ((ch = getopt(argc, argv, "o:")) != -1)
		switch (ch) {
		case 'o':
			mp = getmntopts(optarg, mopts, mntflags, 0);
			if (mp == NULL)
				err(1, "getmntopts");
			freemntopts(mp);
			break;
		case '?':
		default:
			usage("unknown option: -%c", ch);
			/* not reached */
		}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage("missing parameter(s) (special[@label] node)");
		/* not reached */
	}

	/* If MNT_GETARGS is specified, it should be the only flag. */
	if ((*mntflags & MNT_GETARGS) == 0)
		*mntflags = MNT_RDONLY; /* currently write unsupported */

	/* pathadj doesn't work with multi-volumes. */
	strlcpy(canon_dev, argv[0], MAXPATHLEN);
	pathadj(argv[1], canon_dir);

	strlcpy(args->volume, canon_dev, sizeof(args->volume));
	args->hflags = HMNT2_LOCAL; /* force local, not optional */

	/* Automatically add @DATA if no label specified. */
	if (strchr(canon_dev, '@') == NULL) {
		char tmp[MAXPATHLEN - 10];
		strlcpy(tmp, canon_dev, sizeof(tmp));
		snprintf(canon_dev, MAXPATHLEN, "%s@DATA", tmp);
	}

	/* Prefix if necessary. */
	if (!strchr(canon_dev, ':') && canon_dev[0] != '/' &&
	    canon_dev[0] != '@') {
		char tmp[MAXPATHLEN - 10];
		strlcpy(tmp, canon_dev, sizeof(tmp));
		snprintf(canon_dev, MAXPATHLEN, "/dev/%s", tmp);
	}
}

int
mount_hammer2(int argc, char *argv[])
{
	struct hammer2_mount_info args;
	char canon_dev[MAXPATHLEN], canon_dir[MAXPATHLEN];
	const char *errcause;
	int mntflags;

	mount_hammer2_parseargs(argc, argv, &args, &mntflags, canon_dev,
	    canon_dir);

	if (mount(MOUNT_HAMMER2, canon_dir, mntflags, &args, sizeof(args))
	    == -1) {
		switch (errno) {
		case EMFILE:
			errcause = "mount table full";
			break;
		case EINVAL:
			if (mntflags & MNT_UPDATE)
				errcause =
			    "specified device does not match mounted device";
			else 
				errcause = "incorrect super block";
			break;
		default:
			errcause = strerror(errno);
			break;
		}
		errx(1, "%s on %s: %s", args.volume, canon_dir, errcause);
	}
	if (mntflags & MNT_GETARGS) {
		printf("volume=%s, hflags=0x%x, cluster_fd=%d\n",
		    args.volume, args.hflags, args.cluster_fd);
	}

	return (0);
}

static void
usage(const char *ctl, ...)
{
	va_list va;

	va_start(va, ctl);
	fprintf(stderr, "mount_hammer2: ");
	vfprintf(stderr, ctl, va);
	va_end(va);
	fprintf(stderr, "\n");
	fprintf(stderr, " mount_hammer2 [-o options] special[@label] node\n");
	fprintf(stderr, " mount_hammer2 [-o options] @label node\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n"
			" <standard_mount_options>\n"
	);
	exit(1);
}
