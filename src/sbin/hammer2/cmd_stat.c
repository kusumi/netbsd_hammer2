/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
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

#include "hammer2.h"

/*
 * Should be run as root.  Creates /etc/hammer2/rsa.{pub,prv} using
 * an openssl command.
 */
int
cmd_stat(int ac, const char **av)
{
	hammer2_ioc_inode_t ino;
	const char *cdir = ".";
	int ecode = 0;
	int w;
	int i;
	int fd;

	if (ac == 0) {
		ac = 1;
		av = &cdir;
	}
	for (i = w = 0; i < ac; ++i) {
		if (w < (int)strlen(av[i]))
			w = (int)strlen(av[i]);
	}
	if (w < 16)
		w = 16;
	printf("%-*.*s ncp  data-use inode-use comp               check        quota\n",
		w, w, "PATH");
	for (i = 0; i < ac; ++i) {
		if ((fd = open(av[i], O_RDONLY)) < 0) {
			fprintf(stderr, "%s: %s\n", av[i], strerror(errno));
			ecode = 1;
			continue;
		}
		if (ioctl(fd, HAMMER2IOC_INODE_GET, &ino) < 0) {
			fprintf(stderr, "%s: %s\n", av[i], strerror(errno));
			ecode = 1;
			continue;
		}
		printf("%-*.*s ", w, w, av[i]);
		printf("%3d ", ino.ip_data.meta.ncopies);
		printf("%9s ", sizetostr(ino.data_count));
		printf("%9s ", counttostr(ino.inode_count));
		printf("%-18s ", hammer2_compmode_to_str(
			ino.ip_data.meta.comp_algo));
		printf("%-12s ", hammer2_checkmode_to_str(
			ino.ip_data.meta.check_algo));
		if (ino.ip_data.meta.data_quota ||
		    ino.ip_data.meta.inode_quota) {
			printf("%s",
				sizetostr(ino.ip_data.meta.data_quota));
			printf("/%-12s",
				counttostr(ino.ip_data.meta.inode_quota));
		}
		printf("\n");
	}
	return ecode;
}
