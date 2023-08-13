/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2020 The DragonFly Project.  All rights reserved.
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

int
cmd_growfs(const char *sel_path, int ac, const char **av)
{
	int fd;
	int i;
	int ecode = 0;

	/*
	 * Use sel_path if no arguments, else used passed arguments
	 */
	for (i = 0; i <= ac; ++i) {
		struct hammer2_ioc_growfs growfs;

		if (i < ac)
			sel_path = av[i];
		else if (i == ac && ac != 0)
			continue;

		fd = hammer2_ioctl_handle(sel_path);
		if (fd < 0) {
			ecode = 1;
			continue;
		}
		bzero(&growfs, sizeof(growfs));
		if (ioctl(fd, HAMMER2IOC_GROWFS, &growfs) < 0) {
			fprintf(stderr, "grow %s failed: %s\n",
			       sel_path, strerror(errno));
			ecode = 1;
		} else if (growfs.modified) {
			printf("%s grown to %016jx\n",
			       sel_path, (intmax_t)growfs.size);
		} else {
			printf("%s no size change - %016jx\n",
			       sel_path, (intmax_t)growfs.size);
		}
		close(fd);
	}
	return ecode;
}
