/*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>

#include "caml/memory.h"
#include "caml/fail.h"
#include "caml/unixsupport.h"
#include "caml/signals.h"
#include "caml/alloc.h"
#include "caml/custom.h"
#include "caml/bigarray.h"

int
bpf_open(void)
{
	int i, fd;
	char path[16];

	for (i = 0; i < 10; i++) {
		snprintf(path, sizeof(path), "/dev/bpf%d", i);
		enter_blocking_section();
		fd = open(path, O_RDWR);
		leave_blocking_section();
		if (fd == -1) {
			if (errno == EBUSY)
				continue;
			uerror("bpf_open", Nothing);
		}
	}

	return (fd);
}

int
bpf_setif(int fd, char *ifname)
{
	struct ifreq ifreq;
	int r;

	bzero(&ifreq, sizeof(ifreq));
	strlcpy(ifreq.ifr_name, ifname, sizeof (ifreq.ifr_name));
	caml_enter_blocking_section();
	r = ioctl(fd, BIOCSETIF, &ifreq);
	caml_leave_blocking_section();
	if (r == -1)
		uerror("bpf_setif", Nothing);

	return (r);
}

CAMLprim value
caml_rawlink_open(char *ifname)
{
	CAMLparam0();
	int fd;

	if ((fd = bpf_open()) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setif(fd, ifname) == -1)
		CAMLreturn(Val_unit);

	CAMLreturn (Val_int(fd));
}
