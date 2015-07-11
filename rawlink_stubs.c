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
bpf_seesent(int fd, u_int opt)
{
	int r;

	caml_enter_blocking_section();
	r = ioctl(fd, BIOCSSEESENT, &opt);
	caml_leave_blocking_section();
	if (r == -1)
		uerror("bpf_seesent", Nothing);

	return (r);
}

int
bpf_setblen(int fd, u_int len)
{
	int r;

	caml_enter_blocking_section();
	r = ioctl(fd, BIOCSBLEN, &len);
	caml_leave_blocking_section();
	if (r == -1)
		uerror("bpf_setblen", Nothing);

	return (r);
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

int
bpf_setimmediate(int fd, u_int opt)
{
	int r;

	caml_enter_blocking_section();
	r = ioctl(fd, BIOCIMMEDIATE, &opt);
	caml_leave_blocking_section();
	if (r == -1)
		uerror("bpf_setimmediate", Nothing);

	return (r);
}

CAMLprim value
caml_rawlink_read(value vfd)
{
	CAMLparam1(vfd);
	CAMLlocal3(vtail, vprevtail, vhead);
	struct bpf_hdr *hp;
	char buf[UNIX_BUFFER_SIZE], *p, *eh;
	ssize_t n;
	int fd = Int_val(vfd);

	bzero(buf, sizeof(buf));
again:
	caml_enter_blocking_section();
	n = read(fd, buf, sizeof(buf));
	caml_leave_blocking_section();

	if (n == -1) {
		if (errno == EAGAIN)
			goto again;
		uerror("read", Nothing);
		CAMLreturn (Val_unit);
	}
	vhead = vprevtail = vtail = Val_int(0);

	p = buf;
	hp = (struct bpf_hdr *) p;
	eh = p + hp->bh_hdrlen;

	while (p < (buf + n)) {
		if (hp->bh_caplen != hp->bh_datalen)
			continue;

		/* Create the new tail */
		vtail = caml_alloc_small(2, 0);
		Field(vtail, 0) = caml_alloc_string(hp->bh_caplen);
		memcpy(String_val(Field(vtail, 0)), p, hp->bh_caplen);
		Field(vtail, 1) = Val_int(0);

		/* If not the first element... */
		if (p != buf)
			caml_modify(&Field(vprevtail, 1), vtail);
		else
			vhead = vtail;

		vprevtail = vtail;
		p += BPF_WORDALIGN(hp->bh_hdrlen + hp->bh_caplen);
		hp = (struct bpf_hdr *) p;
		eh = p + hp->bh_hdrlen;
	}

	CAMLreturn (vhead);
}

CAMLprim value
caml_rawlink_open(char *ifname)
{
	CAMLparam0();
	int fd;

	if ((fd = bpf_open()) == -1)
		CAMLreturn(Val_unit);
	if (bpf_seesent(fd, 0) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setblen(fd, UNIX_BUFFER_SIZE) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setif(fd, ifname) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setimmediate(fd, 1) == -1)
		CAMLreturn(Val_unit);

	CAMLreturn (Val_int(fd));
}
