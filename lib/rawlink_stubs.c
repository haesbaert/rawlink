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

#ifdef __linux__
#define USE_AF_PACKET
#else
#define USE_BPF /* Best bet */
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>

#ifdef USE_AF_PACKET
#include <linux/if_packet.h>
#include <linux/filter.h>
#endif	/* USE_AF_PACKET */

#ifdef USE_BPF
#include <net/bpf.h>
#endif	/* USE_BPF */

#include <net/if.h>

#include <arpa/inet.h>

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

#ifdef USE_BPF

#define FILTER bpf_insn

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

int
bpf_setfilter(int fd, value vfilter)
{
	int r;
	struct bpf_program prog;

	if (vfilter == Val_int(0))
		return (0);
	prog.bf_len = caml_string_length(Field(vfilter, 0)) /
	    sizeof(struct bpf_insn);
	prog.bf_insns = (struct bpf_insn *) String_val(Field(vfilter, 0));

	caml_enter_blocking_section();
	r = ioctl(fd, BIOCSETF, &prog);
	caml_leave_blocking_section();

	if (r == -1)
		uerror("bpf_setfilter", Nothing);

	return (r);
}

CAMLprim value
caml_rawlink_read(value vfd)
{
	CAMLparam1(vfd);
	CAMLlocal4(vtail, vprevtail, vhead, vs);
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

		/* Copy the string */
		vs = caml_alloc_string(hp->bh_caplen);
		memcpy(String_val(vs), p, hp->bh_caplen);

		/* Create the new tail */
		vtail = caml_alloc_small(2, 0);
		Field(vtail, 0) = vs;
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
caml_rawlink_open(value vfilter, value vifname)
{
	CAMLparam2(vfilter, vifname);
	int fd;

	if ((fd = bpf_open()) == -1)
		CAMLreturn(Val_unit);
	if (bpf_seesent(fd, 0) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setblen(fd, UNIX_BUFFER_SIZE) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setfilter(fd, vfilter) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setif(fd, String_val(vifname)) == -1)
		CAMLreturn(Val_unit);
	if (bpf_setimmediate(fd, 1) == -1)
		CAMLreturn(Val_unit);

	CAMLreturn (Val_int(fd));
}

#endif	/* USE_BPF */

#ifdef USE_AF_PACKET

#define FILTER sock_filter

int
af_packet_open(void)
{
	int fd;

	enter_blocking_section();
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	leave_blocking_section();

	if (fd == -1)
		uerror("af_packet_open", Nothing);

	return (fd);
}

int
af_packet_setif(int fd, char *ifname)
{
	int r;

	enter_blocking_section();
	r = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
	    strlen(ifname));
	leave_blocking_section();

	if (r == -1)
		uerror("af_packet_setif", Nothing);

	return (r);
}

int
af_packet_setfilter(int fd, value vfilter)
{
	int r;
	struct sock_fprog prog;

	if (vfilter == Val_int(0))
		return (0);

	prog.len = caml_string_length(Field(vfilter, 0)) /
	    sizeof(struct sock_filter);
	prog.filter = (struct sock_filter *) String_val(Field(vfilter, 0));

	caml_enter_blocking_section();
	r = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
	caml_leave_blocking_section();

	if (r == -1)
		uerror("af_packet_setfilter", Nothing);

	return (r);
}

CAMLprim value
caml_rawlink_read(value vfd)
{
	CAMLparam1(vfd);
	CAMLlocal2(v, vs);
	char buf[UNIX_BUFFER_SIZE];
	ssize_t n;
	int fd = Int_val(vfd);

again:
	caml_enter_blocking_section();
	n = read(fd, buf, sizeof(buf));
	caml_leave_blocking_section();

	if (n == -1) {
		if (errno == EAGAIN)
			goto again;
		CAMLreturn (Val_unit);
	}

	vs = caml_alloc_string(n);
	memcpy(String_val(vs), buf, n);

	v = caml_alloc_small(2, 0);
	Field(v, 0) = vs;
	Field(v, 1) = Val_int(0);

	CAMLreturn (v);
}

CAMLprim value
caml_rawlink_open(value vfilter, value vifname)
{
	CAMLparam2(vfilter, vifname);
	int fd;

	if ((fd = af_packet_open()) == -1)
		CAMLreturn (Val_unit);
	if (af_packet_setfilter(fd, vfilter) == -1)
		CAMLreturn(Val_unit);
	if (af_packet_setif(fd, String_val(vifname)) == -1)
		CAMLreturn (Val_unit);

	CAMLreturn (Val_int(fd));
}

#endif	/* USE_AF_PACKET */

/* Filters */
CAMLprim value
caml_dhcp_filter(value vunit)
{
	CAMLparam0();
	CAMLlocal1(vfilter);
	struct FILTER dhcp_bpf_filter[] = {
		/* Make sure this is an IP packet... */
		BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 12),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),

		/* Make sure it's a UDP packet... */
		BPF_STMT (BPF_LD + BPF_B + BPF_ABS, 23),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

		/* Make sure this isn't a fragment... */
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
		BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

		/* Get the IP header length... */
		BPF_STMT (BPF_LDX + BPF_B + BPF_MSH, 14),

		/* Make sure it's to the right port... */
		BPF_STMT (BPF_LD + BPF_H + BPF_IND, 16),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, 67, 0, 1), /* patch */

		/* If we passed all the tests, ask for the whole packet. */
		BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

		/* Otherwise, drop it. */
		BPF_STMT(BPF_RET+BPF_K, 0),
	};

	vfilter = caml_alloc_string(sizeof(dhcp_bpf_filter));
	memcpy(String_val(vfilter), dhcp_bpf_filter, sizeof(dhcp_bpf_filter));

	CAMLreturn (vfilter);
}
