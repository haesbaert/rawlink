cstruct bpf_hdr {
	uint32_t     bh_sec;
	uint32_t     bh_usec;
	uint32_t     bh_caplen;
	uint32_t     bh_datalen;
	uint16_t     bh_hdrlen;
} as little_endian
