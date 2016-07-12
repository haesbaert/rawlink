[%%cstruct
type bpf_hdr = {
	bh_sec: uint32_t;
	bh_usec: uint32_t;
	bh_caplen: uint32_t;
	bh_datalen: uint32_t;
	bh_hdrlen: uint16_t;
} [@@little_endian]]
