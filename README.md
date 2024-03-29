## Rawlink - portable library to read and write raw packets.

[![Build Status](https://travis-ci.org/haesbaert/rawlink.svg)](https://travis-ci.org/haesbaert/rawlink)

Rawlink is an ocaml library for sending and receiving raw packets at the link
layer level. Sometimes you need to have full control of the packet, including
building the full ethernet frame.

The API is platform independent, it uses BPF on real UNIXes and AF_SOCKET on
linux. Some functionality is sacrificed so that the API is portable enough.

Currently BPF and AF_PACKET are implemented, including filtering capabilities.
Writing a BPF program is a pain in the ass, so no facilities are provided for
it. If you need a BPF filter, I suggest you write a small .c file with a
function that returns the BPF program as a string, check `rawlink_stubs.c` for
an example. You can leverage [`dumpcap -d`](https://tshark.dev/packetcraft/arcana/bpf_instructions/)
to generate BPF programs from human readable filters.

Both normal blocking functions as well as `Eio` and `Lwt` bindings are provided.

A typical code for receiving all packets and just sending them back on a
specific interface is detailed below:

```ocaml
let link = Rawlink.open_link "eth0" in
let buf = Rawlink.read_packet link in
Printf.printf "got a packet with %d bytes.\n%!" (Cstruct.len buf);
Rawlink.send_packet link buf
```

Check the mli interface for more options.
