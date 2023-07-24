(lang dune 3.2)
(name rawlink)
(generate_opam_files)
(source (github haesbaert/rawlink))
(homepage https://github.com/haesbaert/rawlink)
(bug_reports https://github.com/haesbaert/rawlink/issues)
(documentation https://haesbaert.github.io/rawlink/)
(authors "Christiano F. Haesbaert <haesbaert@haesbaert.org>")
(maintainers "Christiano F. Haesbaert <haesbaert@haesbaert.org>")
(license "ISC")

(package
 (name rawlink)
 (synopsis "Portable library to read and write raw packets")
 (description "Rawlink is an ocaml library for sending and receiving raw packets at the link
layer level. Sometimes you need to have full control of the packet, including
building the full ethernet frame.

The API is platform independent, it uses BPF on real UNIXes and AF_SOCKET on
linux. Some functionality is sacrificed so that the API is portable enough.

Currently BPF and AF_PACKET are implemented, including filtering capabilities.
Writing a BPF program is a pain in the ass, so no facilities are provided for
it. If you need a BPF filter, I suggest you write a small .c file with a
function that returns the BPF program as a string, check `rawlink_stubs.c` for
an example.")
 (depends (ocaml (>= "4.09.0"))
  (cstruct (>= "6.1.0"))
  ppx_cstruct)
)

(package
 (name rawlink-eio)
 (synopsis "Portable library to read and write raw packets with EIO bindings")
 (description "
Rawlink is an ocaml library for sending and receiving raw packets at the link
layer level. Sometimes you need to have full control of the packet, including
building the full ethernet frame.

The API is platform independent, it uses BPF on real UNIXes and AF_SOCKET on
linux. Some functionality is sacrificed so that the API is portable enough.

Currently BPF and AF_PACKET are implemented, including filtering capabilities.
Writing a BPF program is a pain in the ass, so no facilities are provided for
it. If you need a BPF filter, I suggest you write a small .c file with a
function that returns the BPF program as a string, check `rawlink_stubs.c` for
an example.

This version of Rawlink is to be used with Eio, the IO functions will produce
EIO effects.
")
 (depends (ocaml (>= "5.0.0"))
  (rawlink (>= "2.1"))
  (eio (>= "0.4")))
)

(package
 (name rawlink-lwt)
 (synopsis "Portable library to read and write raw packets with Lwt bindings")
 (description "
Rawlink is an ocaml library for sending and receiving raw packets at the link
layer level. Sometimes you need to have full control of the packet, including
building the full ethernet frame.

The API is platform independent, it uses BPF on real UNIXes and AF_SOCKET on
linux. Some functionality is sacrificed so that the API is portable enough.

Currently BPF and AF_PACKET are implemented, including filtering capabilities.
Writing a BPF program is a pain in the ass, so no facilities are provided for
it. If you need a BPF filter, I suggest you write a small .c file with a
function that returns the BPF program as a string, check `rawlink_stubs.c` for
an example.

This version of Rawlink is to be used with Lwt, the IO functions will produce
Lwt threads (promises).
")
 (depends (ocaml (>= "4.09.0"))
  (rawlink (>= "2.1"))
  (lwt (>= "2.4.7")))
)
