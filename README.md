# Rawlink (WIP)

Rawlink is an ocaml library for sending and receiving raw packets at the link
layer level.  Sometimes you need to have full control of the packet, including
building the a full ethernet frame.

The API is platform independent and it will use BPF on BSDs systems and
AF_SOCKET on linux. Some functionality will have to be sacrificed so that the
API is portable enough. Currently BPF is implemented, including filtering
capabilities, writing a BPF program is a pain in the ass, and so far you can
send a BPF program as a string, but no facilities are provided for actually
building the program. I suggest you write a small .c file that returns the
BPF program as a string.
