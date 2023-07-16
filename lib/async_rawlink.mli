open! Base
open! Async

type t

val open_link : ?filter:string -> ?promisc:bool -> string ->  t
(** [open_link ~filter ~promisc interface sw]. Creates a rawlink on the
   specified [interface], a BPF program [filter] can be passed to
   filter out incoming packets. If [promisc] is true, sets [interface]
   to promiscuous mode, defaults to false.*)

val close_link : t -> unit Deferred.t
(** [close_link]. Closes a rawlink. *)

val read_packet : t -> Cstruct.t Deferred.t
(** [read_packet t]. Reads a full packet, may raise Unix.Unix_error. *)

val send_packet : t -> Cstruct.t -> unit Deferred.t
(** [send_packet t]. Sends a full packet, may raise Unix.Unix_error. *)

val dhcp_server_filter : unit -> string
(** [dhcp_server_filter]. Returns a BPF program suitable to be passed in
    [open_link ~filter], it accepts UDP packets destined to
    port 67 (DHCP server). *)

val dhcp_client_filter : unit -> string
(** [dhcp_client_filter]. Returns a BPF program suitable to be passed in
    [open_link ~filter], it accepts UDP packets destined to
    port 68 (DHCP client). *)
