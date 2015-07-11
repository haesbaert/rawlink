
type t

val open_link : string -> t
val close_link : t -> unit
val close_link_lwt : t -> unit Lwt.t

val get_packet : t -> string
val get_packet_lwt : t -> string Lwt.t

val get_packet_list : t -> string list
val get_packet_list_lwt : t -> string list Lwt.t
