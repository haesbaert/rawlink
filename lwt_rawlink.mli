type t

val open_link : ?filter:string -> string -> t
val close_link : t -> unit Lwt.t
val get_packet : t -> string Lwt.t
val get_packet_list : t -> string list Lwt.t
