type t

val open_link : ?filter:string -> string -> t
val close_link : t -> unit Lwt.t
val read_packet : t -> Cstruct.t Lwt.t
val send_packet : t -> Cstruct.t -> unit Lwt.t
val dhcp_filter : unit -> string
