type t

val open_link : ?filter:string -> string -> t
val close_link : t -> unit
val read_packet : t -> Cstruct.t
val send_packet : t -> Cstruct.t -> unit
val dhcp_filter : unit -> string
val bpf_split_buffer : Cstruct.t -> Cstruct.t list
