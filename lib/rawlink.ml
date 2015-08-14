type t = {
  fd : Unix.file_descr;
  packets : string list ref;
}

external opensock: ?filter:string -> string -> Unix.file_descr = "caml_rawlink_open"
external readsock: Unix.file_descr -> string list = "caml_rawlink_read"
external writesock: Unix.file_descr -> string -> unit = "caml_rawlink_write"
external dhcp_filter: unit -> string = "caml_dhcp_filter"

let open_link ?filter ifname =
  { fd = opensock ?filter:filter ifname; packets = ref [] }

let close_link t = Unix.close t.fd

let rec get_packet t = match !(t.packets) with
  | [] -> t.packets := readsock t.fd; get_packet t
  | hd :: tail -> t.packets := tail; hd

let get_packet_list t = match !(t.packets) with
  | [] -> readsock t.fd
  | packets -> t.packets := []; packets

let put_packet t b =
  let len = Bytes.length b in
  let n = Unix.write t.fd b 0 len in
  if n <> len then
    raise (Unix.Unix_error(Unix.ENOBUFS, "put_packet", ""))
