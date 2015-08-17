open Lwt.Infix

type t = {
  fd : Lwt_unix.file_descr;
  packets : string list ref;
}

external opensock: ?filter:string -> string -> Unix.file_descr = "caml_rawlink_open"
external readsock: Unix.file_descr -> string list = "caml_rawlink_read"
external dhcp_filter: unit -> string = "caml_dhcp_filter"

let readsock_lwt fd =
  Lwt_unix.blocking fd >>= function
  | true -> failwith "readsock_lwt: socket must be nonblocking"
  | false -> Lwt_unix.wrap_syscall Lwt_unix.Read fd
               (fun () -> readsock (Lwt_unix.unix_file_descr fd))

let open_link ?filter ifname =
  let fd = Lwt_unix.of_unix_file_descr (opensock ?filter:filter ifname) in
  let () = Lwt_unix.set_blocking fd false in
  { fd; packets = ref [] }

let close_link t = Lwt_unix.close t.fd

let rec get_packet t =
  let open Lwt.Infix in
  match !(t.packets) with
  | [] -> readsock_lwt t.fd
    >>= (fun packets -> Lwt.return (t.packets := packets))
    >>= (fun () -> get_packet t)
  | hd :: tail -> t.packets := tail; Lwt.return hd

let get_packet_list t = match !(t.packets) with
  | [] -> readsock_lwt t.fd
  | packets -> t.packets := []; Lwt.return packets

let put_packet t b =
  let len = Bytes.length b in
  Lwt_unix.write t.fd b 0 len >>= function
  | n when n != len ->
    Lwt.fail (Unix.Unix_error(Unix.ENOBUFS, "put_packet", ""))
  | n ->
    Lwt.return_unit
