open Lwt.Infix

type t = {
  fd : Lwt_unix.file_descr;
  packets : string list ref;
}

external opensock: string -> Unix.file_descr = "caml_rawlink_open"
external readsock: Unix.file_descr -> string list = "caml_rawlink_read"

let readsock_lwt fd =
  Lwt_unix.blocking fd >>= function
  | true -> failwith "readsock_lwt: socket must be nonblocking"
  | false -> Lwt_unix.wrap_syscall Lwt_unix.Read fd
               (fun () -> readsock (Lwt_unix.unix_file_descr fd))

let open_link ifname = {
  fd = Lwt_unix.of_unix_file_descr (opensock ifname);
  packets = ref []
}

let close_link t = Unix.close (Lwt_unix.unix_file_descr t.fd)

let close_link_lwt t = Lwt_unix.close t.fd

let rec get_packet t = match !(t.packets) with
  | [] -> t.packets := readsock (Lwt_unix.unix_file_descr t.fd); get_packet t
  | hd :: tail -> t.packets := tail; hd

let rec get_packet_lwt t =
  let open Lwt.Infix in
  match !(t.packets) with
  | [] -> readsock_lwt t.fd
    >>= (fun packets -> Lwt.return (t.packets := packets))
    >>= (fun () -> get_packet_lwt t)
  | hd :: tail -> t.packets := tail; Lwt.return hd

let get_packet_list t = match !(t.packets) with
  | [] -> readsock (Lwt_unix.unix_file_descr t.fd)
  | packets -> t.packets := []; packets

let get_packet_list_lwt t = match !(t.packets) with
  | [] -> readsock_lwt t.fd
  | packets -> t.packets := []; Lwt.return packets

