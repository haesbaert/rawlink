open! Core
open Async
open Deferred.Let_syntax

let command =
  Command.async ~summary:""
    (let%map_open.Command () = Log.Global.set_level_via_param ()
     and ifname = anon ("ifname" %: string) in
     fun () ->
       let link = Async_rawlink.open_link ~promisc:true ifname in
       let rec loop () =
         let%bind.Deferred () =
           Async_rawlink.read_packet link >>| fun pkt ->
           printf "got packet with %d bytes\n%!" (Cstruct.length pkt)
         in
         loop ()
       in
       loop ())

let () = Command_unix.run command
