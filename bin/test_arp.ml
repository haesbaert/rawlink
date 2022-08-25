let a_mac = Macaddr.of_string_exn "18:18:18:18:18:18"
let a_ip = Ipaddr.V4.of_string_exn "18.18.18.18"
let _b_mac = Macaddr.of_string_exn "29:29:29:29:29:29"
let b_ip = Ipaddr.V4.of_string_exn "29.29.29.29"

let a_arp_request =
  let source_mac = a_mac in
  let source_ip = a_ip in
  let target_mac = Macaddr.of_string_exn "00:00:00:00:00:00" in
  let target_ip = b_ip in
  let arp = Arp_packet.{ operation = Arp_packet.Request; source_mac; source_ip; target_mac; target_ip } in
  let eth = Ethernet.Packet.{ source = source_mac; destination = Macaddr.broadcast; ethertype = `ARP } in
  Cstruct.append (Ethernet.Packet.make_cstruct eth) (Arp_packet.encode arp)

let pp hdr buf =
  print_string hdr;
  Cstruct.hexdump buf;
  print_newline ()

let () =
  Eio_main.run @@ fun _env ->
  Eio.Switch.run (fun sw ->
      let a_link = Eio_rawlink.open_link ~sw ~promisc:true "lo" in
      let b_link = Eio_rawlink.open_link ~sw ~promisc:true "lo" in

      (* Make an arp request on a, answer from b *)
      Eio_rawlink.send_packet a_link (Eio.Flow.cstruct_source [ a_arp_request ]);
      pp "A sent:" a_arp_request;
      Eio_rawlink.close_link a_link;
      let rec loop () =
        let pkt = Eio_rawlink.read_packet b_link in
        pp "B got:" pkt;
        if Cstruct.equal pkt a_arp_request then
          let () = Eio_rawlink.close_link b_link in
          Printf.printf "match !\n%!"
        else
          loop ()
      in
      loop ())
