#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  let opams =
    [ Pkg.opam_file "opam" ~lint_deps_excluding:(Some ["ppx_tools" ; "ppx_sexp_conv"]) ]
  in
  Pkg.describe ~opams "rawlink" @@ fun _ ->
  Ok [
    Pkg.clib "lib/librawlink_stubs.clib";
    Pkg.mllib "lib/rawlink.mllib";
  ];
