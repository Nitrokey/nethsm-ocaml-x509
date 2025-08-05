let ( let* ) = Result.bind

type ecdsa = [
  | `P256 of Mirage_crypto_ec.P256.Dsa.priv
  | `P384 of Mirage_crypto_ec.P384.Dsa.priv
  | `P521 of Mirage_crypto_ec.P521.Dsa.priv
  | `P256K1 of Mirage_crypto_ec.P256k1.Dsa.priv
  | `BrainpoolP256 of Mirage_crypto_ec.BrainpoolP256.Dsa.priv
  | `BrainpoolP384 of Mirage_crypto_ec.BrainpoolP384.Dsa.priv
  | `BrainpoolP512 of Mirage_crypto_ec.BrainpoolP512.Dsa.priv
]

type t = [
  ecdsa
  | `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv
]

let key_type = function
  | `RSA _ -> `RSA
  | `ED25519 _ -> `ED25519
  | `P256 _ -> `P256
  | `P384 _ -> `P384
  | `P521 _ -> `P521
  | `P256K1 _ -> `P256K1
  | `BrainpoolP256 _ -> `BrainpoolP256
  | `BrainpoolP384 _ -> `BrainpoolP384
  | `BrainpoolP512 _ -> `BrainpoolP512

let generate ?seed ?(bits = 4096) typ =
  let g = match seed with
    | None -> None
    | Some seed -> Some Mirage_crypto_rng.(create ~seed (module Fortuna))
  in
  match typ with
  | `RSA -> `RSA (Mirage_crypto_pk.Rsa.generate ?g ~bits ())
  | `ED25519 -> `ED25519 (fst (Mirage_crypto_ec.Ed25519.generate ?g ()))
  | `P256 -> `P256 (fst (Mirage_crypto_ec.P256.Dsa.generate ?g ()))
  | `P384 -> `P384 (fst (Mirage_crypto_ec.P384.Dsa.generate ?g ()))
  | `P521 -> `P521 (fst (Mirage_crypto_ec.P521.Dsa.generate ?g ()))
  | `P256K1 -> `P256K1 (fst (Mirage_crypto_ec.P256k1.Dsa.generate ?g ()))
  | `BrainpoolP256 -> `BrainpoolP256 (fst (Mirage_crypto_ec.BrainpoolP256.Dsa.generate ?g ()))
  | `BrainpoolP384 -> `BrainpoolP384 (fst (Mirage_crypto_ec.BrainpoolP384.Dsa.generate ?g ()))
  | `BrainpoolP512 -> `BrainpoolP512 (fst (Mirage_crypto_ec.BrainpoolP512.Dsa.generate ?g ()))

let of_octets data =
  let open Mirage_crypto_ec in
  let ec_err e =
    Result.map_error
      (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
      e
  in
  function
  | `RSA -> Error (`Msg "cannot decode an RSA key")
  | `ED25519 ->
    let* k = ec_err (Ed25519.priv_of_octets data) in
    Ok (`ED25519 k)
  | `P256 ->
    let* k = ec_err (P256.Dsa.priv_of_octets data) in
    Ok (`P256 k)
  | `P384 ->
    let* k = ec_err (P384.Dsa.priv_of_octets data) in
    Ok (`P384 k)
  | `P521 ->
    let* k = ec_err (P521.Dsa.priv_of_octets data) in
    Ok (`P521 k)
  | `P256K1 ->
    let* k = ec_err (P256k1.Dsa.priv_of_octets data) in
    Ok (`P256K1 k)
  | `BrainpoolP256 ->
    let* k = ec_err (BrainpoolP256.Dsa.priv_of_octets data) in
    Ok (`BrainpoolP256 k)
  | `BrainpoolP384 ->
    let* k = ec_err (BrainpoolP384.Dsa.priv_of_octets data) in
    Ok (`BrainpoolP384 k)
  | `BrainpoolP512 ->
    let* k = ec_err (BrainpoolP512.Dsa.priv_of_octets data) in
    Ok (`BrainpoolP512 k)

let of_string ?seed_or_data ?bits typ data =
  match seed_or_data with
  | None ->
    begin match typ with
      | `RSA -> Ok (generate ~seed:data ?bits `RSA)
      | _ ->
        let* data = Base64.decode data in
        of_octets data typ
    end
  | Some `Seed ->
    Ok (generate ~seed:data ?bits typ)
  | Some `Data ->
    let* data = Base64.decode data in
    of_octets data typ

let public = function
  | `RSA priv -> `RSA (Mirage_crypto_pk.Rsa.pub_of_priv priv)
  | `ED25519 priv -> `ED25519 (Mirage_crypto_ec.Ed25519.pub_of_priv priv)
  | `P256 priv -> `P256 (Mirage_crypto_ec.P256.Dsa.pub_of_priv priv)
  | `P384 priv -> `P384 (Mirage_crypto_ec.P384.Dsa.pub_of_priv priv)
  | `P521 priv -> `P521 (Mirage_crypto_ec.P521.Dsa.pub_of_priv priv)
  | `P256K1 priv -> `P256K1 (Mirage_crypto_ec.P256k1.Dsa.pub_of_priv priv)
  | `BrainpoolP256 priv -> `BrainpoolP256 (Mirage_crypto_ec.BrainpoolP256.Dsa.pub_of_priv priv)
  | `BrainpoolP384 priv -> `BrainpoolP384 (Mirage_crypto_ec.BrainpoolP384.Dsa.pub_of_priv priv)
  | `BrainpoolP512 priv -> `BrainpoolP512 (Mirage_crypto_ec.BrainpoolP512.Dsa.pub_of_priv priv)

let sign hash ?(rand_k=false) ?scheme key data =
  let open Mirage_crypto_ec in
  let hashed () = Public_key.hashed hash data
  and ecdsa_to_str s = Algorithm.ecdsa_sig_to_octets s
  in
  let scheme = Key_type.opt_signature_scheme ?scheme (key_type key) in
  try
    match key, scheme with
    | `RSA key, `RSA_PSS ->
      let module H = (val (Digestif.module_of_hash' hash)) in
      let module PSS = Mirage_crypto_pk.Rsa.PSS(H) in
      let* d = hashed () in
      Ok (PSS.sign ~key (`Digest d))
    | `RSA key, `RSA_PKCS1 ->
      let* d = hashed () in
      Ok (Mirage_crypto_pk.Rsa.PKCS1.sign ~key ~hash (`Digest d))
    | `ED25519 key, `ED25519 ->
      begin match data with
        | `Message m -> Ok (Ed25519.sign ~key m)
        | `Digest _ -> Error (`Msg "Ed25519 only suitable with raw message")
      end
    | #ecdsa as key, `ECDSA ->
      let* data = hashed () in
      let sign_ecdsa ~sign ~bit_length =
        let byte_length = (bit_length + 7) / 8 in
        let mask = (1 lsl (bit_length mod 8)) - 1 in
        let gen_k () =
          let buf = Bytes.create byte_length in
          Mirage_crypto_rng.generate_into buf byte_length;
          if mask > 0 then Bytes.set_uint8 buf 0 ((Bytes.get_uint8 buf 0) land mask);
          Bytes.unsafe_to_string buf
        in
        fun key data ->
          let data = if String.length data > byte_length then
            String.sub data 0 byte_length
          else
            data
          in
          let rec go () =
            let k = match rand_k with
              | false -> None
              | true -> Some (gen_k ())
            in
            try
              Ok (sign ?mask:None ~key ?k data)
            with
            | Invalid_argument _ -> go ()
            | Mirage_crypto_ec.Message_too_long ->
                Error (`Msg "data too long")
          in
          go ()
      in
      Result.map ecdsa_to_str (match key with
          | `P256 key -> P256.Dsa.(sign_ecdsa ~sign ~bit_length) key data
          | `P384 key -> P384.Dsa.(sign_ecdsa ~sign ~bit_length) key data
          | `P521 key -> P521.Dsa.(sign_ecdsa ~sign ~bit_length) key data
          | `P256K1 key -> P256k1.Dsa.(sign_ecdsa ~sign ~bit_length) key data
          | `BrainpoolP256 key -> BrainpoolP256.Dsa.(sign_ecdsa ~sign ~bit_length) key data
          | `BrainpoolP384 key -> BrainpoolP384.Dsa.(sign_ecdsa ~sign ~bit_length) key data
          | `BrainpoolP512 key -> BrainpoolP512.Dsa.(sign_ecdsa ~sign ~bit_length) key data)
    | _ -> Error (`Msg "invalid key and signature scheme combination")
  with
  | Mirage_crypto_pk.Rsa.Insufficient_key ->
    Error (`Msg "RSA key of insufficient length")
  | Message_too_long -> Error (`Msg "message too long")

module Asn = struct
  open Asn.S
  open Mirage_crypto_pk

  (* RSA *)
  let other_prime_infos =
    sequence_of @@
      (sequence3
        (required ~label:"prime"       unsigned_integer)
        (required ~label:"exponent"    unsigned_integer)
        (required ~label:"coefficient" unsigned_integer))

  let rsa_private_key =
    let integer = map Z_extra.of_octets_be Z_extra.to_octets_be unsigned_integer in
    let f (v, (n, (e, (d, (p, (q, (dp, (dq, (q', other))))))))) =
      match (v, other) with
      | (0, None) ->
        begin match Rsa.priv ~e ~d ~n ~p ~q ~dp ~dq ~q' with
          | Ok p -> p
          | Error (`Msg m) -> parse_error "bad RSA private key %s" m
        end
      | _         -> parse_error "multi-prime RSA keys not supported"
    and g { Rsa.e; d; n; p; q; dp; dq; q' } =
      (0, (n, (e, (d, (p, (q, (dp, (dq, (q', None))))))))) in
    map f g @@
    sequence @@
        (required ~label:"version"         int)
      @ (required ~label:"modulus"         integer)  (* n    *)
      @ (required ~label:"publicExponent"  integer)  (* e    *)
      @ (required ~label:"privateExponent" integer)  (* d    *)
      @ (required ~label:"prime1"          integer)  (* p    *)
      @ (required ~label:"prime2"          integer)  (* q    *)
      @ (required ~label:"exponent1"       integer)  (* dp   *)
      @ (required ~label:"exponent2"       integer)  (* dq   *)
      @ (required ~label:"coefficient"     integer)  (* qinv *)
     -@ (optional ~label:"otherPrimeInfos" other_prime_infos)

  (* For outside uses. *)
  let (rsa_private_of_octets, rsa_private_to_octets) =
    Asn_grammars.projections_of Asn.der rsa_private_key

  (* PKCS8 *)
  let (rsa_priv_of_str, rsa_priv_to_str) =
    Asn_grammars.project_exn rsa_private_key

  let ec_to_err = function
    | Ok x -> x
    | Error e -> parse_error "%a" Mirage_crypto_ec.pp_error e

  let ed25519_of_str, ed25519_to_str =
    Asn_grammars.project_exn octet_string

  let ec_private_key =
    let f (v, pk, nc, pub) =
      if v <> 1 then
        parse_error "bad version for ec Private key"
      else
        let curve = match nc with
          | Some c -> Some (Algorithm.curve_of_oid c)
          | None -> None
        in
        pk, curve, pub
    and g (pk, curve, pub) =
      let nc = match curve with
        | None -> None | Some c -> Some (Algorithm.curve_to_oid c)
      in
      (1, pk, nc, pub)
    in
    Asn.S.map f g @@
    sequence4
      (required ~label:"version" int) (* ecPrivkeyVer1(1) *)
      (required ~label:"privateKey" octet_string)
      (* from rfc5480: choice3, but only namedCurve is allowed in PKIX *)
      (optional ~label:"namedCurve" (explicit 0 oid))
      (optional ~label:"publicKey" (explicit 1 bit_string))

  let ec_of_str, ec_to_str =
    Asn_grammars.project_exn ec_private_key

  let reparse_ec_private curve priv =
    let open Mirage_crypto_ec in
    match curve with
    | `SECP256R1 -> let* p = P256.Dsa.priv_of_octets priv in Ok (`P256 p)
    | `SECP384R1 -> let* p = P384.Dsa.priv_of_octets priv in Ok (`P384 p)
    | `SECP521R1 -> let* p = P521.Dsa.priv_of_octets priv in Ok (`P521 p)
    | `SECP256K1 -> let* p = P256k1.Dsa.priv_of_octets priv in Ok (`P256K1 p)
    | `BRAINPOOLP256R1 -> let* p = BrainpoolP256.Dsa.priv_of_octets priv in Ok (`BrainpoolP256 p)
    | `BRAINPOOLP384R1 -> let* p = BrainpoolP384.Dsa.priv_of_octets priv in Ok (`BrainpoolP384 p)
    | `BRAINPOOLP512R1 -> let* p = BrainpoolP512.Dsa.priv_of_octets priv in Ok (`BrainpoolP512 p)

  (* external use (result) *)
  let ec_priv_of_str =
    let dec, _ = Asn_grammars.projections_of Asn.der ec_private_key in
    fun cs ->
      let* priv, curve, _pub = dec cs in
      match curve with
      | None -> Error (`Parse "no curve provided")
      | Some c ->
        Result.map_error
          (fun e -> `Parse (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
          (reparse_ec_private c priv)

  let ec_of_str ?curve cs =
    let (priv, named_curve, _pub) = ec_of_str cs in
    let nc =
      match curve, named_curve with
      | Some c, None -> c
      | None, Some c -> c
      | Some c, Some c' -> if c = c' then c else parse_error "conflicting curve"
      | None, None -> parse_error "unknown curve"
    in
    ec_to_err (reparse_ec_private nc priv)

  let ec_to_str ?curve ?pub key = ec_to_str (key, curve, pub)

  let reparse_private pk =
    match pk with
    | (0, Algorithm.RSA, cs) -> `RSA (rsa_priv_of_str cs)
    | (0, Algorithm.ED25519, cs) ->
      let data = ed25519_of_str cs in
      `ED25519 (ec_to_err (Mirage_crypto_ec.Ed25519.priv_of_octets data))
    | (0, Algorithm.EC_pub curve, cs) -> ec_of_str ~curve cs
    | _ -> parse_error "unknown private key info"

  let unparse_private p =
    let open Mirage_crypto_ec in
    let open Algorithm in
    let alg, cs =
      match p with
      | `RSA pk -> RSA, rsa_priv_to_str pk
      | `ED25519 pk -> ED25519, ed25519_to_str (Ed25519.priv_to_octets pk)
      | `P256 pk -> EC_pub `SECP256R1, ec_to_str (P256.Dsa.priv_to_octets pk)
      | `P384 pk -> EC_pub `SECP384R1, ec_to_str (P384.Dsa.priv_to_octets pk)
      | `P521 pk -> EC_pub `SECP521R1, ec_to_str (P521.Dsa.priv_to_octets pk)
      | `P256K1 pk -> EC_pub `SECP256K1, ec_to_str (P256k1.Dsa.priv_to_octets pk)
      | `BrainpoolP256 pk -> EC_pub `BRAINPOOLP256R1, ec_to_str (BrainpoolP256.Dsa.priv_to_octets pk)
      | `BrainpoolP384 pk -> EC_pub `BRAINPOOLP384R1, ec_to_str (BrainpoolP384.Dsa.priv_to_octets pk)
      | `BrainpoolP512 pk -> EC_pub `BRAINPOOLP512R1, ec_to_str (BrainpoolP512.Dsa.priv_to_octets pk)
    in
    (0, alg, cs)

  let private_key_info =
    map reparse_private unparse_private @@
    sequence3
      (required ~label:"version"             int)
      (required ~label:"privateKeyAlgorithm" Algorithm.identifier)
      (required ~label:"privateKey"          octet_string)
      (* TODO: there's an
         (optional ~label:"attributes" @@ implicit 0 (SET of Attributes)
         which are defined in X.501; but nobody seems to use them anyways *)

  let (private_of_octets, private_to_octets) =
    Asn_grammars.projections_of Asn.der private_key_info
end

let decode_der cs =
  Asn_grammars.err_to_msg (Asn.private_of_octets cs)

let encode_der = Asn.private_to_octets

let decode_pem cs =
  let* data = Pem.parse cs in
  let rsa_p (t, _) = String.equal "RSA PRIVATE KEY" t
  and ec_p (t, _) = String.equal "EC PRIVATE KEY" t
  and pk_p (t, _) = String.equal "PRIVATE KEY" t
  in
  let r, _ = List.partition rsa_p data
  and ec, _ = List.partition ec_p data
  and p, _ = List.partition pk_p data
  in
  let* k =
    Pem.foldM (fun (_, k) ->
        let* k = Asn_grammars.err_to_msg (Asn.rsa_private_of_octets k) in
        Ok (`RSA k)) r
  in
  let* k' =
    Pem.foldM (fun (_, k) ->
        Asn_grammars.err_to_msg (Asn.ec_priv_of_str k)) ec
  in
  let* k'' =
    Pem.foldM (fun (_, k) ->
        Asn_grammars.err_to_msg (Asn.private_of_octets k)) p
  in
  Pem.exactly_one ~what:"private key" (k @ k' @ k'')

let encode_pem p =
  Pem.unparse ~tag:"PRIVATE KEY" (Asn.private_to_octets p)
