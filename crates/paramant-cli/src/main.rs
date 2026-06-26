//! paramant-cli: a thin command-line bridge to paramant-core's ML-DSA-65
//! signatures, so a non-Rust caller (e.g. BeerHive's Python action-log) can
//! `keygen` / `sign` / `verify` via subprocess. Keys and signatures are hex on
//! disk; the message is read from a *file* to stay binary-safe and avoid argv
//! length limits. No dependencies beyond paramant-core + hex (ADR-0004
//! code-minimization): the crypto is entirely paramant-core's.
//!
//! Usage:
//!   paramant-cli keygen <pk_out.hex> <sk_out.hex>     # sk_out is chmod 0600
//!   paramant-cli sign   <sk.hex> <msg_file>           # prints signature hex
//!   paramant-cli verify <pk.hex> <msg_file> <sig.hex> # exit 0 = ok, 1 = bad
//!
//! Exit codes: 0 ok, 1 invalid signature, 2 usage/IO/crypto error.

use std::process::exit;

use paramant_core::sig::ml_dsa_65;

fn die(msg: &str) -> ! {
    eprintln!("paramant-cli: {msg}");
    exit(2);
}

fn read_bytes(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")))
}

fn read_hex(path: &str) -> Vec<u8> {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
    hex::decode(s.trim()).unwrap_or_else(|e| die(&format!("decode hex in {path}: {e}")))
}

fn arg(args: &[String], i: usize, usage: &str) -> String {
    args.get(i).cloned().unwrap_or_else(|| die(usage))
}

fn write_secret(path: &str, data: &str) {
    std::fs::write(path, data).unwrap_or_else(|e| die(&format!("write {path}: {e}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("") {
        "keygen" => {
            let pk_out = arg(&args, 2, "keygen <pk_out.hex> <sk_out.hex>");
            let sk_out = arg(&args, 3, "keygen <pk_out.hex> <sk_out.hex>");
            let (pk, sk) = ml_dsa_65::keygen().unwrap_or_else(|e| die(&format!("keygen: {e}")));
            std::fs::write(&pk_out, hex::encode(pk.as_bytes()))
                .unwrap_or_else(|e| die(&format!("write {pk_out}: {e}")));
            write_secret(&sk_out, &hex::encode(sk.as_bytes()));
            println!("ok");
        }
        "sign" => {
            let sk_path = arg(&args, 2, "sign <sk.hex> <msg_file>");
            let msg_path = arg(&args, 3, "sign <sk.hex> <msg_file>");
            let sk = ml_dsa_65::SecretKey::from_bytes(&read_hex(&sk_path))
                .unwrap_or_else(|e| die(&format!("secret key: {e}")));
            let sig = ml_dsa_65::sign(&sk, &read_bytes(&msg_path))
                .unwrap_or_else(|e| die(&format!("sign: {e}")));
            println!("{}", hex::encode(sig.as_bytes()));
        }
        "verify" => {
            let pk_path = arg(&args, 2, "verify <pk.hex> <msg_file> <sig.hex>");
            let msg_path = arg(&args, 3, "verify <pk.hex> <msg_file> <sig.hex>");
            let sig_path = arg(&args, 4, "verify <pk.hex> <msg_file> <sig.hex>");
            let pk = ml_dsa_65::PublicKey::from_bytes(&read_hex(&pk_path))
                .unwrap_or_else(|e| die(&format!("public key: {e}")));
            // A wrong-length signature is simply invalid, not an error.
            let sig = match ml_dsa_65::Signature::from_bytes(&read_hex(&sig_path)) {
                Ok(s) => s,
                Err(_) => {
                    println!("bad");
                    exit(1);
                }
            };
            match ml_dsa_65::verify(&pk, &read_bytes(&msg_path), &sig) {
                Ok(true) => println!("ok"),
                Ok(false) => {
                    println!("bad");
                    exit(1);
                }
                Err(e) => die(&format!("verify: {e}")),
            }
        }
        _ => die("usage: paramant-cli <keygen|sign|verify> ..."),
    }
}
