//! Generate a WireGuard/interestun X25519 key pair without wireguard-tools.
//! Output contains the PRIVATE key. Capture it locally; never paste it into chat.
//! PowerShell: $keys = cargo run --quiet --example keygen | ConvertFrom-Json
fn main() {
    let mut bytes: [u8; 32] = rand::random();
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let private = boringtun::x25519::StaticSecret::from(bytes);
    let public = boringtun::x25519::PublicKey::from(&private);
    println!(
        "{{\"private_key\":\"{}\",\"public_key\":\"{}\"}}",
        hex::encode(private.to_bytes()),
        hex::encode(public.as_bytes())
    );
}
