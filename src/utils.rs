
use ::keypair::KeyPair;
use ::{Secret, PublicX25519, Error, NONCE_BYTES};

use rand::{Rng, OsRng};
use std::time::SystemTime;

pub fn generate_x25519_keypair() -> KeyPair<Secret, PublicX25519> {
    
    KeyPair::<Secret, PublicX25519>::generate_keypair().unwrap()
    
}

pub fn gen_nonce() ->[u8; NONCE_BYTES]{
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let counter = now.as_bytes();
    let l = counter.len();

    let mut nonce = [0u8;NONCE_BYTES];
    nonce[..l].copy_from_slice(&counter);

    let mut r = OsRng::new().unwrap();
    r.fill_bytes(&mut nonce[l..]);

    nonce
    
}
