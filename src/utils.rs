
use ::{KeyPair, Secret, PublicX25519, Error, XSALSA20_NONCE_BYTES};

use rand::{Rng, OsRng};
use std::time::SystemTime;

const MAX_ARRAY_LEN: usize = 128usize;


pub fn random_fill(arr: &[u8])->Result<(), Error>{
    let l = arr.len()
    if l > MAX_ARRAY_LEN{
        return Err(Error::InvalidBufferLength);
    }
    
    let mut r = OsRng::new().unwrap();
    r.fill_bytes(&mut arr[..l]);
    
    
    Ok(())
}

pub fn gen_nonce() ->[u8; XSALSA20_NONCE_BYTES]{
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let counter = now.as_bytes();
    let l = counter.len();

    let mut nonce = [0u8;XSALSA20_NONCE_BYTES];
    nonce[..l].copy_from_slice(&counter);

    let mut r = OsRng::new().unwrap();
    r.fill_bytes(&mut nonce[l..]);

    nonce
    
}
