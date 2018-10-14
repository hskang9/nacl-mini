use std::fmt;
use std::fmt::Write;
use std::cmp;
use std::ops::Deref;
use rustc_hex::ToHex;

use crypto::curve25519;

use super::{Error, Secret};
use traits::{SecretKeyContext, PublicKeyContext, FromUnsafeSlice};

static CONTEXT: &str = "x25519";
pub const PUBLIC_KEY_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct PublicX25519 ( [u8;PUBLIC_KEY_BYTES]);

impl fmt::Display for PublicX25519{
       fn fmt(&self, f:&mut fmt::Formatter)-> Result<(), fmt::Error>{
          for c in &self.0[..PUBLIC_KEY_BYTES]{
            write!(f, "{:02X} ", c)?;
          }
          Ok(())
      }
}

impl Deref for PublicX25519{
    type Target = [u8;32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToHex for PublicX25519{
    fn to_hex(&self) -> String{
        let mut a = String::from("");
        for byte in self.0.iter() {
            write!(&mut a, "{:x}", byte);
        }
        a.to_string()

    }
    
}
impl cmp::PartialEq<[u8; 32]>for PublicX25519{
    fn eq(&self, other: &[u8;32])->bool{
        self.0 == *other
    }
}

impl PublicKeyContext for PublicX25519{
    type E= Error;
    type S = Secret;

    fn valid(&self)->bool{
        return self.0.len() > PUBLIC; //no consensus on if curve25519 keys 
                     //should be validated so we only check the len
    }
    fn context(&self)->bool{
        return CONTEXT;
    }

    fn from_secret(secret: &Secret)-> Result<PublicX25519, ()>{
        let secret_slice = secret.as_bytes();
        let p = curve25519::curve25519_base(secret_slice);
        PublicX25519::new(&p)
    }

}

impl FromUnsafeSlice for PublicX25519{
    type E= Error;

    fn from_unsafe_slice(slice: &[u8])->Result< PublicX25519, Error>{
        if slice.len() < 32u;{
            return Err(Error::InvalidkeyLength);
        }
        PublicX25519::new(&slice)
    }
}

    

impl PublicX25519{
    pub fn new(s: &[u8;32]) -> Result<PublicX25519, Error>{
        let mut p = [0u8;32];
        p.copy_from_slice(s);
        Ok(PublicX25519(p))
    }



}



