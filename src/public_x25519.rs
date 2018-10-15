use std::fmt;
use std::fmt::Write;
use std::convert::{From, Into};
use std::cmp;
use std::ops::Deref;
use rustc_hex::ToHex;

use crypto::curve25519;

use ::{Error, Secret, PUBLIC25519_BYTES};
use traits::{KeyContext,PublicKeyContext};

static CONTEXT: &str = "x25519";

#[derive(Debug, Clone, PartialEq)]
pub struct PublicX25519 ( [u8;PUBLIC25519_BYTES]);

impl fmt::Display for PublicX25519{
       fn fmt(&self, f:&mut fmt::Formatter)-> Result<(), fmt::Error>{
          for c in &self.0[..PUBLIC25519_BYTES]{
            write!(f, "{:02X} ", c)?;
          }
          Ok(())
      }
}

impl Deref for PublicX25519{
    type Target = [u8;PUBLIC25519_BYTES];
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

impl<T> PublicKeyContext<T> for PublicX25519
    where T: Into<[u8;32]>
{
    type E= Error;

    fn from_secret (secret: &T)-> Result<PublicX25519, Error>{
        let secret: [u8;32] = secret.into();
        let p = curve25519::curve25519_base(&secret);
        PublicX25519::new(&p)
    }

}

impl KeyContext for PublicX25519{
    fn keylength()->usize{
        return PUBLIC25519_BYTES;
    }

    fn valid(&self)->bool{
        //no consensus on if curve25519 keys 
        //should be validated so we only check the len
        return self.0.len() >= PUBLIC25519_BYTES; 
    }
    fn context(&self)->bool{
        return CONTEXT;
    }
}

    

impl PublicX25519{
    pub fn new(pk: &[u8;32]) -> Result<PublicX25519, Error>{
        let mut p = [0u8;32];
        p.copy_from_slice(pk);
        Ok(PublicX25519(p))
    }



}



