use std::fmt;
use std::fmt::Write;
use std::convert::{From, Into};
use std::cmp;
use std::ops::Deref;
use rustc_hex::ToHex;

use crypto::curve25519;

use super::{Error,  PUBLIC25519_BYTES};
use super::traits::{KeyContext,PublicKeyContext, FromUnsafeSlice};

static CONTEXT: &str = "x25519";

#[derive(Debug, Clone, PartialEq)]
pub struct Public ( [u8;PUBLIC25519_BYTES]);

impl fmt::Display for Public{
       fn fmt(&self, f:&mut fmt::Formatter)-> Result<(), fmt::Error>{
          for c in &self.0[..PUBLIC25519_BYTES]{
            write!(f, "{:02X} ", c)?;
          }
          Ok(())
      }
}

impl Deref for Public{
    type Target = [u8;PUBLIC25519_BYTES];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToHex for Public{
    fn to_hex(&self) -> String{
        let mut a = String::from("");
        for byte in self.0.iter() {
            write!(&mut a, "{:x}", byte);
        }
        a.to_string()

    }
    
}
impl cmp::PartialEq<[u8; 32]>for Public{
    fn eq(&self, other: &[u8;32])->bool{
        self.0 == *other
    }
}

impl<T> PublicKeyContext<T> for Public
    where T: FromUnsafeSlice
{
    type RHS=Self;

    fn from_secret (secret: &T)-> Result<Public, Error>{
        let secret  = (*secret).as_byte_array_ref();
        let p = curve25519::curve25519_base(secret);
        Public::new(&p)
    }

}


impl KeyContext for Public{
    const KEYLENGTH: usize = PUBLIC25519_BYTES;


    fn valid(&self)->bool{
        //no consensus on if curve25519 keys 
        //should be validated so we only check the len
        return self.0.len() >= PUBLIC25519_BYTES; 
    }
    fn context(&self)->String{
        return CONTEXT.to_string();
    }
}

    

impl Public{
    pub fn new(pk: &[u8;32]) -> Result<Public, Error>{
        let mut p = [0u8;32];
        p.copy_from_slice(pk);
        Ok(Public(p))
    }



}



