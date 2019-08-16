use std::fmt;
use std::fmt::Write;
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

impl PublicKeyContext for Public {}


impl KeyContext for Public{
    const KEYLENGTH: usize = PUBLIC25519_BYTES;


    fn is_valid_key(arr: &[u8])->bool{
        //no consensus on if curve25519 keys 
        //should be validated so we only check the len
        arr.len() >= PUBLIC25519_BYTES 
    }
    fn context(&self)->String{
        CONTEXT.to_string()
    }
}

impl FromUnsafeSlice for Public{
    type RHS=Self;

    fn from_unsafe_secret_slice (secret: &[u8])-> Result<Public, Error>{
        let p = curve25519::curve25519_base(secret);
        Ok(Public::new(&p))
    }

    fn from_unsafe_slice(slice: &[u8])->Result<Public, Error>{
        assert!(Public::is_valid_key(slice));
        let mut p =[0u8;PUBLIC25519_BYTES];
        p.copy_from_slice(&slice[..32]);
        Ok (  Public(p))
    }

}

impl Public{
    pub fn new(pk: &[u8;32]) -> Public{
        let mut p = [0u8;32];
        p.copy_from_slice(pk);
        Public(p)
    }



}



