use super::traits::{KeyContext, FromUnsafeSlice};
use super::Error;

pub const PRIVATE_KEY_BYTES:usize = 32usize;

pub type Secret = [u8;PRIVATE_KEY_BYTES];

impl KeyContext for Secret{
    const KEYLENGTH: usize = PRIVATE_KEY_BYTES;



    fn valid(&self)->bool{
        self.len() == PRIVATE_KEY_BYTES
    }
}

impl FromUnsafeSlice for Secret{
    type RHS=Self;

    fn from_unsafe_slice( slice: &[u8]) -> Result<Secret, Error >{
        assert!(slice.len() == PRIVATE_KEY_BYTES);
        let s = [0u8;PRIVATE_KEY_BYTES];
        s[..].copy_from_slice(slice);

        Ok(s)
    }

    fn as_byte_array_ref(&self)-> &[u8;32]{
        &self
    }

}

