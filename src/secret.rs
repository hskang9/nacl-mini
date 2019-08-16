use super::traits::{KeyContext, FromUnsafeSlice};
use super::Error;

pub const PRIVATE_KEY_BYTES:usize = 32usize;

pub type Secret = [u8;PRIVATE_KEY_BYTES];

impl KeyContext for Secret{
    const KEYLENGTH: usize = PRIVATE_KEY_BYTES;



    fn is_valid_key(arr:&[u8])->bool{
        arr.len() == PRIVATE_KEY_BYTES
    }
}

impl FromUnsafeSlice for Secret{
    type RHS=Self;

    fn from_unsafe_slice( slice: &[u8]) -> Result<Secret, Error >{
        assert!(slice.len() == PRIVATE_KEY_BYTES);
        let mut s = [0u8;PRIVATE_KEY_BYTES];
        s.copy_from_slice(slice);

        Ok(s)
    }

    fn from_unsafe_secret_slice( secret_slice: &[u8])-> Result<Secret,Error>{
        Secret::from_unsafe_slice(secret_slice)
    }


}

