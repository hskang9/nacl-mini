use super::Error;

pub trait KeyContext{
    const KEYLENGTH: usize;


    //optional
    fn is_valid_key(_arr:&[u8]) -> bool{ true }
    fn context(&self)->String{ "".to_string() }

}

pub trait PublicKeyContext{

    const ISPUBLICKEY: bool = true;

}

pub trait FromUnsafeSlice{
    type RHS;

    fn from_unsafe_slice(slice:&[u8])-> Result <Self::RHS, Error>;
    fn from_unsafe_secret_slice(secret_slice:&[u8]) -> Result< Self::RHS, Error>;
}
