use super::Error;

pub trait KeyContext{
    const KEYLENGTH: usize;


    //optional
    fn valid(&self) -> bool{ true }
    fn context(&self)->String{ "None".to_string }

}

pub trait PublicKeyContext<S>{
    type RHS;
    

    fn is_public_key(&self) -> bool{
        return true;
    }


    fn from_secret(secret:&S) -> Result< Self::RHS, Error>;

}

pub trait FromUnsafeSlice{
    type RHS;

    fn from_unsafe_slice(slice:&[u8])-> Result <Self::RHS, Error>;
    fn as_byte_array_ref(&self) -> &Self::RHS;
}
