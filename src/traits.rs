

pub trait SecretKeyContext{
    type E;

    //fn random_fill() -> Result< Self, Self::E> ;   
    
    fn valid(&self) -> bool;
    fn as_bytes(&self) -> &[u8];

}


pub trait PublicKeyContext{
    type S: SecretKeyContext;
    type E;

    fn valid(&self) -> bool;

    fn is_public_key(&self) -> bool{
        return true;
    }

    fn context(&self)->String;

    fn from_secret(&Self::S) -> Result< Self, Self::E>;

}


pub trait FromUnsafeSlice{
    type E;
    
    fn from_unsafe_slice(slice: &[u8])-> Result< Self , Self::E>;
    
}

