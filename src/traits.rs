pub trait KeyContext{
    fn keylength() -> usize;

    //optional
    fn valid(&self) -> bool{ true }
    fn context(&self)->String{ "No context".to_string }
}

pub trait PublicKeyContext<S>{
    type E;
    

    fn is_public_key(&self) -> bool{
        return true;
    }


    fn from_secret(secret:&S) -> Result< Self, Self::E>;

}


