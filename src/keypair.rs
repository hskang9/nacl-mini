use std::fmt;
use std::convert::{From,Into};
use rustc_hex::ToHex;


use traits::{PublicKeyContext, KeyContext};
use utils::rand_fill;

#[derive(Debug,Clone,PartialEq)]
pub struct KeyPair<S,P>{
    secret: S,
    public: P,
}

impl<S,P> fmt::Display for KeyPair<S, P>
    where S: ToHex, 
          P: ToHex 
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result< (), fmt::Error>{
		writeln!(f, "secret:  {}", self.secret.to_hex())?;
		write!(f, "public:  {}", self.public.to_hex())
    }
}



impl<S,P:KeyContext> KeyPair<S,P>{
    pub fn context(&self) -> String{
        self.public.context()
    }
}

impl<S,P> KeyPair<S, P>
    where S: From<[u8]>, 
          P: PublicKeyContext + KeyContext  
{
    pub fn from_secret_slice(slice: &[u8]) -> Result< KeyPair<S,P>, ()>{
        let secret: S = (*slice).into();
        let public = P::from_secret(&secret)?;

        if ! <P as KeyContext>::valid(&public){
            return Err(Error::InvalidPublicKey);
        }


        Ok(   KeyPair{ secret, public} )
    }
}

impl<S,P> KeyPair<S,P>
    where S: From<[u8]> + KeyContext,  
          P: KeyContext + PublicKeyContext
{
    pub fn generate_keypair() -> Result < KeyPair<S,P>, ()>{
        let ssize = S::keylength();
        
        let arr =  [0u8;ssize]; 
        random::fill(&arr)?;
        let secret: S =  arr.into();
        let public =  P::from_secret(&secret)?;
    
        if ! <S as KeyContext>::valid(&secret){
            return Err(Error::InvalidSecretKey);
        }
    
        if ! <P as KeyContext>::valid(&public){
            return Err(Error::InvalidPublicKey);
        }

        Ok( KeyPair{ secret, public } )
    }
}


impl<S,P> KeyPair<S,P>
{
    pub fn secret(&self) -> &S {
        &self.secret
    }

    pub fn public(&self) -> &P {
        &self.public
    }
}










