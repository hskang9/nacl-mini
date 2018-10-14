use std::fmt;
use std::error::Error;
use rustc_hex::hex::ToHex;

use traits::{PublicKeyContext, SecretKeyContext, FromUnsafeSlice}

#[derive(Debug,Clone,PartialEq)]
pub struct KeyPair<S,P>{
    secret: S,
    public: P,
}

impl<S,P> fmt::Display for KeyPair<S, P>
    where S: ToHex, 
          P: ToHex + PublicKeyContext
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result< (), fmt::Error>{
		writeln!(f, "secret:  {}", self.secret.to_hex())?;
		write!(f, "public:  {}", self.public.to_hex())
    }
}


impl<S,P:PublicKeyContext> KeyPair<S,P>{
    pub fn context(&self) -> String{
        self.public.context()
    }
}


impl<S,P> KeyPair<S, P>
    where S: SecretKeyContext + FromUnsafeSlice, 
          P: PublicKeyContext  
{
    pub fn from_secret_slice(slice: &[u8]) -> Result< KeyPair<S,P>, ()>{
        let secret = S::from_unsafe_slice(slice)?;
        let public = P::from_secret(&secret)?;

        if ! <S as SecretKeyContext>::valid(&secret){
            return Err(Error::InvalidSecretKey);
        }

        if ! <P as PublicKeyContext>::valid(&public){
            return Err(Error::InvalidPublicKey);
        }


        Ok(   KeyPair{ secret, public} )
    }
}

impl<S,P> KeyPair<S,P>
    where S: SecretKeyContext, 
          P: PublicKeyContext
{
    pub fn generate_keypair() -> Result < KeyPair<S,P>, ()>{
        let secret =  S::random_fill()?;
        let public =  P::from_secret(&secret)?;
    
    
        if ! <P as PublicKeyContext>::valid(&public){
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










