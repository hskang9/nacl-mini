use std::fmt;
use rustc_hex::ToHex;

use super::Error;
use super::traits::{PublicKeyContext, KeyContext, FromUnsafeSlice};
use super::utils::random_fill;

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
    where S: FromUnsafeSlice, 
          P: PublicKeyContext<S> + KeyContext  
{
    pub fn from_secret_slice(slice: &[u8]) -> Result< KeyPair<S,P>, Error>{
        let secret  = S::from_unsafe_slice(slice)?;
    
        //let public = P::generator_fn     P::generate(secret)
        //scalarmult
        //p::generate_from_slice(secret.slice()
        //) p.slice_

        let public = P::from_secret(&secret)?;

        if ! public.valid(){
            return Err(Error::InvalidPublicKey);
        }


        Ok(   KeyPair{ secret, public} )
    }
}

impl<S,P> KeyPair<S,P>
    where S: FromUnsafeSlice + KeyContext,  
          P: KeyContext + PublicKeyContext<S>
{
    pub fn generate_keypair() -> Result < KeyPair<S,P>, Error>{
        
        let arr =  vec![0u8;S::KEYLENGTH]; 
        random_fill(&arr[..])?;
        let secret  = S::from_unsafe_slice(&arr[..])?;
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










