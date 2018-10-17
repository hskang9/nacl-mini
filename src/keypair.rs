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
    where S: FromUnsafeSlice<RHS=S>, 
          P: PublicKeyContext + KeyContext + FromUnsafeSlice<RHS=P>  
{
    pub fn from_secret_slice(slice: &[u8]) -> Result< KeyPair<S,P>, Error>{
        let secret  = S::from_unsafe_slice(slice)?;
    

        let public = P::from_unsafe_secret_slice(slice)?;


        Ok(   KeyPair{ secret, public} )
    }
}

impl<S,P> KeyPair<S,P>
    where S: FromUnsafeSlice<RHS=S> + KeyContext,  
          P: PublicKeyContext + KeyContext + FromUnsafeSlice<RHS=P>
{
    pub fn generate_keypair() -> Result < KeyPair<S,P>, Error>{
        
        let mut arr =  vec![0u8;S::KEYLENGTH]; 
        random_fill(&mut arr[..])?;
        let secret  = S::from_unsafe_slice(&arr[..])?;
        let public =  P::from_unsafe_secret_slice(&arr[..])?;
    

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










