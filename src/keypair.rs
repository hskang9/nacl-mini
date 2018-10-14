use std::fmt;
use rustc_hex::hex::ToHex;

use super::{Public, Secret, Error};


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


impl<S,P> KeyPair<S, P>
    where S: SecretKeyContext + FromSecretSlice, 
          P: PublicKeyContext + FromSecretSlice 
{
    pub fn from_secret_slice(slice: &[u8]) -> Result< KeyPair<S,P>, std::error::Error>{
        let secret = S::from_unsafe_slice(slice)?;
        let public = P::from_unsafe_slice(slice)?;

        if !public.valid_context() || !secret.valid_context(){
            return Err(Error::InvalidKeyType)

        Ok(   KeyPair<S,P>{ secret, public} )
    }
}

impl<S,P> KeyPair<S,P>
    where S: RandomFill + SecretKeyContext,
          P: FromSecret<S> + PublicKeyContext
{
    fn generate_keypair() -> Result < KeyPair<S,P>, std::error::Error>{
        let secret = S::random_fill()?;
        let public = <P as FromSecret<S> >::from_secret(&secret)?;

        Ok( KeyPair<S,P> { secret, public } )
    }

}


impl<S,P> KeyPair<S,P>





