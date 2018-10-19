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


#[cfg(test)]
mod test{


    use super::KeyPair;
    use super::super::{Public, Secret};
    
    // test array from cr.yp.to/highspeed/naclcrypto-20090310.pdf
    const SK: [u8;32] =
        [  
             0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
            ,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
            ,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
            ,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
        ];



    #[test]
    fn test_public_key(){
        let kp = KeyPair::<Secret,Public>::from_secret_slice(&SK).unwrap();

         let expected:[u8;32]=          
                    [
                        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
                        ,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
                        ,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
                        ,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a 
                    ];

        assert_eq!(**(kp.public()), expected);

    }


}
        





