use std::fmt;
use rustc_hex::ToHex;

use crypto::curve25519;
use ethkey::{Generator, Random};
use super::{PublicX25519, Secret, Error};

pub struct KeyPairX25519{
    secret: Secret,
    public: PublicX25519,
}


impl fmt::Display for KeyPairX25519{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		writeln!(f, "secret:  {}", self.secret.to_hex())?;
		write!(f, "public:  {}", self.public.to_hex())
    }
}


impl KeyPairX25519{
    pub fn from_secret_slice(slice: &[u8]) -> Result<KeyPairX25519, Error> {
        let secret = Secret::from_unsafe_slice(slice)?;
        let public = curve25519::curve25519_base(slice);
        let public = PublicX25519::new(&public)?; 

        Ok( 
            KeyPairX25519{ secret, public }
            )

    }

    pub fn gen_keypair()-> Result<KeyPairX25519,Error>{
        
        let secret = Random.generate().unwrap().secret().clone();
        let kp = Self::from_secret_slice(secret.as_ref());

        kp
    }

    pub fn new() -> Result<KeyPairX25519, Error>{
            Self::gen_keypair()
    }

    pub fn secret(&self) -> &Secret{
        &self.secret
    }

    pub fn public(&self) -> &PublicX25519{
        &self.public
    }
    

}

#[cfg(test)]
mod test{


    use super::*;

    
    // test array from D.J Bernstein
    const DJB_SK: [u8;32] =
        [  
             0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
            ,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
            ,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
            ,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
        ];



    #[test]
    fn test_keypair_new(){

        let kp = KeyPairX25519::new().unwrap();

        let public = curve25519::curve25519_base(kp.secret());

        assert_eq!(public, **(kp.public()) );
    }

    #[test]
    fn test_from_secret_slice(){

        
        let kp = KeyPairX25519::from_secret_slice(&DJB_SK).unwrap();
         let expected:[u8;32]=          
                    [
                        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
                        ,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
                        ,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
                        ,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a 
                    ];

        assert_eq!(kp.public(),&expected);
    }

}    
