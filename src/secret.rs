use traits::KeyContext;

pub const PRIVATE_KEY_BYTES:usize = 32usize;

type Secret = [u8;PRIVATE_KEY_BYTES];

impl KeyContext for Secret{
    fn keylength() -> usize{
        PRIVATE_KEY_BYTES
    }


    fn valid(&self)->bool{
        self.len() == PRIVATE_KEY_BYTES
    }
}
