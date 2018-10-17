

extern crate crypto;


pub mod crypto_box;
pub mod crypto_secretbox;
pub mod utils;
pub mod keypair;
pub mod traits;

mod public_x25519;
mod secret;
mod error;




pub use self::public_x25519::Public;
pub use self::keypair::KeyPair;
pub use self::secret::Secret;
pub use self::error::Error;
pub use self::utils::gen_nonce;

static VERSION: &str = "x25519-xsalsa20-poly1305";

const PUBLIC25519_BYTES: usize = 32usize;
const XSALSA20_NONCE_BYTES: usize = 24usize;
const POLY1305_MAC_BYTES: usize = 16usize;


