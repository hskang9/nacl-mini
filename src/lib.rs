

extern crate crypto;


pub mod crypto_box;
pub mod crypto_secretbox;
pub mod utils;
mod public_x25519;
mod secret;
mod keypair;
mod error;
mod traits;




pub use self::public_x25519::PublicX25519;
pub use self::keypair::KeyPair;
pub use self::secret::Secret;
pub use self::error::Error;

static VERSION: &str = "x25519-xsalsa20-poly1305";

const PUBLIC25519_BYTES: usize = 32usize;
const PRIVATE_KEY_BYTES: usize = 32usize;
const XSALSA20_NONCE_BYTES: usize = 24usize;
const POLY1305_MAC_BYTES: usze = 16usize;


