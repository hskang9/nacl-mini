
// Adapted from https://github.com/paritytech/parity-ethereum/blob/master/ethkey/src/error.rs
use std::{fmt, error};



#[derive(Debug)]
pub enum Error {
	InvalidSecretKey,
	InvalidPublicKey,
	InvalidBufferLength,
	Io(::std::io::Error),
	Custom(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let msg = match *self {
			Error::InvalidSecretKey => "Invalid secret key".into(),
			Error::InvalidPublicKey => "Invalid public key".into(),
			Error::InvalidBufferLength => "Invalid buffer length".into(),
			Error::Io(ref err) => format!("I/O error: {}", err),
			Error::Custom(ref s) => s.clone(),
		};

		f.write_fmt(format_args!("Crypto error ({})", msg))
	}
}

impl error::Error for Error {
	fn description(&self) -> &str {
		"Crypto error"
	}
}

impl Into<String> for Error {
	fn into(self) -> String {
		format!("{}", self)
	}
}

impl From<::std::io::Error> for Error {
	fn from(err: ::std::io::Error) -> Error {
		Error::Io(err)
	}
}

#[cfg(feature = "std")]
impl From<::rustc_hex::FromHexError> for Error {
    fn description(&self) -> &str {
        match *self {
            InvalidHexCharacter(_, _) => "invalid character",
            InvalidHexLength => "invalid length",
        }
    }
}

#[cfg(feature = "std")]
impl From<::hex::FromHexError> for Error {
    fn description(&self) -> &str {
        match *self {
            InvalidHexCharacter(_, _) => "invalid character",
            InvalidHexLength => "invalid length",
        }
    }
}