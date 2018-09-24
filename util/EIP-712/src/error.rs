use std::fmt::{self, Display};
use failure::{Fail, Context, Backtrace};

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Clone, Fail, Debug)]
pub enum ErrorKind {
	#[fail(display = "Expected type {} for field {}", _0, _1)]
	SerdeError(String, String),
	#[fail(display = "The given primaryType wasn't found in the types field")]
	NonExistentType,
	#[fail(display = "Address string should be a 0x-prefixed 40 character string, got {}", _0)]
	InvalidAddressLength(usize),
	#[fail(display = "Failed to parse hex {}", _0)]
	HexParseError(String),
	#[fail(display = "The field {} has an unknown type {}", _0, _1)]
	UnknownType(String, String)
}

pub fn serde_error(expected: &str, field: &str) -> ErrorKind {
	ErrorKind::SerdeError(expected.to_owned(), field.to_owned())
}


impl Fail for Error {
	fn cause(&self) -> Option<&Fail> {
		self.inner.cause()
	}

	fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		Display::fmt(&self.inner, f)
	}
}

impl Error {
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error { inner: Context::new(kind) }
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner }
	}
}
