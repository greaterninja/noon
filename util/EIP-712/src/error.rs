// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use std::fmt::{self, Display};
use failure::{Fail, Context, Backtrace};

pub(crate) type Result<T> = ::std::result::Result<T, Error>;
/// Error type
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}
/// Possible errors encountered while hashing/encoding an EIP-712 compliant data structure
#[derive(Clone, Fail, Debug)]
pub enum ErrorKind {
	/// if we fail to deserialize from a serde::Value as a type specified in message types
	/// fail with this error.
	#[fail(display = "Expected type '{}' for field '{}'", _0, _1)]
	UnexpectedType(String, String),
	/// the primary type supplied doesn't exist in the MessageTypes
	#[fail(display = "The given primaryType wasn't found in the types field")]
	NonExistentType,
	/// an invalid address was encountered during encoding
	#[fail(display = "Address string should be a 0x-prefixed 40 character string, got '{}'", _0)]
	InvalidAddressLength(usize),
	/// a hex parse error occured
	#[fail(display = "Failed to parse hex '{}'", _0)]
	HexParseError(String),
	/// the field was declared with a unknown type
	#[fail(display = "The field '{}' has an unknown type '{}'", _0, _1)]
	UnknownType(String, String),
	/// the array type had an
	#[fail(display = "The field '{}' has a closing ']' but not an opening '['", _0)]
	ArrayParseError(String),
	/// schema validation error
	#[fail(display = "{}", _0)]
	SchemaValidationError(String)
}

pub(crate) fn serde_error(expected: &str, field: &str) -> ErrorKind {
	ErrorKind::UnexpectedType(expected.to_owned(), field.to_owned())
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
	/// extract the error kind
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
