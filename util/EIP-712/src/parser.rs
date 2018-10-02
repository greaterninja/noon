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

//! Solidity type-name parsing
//!
use lunarity::lexer::Lexer;
use lunarity::lexer::Token;
use error::*;
use toolshed::Arena;

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
	Address,
	Uint,
	Int,
	String,
	Bool,
	Bytes(u8),
	Custom(String),
	Array(Box<Type>)
}

impl From<Type> for String {
	fn from(field_type: Type) -> String {
		match field_type {
			Type::Address => "address".into(),
			Type::Uint => "uint".into(),
			Type::Int => "int".into(),
			Type::String => "string".into(),
			Type::Bool => "bool".into(),
			Type::Bytes(len) => format!("bytes{}", len),
			Type::Custom(custom) => custom,
			Type::Array(type_) => (*type_).into()
		}
	}
}

pub struct Parser {
	arena: Arena,
}

impl Parser {
	pub fn new() -> Self {
		Parser {
			arena: Arena::new()
		}
	}

	pub fn parse_type(&self, field_type: &str) -> Result<Type> {
		#[derive(PartialEq)]
		enum State { Open, Close }

		let mut lexer = Lexer::new(&self.arena, field_type);
		let mut token = None;
		let mut state = State::Close;
		let mut array_depth = 0;

		loop {
			if lexer.token == Token::EndOfProgram {
				break
			}

			let type_ = match lexer.token {
				Token::Identifier => Type::Custom(lexer.token_as_str().to_owned()),
				Token::TypeByte => Type::Bytes(lexer.type_size.0),
				Token::TypeBool => Type::Bool,
				Token::TypeUint => Type::Uint,
				Token::TypeInt => Type::Int,
				Token::TypeString => Type::String,
				Token::TypeAddress => Type::Address,
				Token::LiteralInteger => {
					lexer.consume();
					continue;
				},
				Token::BracketOpen => {
					state = State::Open;
					lexer.consume();
					continue
				}
				Token::BracketClose if array_depth < 10 => {
					if state == State::Open && token.is_some() {
						state = State::Close;
						token = Some(Type::Array(Box::new(token.expect("line 78 checks for `Some`"))));
						lexer.consume();
						array_depth += 1;
						continue
					} else {
						return Err(ErrorKind::UnexpectedToken(lexer.token_as_str().to_owned(), field_type.to_owned()))?
					}
				}
				Token::BracketClose if array_depth == 10 => {
					return Err(ErrorKind::UnsupportedArrayDepth)?
				}
				_  => return Err(ErrorKind::UnexpectedToken(lexer.token_as_str().to_owned(), field_type.to_owned()))?
			};

			token = Some(type_);
			lexer.consume();
		}

		Ok(token.ok_or_else(|| ErrorKind::NonExistentType)?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parser() {
		let parser = Parser::new();
		let source = "byte[][][7][][][][][][][]";
		parser.parse_type(source).unwrap();
	}

	#[test]
	fn test_nested_array() {
		let parser = Parser::new();
		let source = "byte[][][7][][][][][][][][]";
		assert_eq!(parser.parse_type(source).is_err(), true);
	}
}
