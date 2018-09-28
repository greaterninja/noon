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

//! EIP-712 encoding utilities
#![warn(missing_docs, unused_extern_crates)]

extern crate serde;
extern crate serde_json;
extern crate ethabi;
extern crate ethereum_types;
extern crate keccak_hash;
extern crate itertools;
extern crate failure;
extern crate valico;
extern crate linked_hash_set;
extern crate regex;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
extern crate hex;

mod eip712;
mod error;
mod schema;
pub use error::*;
pub use eip712::*;
use schema::*;

use ethabi::{encode, Token};
use ethereum_types::{Address, U256, H256};
use keccak_hash::keccak;
use serde_json::Value;
use std::collections::HashSet;
use std::str::FromStr;
use itertools::Itertools;
use linked_hash_set::LinkedHashSet;
use serde_json::to_value;


lazy_static! {
    static ref INT_TYPES: HashSet<&'static str> = vec![
        "int8", "int16", "int24", "int32", "int40", "int48", "int56", "int64", "int72", "int80",
        "int88", "int96", "int104", "int112", "int120", "int128", "int136", "int144", "int152", "int160",
        "int168", "int176", "int184", "int192", "int200", "int208", "int216", "int224", "int232", "int240",
        "int248", "int256", "uint8", "uint16", "uint24", "uint32", "uint40", "uint48", "uint56",
        "uint64", "uint72", "uint80", "uint88", "uint96", "uint104", "uint112", "uint120", "uint128",
        "uint136", "uint144", "uint152", "uint160", "uint168", "uint176", "uint184", "uint192", "uint200",
        "uint208", "uint216", "uint224", "uint232", "uint240", "uint248", "uint256"
    ].into_iter().collect();

	static ref BYTES_TYPES: HashSet<&'static str> = vec![
		"bytes1", "bytes2", "bytes3", "bytes4", "bytes5", "bytes6", "bytes7", "bytes8",
		"bytes9", "bytes10", "bytes11", "bytes12", "bytes13", "bytes14", "bytes15", "bytes16", "bytes17",
		"bytes18", "bytes19", "bytes20", "bytes21", "bytes22", "bytes23", "bytes24", "bytes25", "bytes26",
		"bytes27", "bytes28", "bytes29", "bytes30", "bytes31", "bytes32"
	].into_iter().collect();

}


/// given a type and HashMap<String, Vec<FieldType>>
/// returns a HashSet of dependent types of the given type
fn build_dependencies<'a>(message_type: &'a str, message_types: &'a MessageTypes) -> Option<(LinkedHashSet<&'a str>)>
{
	if message_types.get(message_type).is_none() {
		return None;
	}

	let mut types = LinkedHashSet::new();
	types.insert(message_type);
	let mut deps = LinkedHashSet::new();

	loop {
		let item = match types.pop_back() {
			None => return Some(deps),
			Some(item) => item,
		};

		if let Some(fields) = message_types.get(item) {
			deps.insert(item);

			for field in fields {
				// seen this type before? or not a custom type skip
				if deps.contains(&*field.type_) || !message_types.contains_key(&*field.type_) {
					continue;
				}
				types.insert(&*field.type_);
			}
		}
	}
}

fn encode_type(message_type: &str, message_types: &MessageTypes) -> Result<String> {
	let deps = {
		let mut temp = build_dependencies(message_type, message_types).ok_or_else(|| ErrorKind::NonExistentType)?;
		temp.remove(message_type);
		let mut temp = temp.into_iter().collect::<Vec<_>>();
		(&mut temp[..]).sort_unstable();
		temp.insert(0, message_type);
		temp
	};

	let encoded = deps
		.into_iter()
		.filter_map(|dep| {
			message_types.get(dep).map(|field_types| {
				let types = field_types
					.iter()
					.map(|value| format!("{} {}", value.type_, value.name))
					.join(",");
				return format!("{}({})", dep, types);
			})
		})
		.collect::<Vec<_>>()
		.concat();
	Ok(encoded)
}

fn type_hash(message_type: &str, typed_data: &MessageTypes) -> Result<H256> {
	Ok(keccak(encode_type(message_type, typed_data)?))
}

fn encode_data(message_type: &str, message_types: &MessageTypes, message: &Value) -> Result<Vec<u8>> {
	let type_hash = (&type_hash(message_type, &message_types)?).to_vec();
	let mut tokens = vec![Token::FixedBytes(type_hash)];
	for field in message_types.get(message_type).ok_or_else(|| ErrorKind::NonExistentType)? {
		let value = &message[&field.name];
		match &*field.type_ {
			// Array type e.g uint256[], string[]
			ty if ty.len() > 1 && ty.rfind(']') == Some(ty.len() - 1) => {
				let array_type = ty.find('[')
					.and_then(|index| ty.get(..index))
					.ok_or_else(|| ErrorKind::ArrayParseError(field.name.clone()))?;

				let mut items = vec![];

				for item in value.as_array().ok_or_else(|| serde_error("array", &field.name))? {
					// is the array defined in the custom types?
					if let Some(_) = message_types.get(array_type) {
						let encoded = encode_data(array_type.into(), &message_types, item)?;
						items.push(encoded);
					} else {
						// it's either a primitive or invalid
						let token = encode_primitive(array_type.into(), &field.name, item)?;
						items.push(encode(&[token]));
					}
				}
				tokens.push(Token::FixedBytes(keccak(items.concat()).0.to_vec()));
			}
			// custom type defined in message types
			t if message_types.get(t).is_some() => {
				let encoded = encode_data(&field.type_, &message_types, &value)?;
				let hash = (&keccak(encoded)).to_vec();
				tokens.push(Token::FixedBytes(hash));
			}
			// ethabi primitive types
			field_type => {
				let token = encode_primitive(field_type, &field.name, value)?;
				tokens.push(token)
			}
		}
	}
	return Ok(encode(&tokens));
}

fn encode_primitive(field_type: &str, field_name: &str, value: &Value) -> Result<Token> {
	match field_type {
		"bytes" => {
			let string = value.as_str().ok_or_else(|| serde_error("string", field_name))?;
			if string.len() <= 2 {
				return Err(ErrorKind::HexParseError(
					format!("Expected a 0x-prefixed string of even length, found {} length string", string.len()))
				)?
			}
			let string = string.get(2..).expect("line 188 checks for length");
			let bytes = H256::from_str(string).map_err(|err| ErrorKind::HexParseError(format!("{}", err)))?;
			let hash = (&keccak(&bytes)).to_vec();
			return Ok(Token::FixedBytes(hash));
		}
		ty if BYTES_TYPES.contains(ty) => {
			let string = value.as_str().ok_or_else(|| serde_error("string", field_name))?;
			if string.len() <= 2 {
				return Err(ErrorKind::HexParseError(
					format!("Expected a 0x-prefixed string of even length, found {} length string", string.len()))
				)?
			}
			let string = string.get(2..).expect("line 188 checks for length");
			let bytes = H256::from_str(string).map_err(|err| ErrorKind::HexParseError(format!("{}", err)))?;
			return Ok(Token::FixedBytes(bytes.to_vec()));
		}
		"string" => {
			let value = value.as_str().ok_or_else(|| serde_error("string", field_name))?;
			let hash = (&keccak(value)).to_vec();
			return Ok(Token::FixedBytes(hash));
		}
		"bool" => return Ok(Token::Bool(value.as_bool().ok_or_else(|| serde_error("bool", field_name))?)),
		"address" => {
			let addr = value.as_str().ok_or_else(|| serde_error("string", field_name))?;
			if addr.len() != 42 {
				return Err(ErrorKind::InvalidAddressLength(addr.len()))?;
			}
			// we've checked the address length, this is safe
			let addr = addr.get(2..).unwrap();
			let address = Address::from_str(addr).map_err(|err| ErrorKind::HexParseError(format!("{}", err)))?;
			return Ok(Token::Address(address));
		}
		// (un)signed integers
		ty if INT_TYPES.contains(ty) => {
			// try to deserialize as a number first, then a string
			let uint = match (value.as_u64(), value.as_str()) {
				(Some(number), _) => U256::from(number),
				(_, Some(string)) => {
					if string.len() <= 2 {
						return Err(ErrorKind::HexParseError(
							format!("Expected a 0x-prefixed string of even length, found {} length string", string.len()))
						)?
					}
					let string = string.get(2..).expect("line 200 checks for length");
					U256::from_str(string).map_err(|err| ErrorKind::HexParseError(format!("{}", err)))?
				}
				_ => return Err(serde_error("int/uint", field_name))?
			};
			return Ok(Token::Uint(uint));
		}
		// the type couldn't be encoded
		_ => return Err(ErrorKind::UnknownType(field_name.to_owned(), field_type.to_owned()))?
	}
}

/// encodes and hashes the given EIP712 struct
pub fn hash_data(typed_data: EIP712) -> Result<Vec<u8>> {
	// json schema validation
	validate_data(&typed_data)?;
	// EIP-191 compliant
	let prefix = (b"\x19\x01").to_vec();
	let domain = to_value(&typed_data.domain).unwrap();
	let (domain_hash, data_hash) = (
		keccak(encode_data("EIP712Domain", &typed_data.types, &domain)?).0,
		keccak(encode_data(&typed_data.primary_type, &typed_data.types, &typed_data.message)?).0
	);
	let concat = [&prefix[..], &domain_hash[..], &data_hash[..]].concat();
	Ok((&keccak(concat)).to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::from_str;

	#[test]
	fn test_valico() {
		let typed_data = from_str::<EIP712>(JSON).expect("alas error!");

		validate_data(&typed_data).unwrap();
	}

	const JSON: &'static str = r#"{
		"primaryType": "Mail",
		"domain": {
			"name": "Ether Mail",
			"version": "1",
			"chainId": "0x1",
			"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
		},
		"message": {
			"from": {
				"name": "Cow",
				"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
			},
			"to": {
				"name": "Bob",
				"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
			},
			"contents": "Hello, Bob!"
		},
		"types": {
			"EIP712Domain": [
			    { "name": "name", "type": "string" },
				{ "name": "version", "type": "string" },
				{ "name": "chainId", "type": "uint256" },
				{ "name": "verifyingContract", "type": "address" }
			],
			"Person": [
				{ "name": "name", "type": "string" },
				{ "name": "wallet", "type": "address" }
			],
			"Mail": [
				{ "name": "from", "type": "Person" },
				{ "name": "to", "type": "Person" },
				{ "name": "contents", "type": "string" }
			]
		}
	}"#;

	#[test]
	fn test_build_dependencies() {
		let string = r#"{
			"EIP712Domain": [
				{ "name": "name", "type": "string" },
				{ "name": "version", "type": "string" },
				{ "name": "chainId", "type": "uint256" },
				{ "name": "verifyingContract", "type": "address" }
			],
			"Person": [
				{ "name": "name", "type": "string" },
				{ "name": "wallet", "type": "address" }
			],
			"Mail": [
				{ "name": "from", "type": "Person" },
				{ "name": "to", "type": "Person" },
				{ "name": "contents", "type": "string" }
			]
		}"#;

		let value = from_str::<MessageTypes>(string).expect("alas error!");
		let mail = "Mail";
		let person = "Person";

		let hashset = {
			let mut temp = LinkedHashSet::new();
			temp.insert(mail);
			temp.insert(person);
			temp
		};
		assert_eq!(build_dependencies(mail, &value), Some(hashset));
	}

	#[test]
	fn test_encode_type() {
		let string = r#"{
			"EIP712Domain": [
				{ "name": "name", "type": "string" },
				{ "name": "version", "type": "string" },
				{ "name": "chainId", "type": "uint256" },
				{ "name": "verifyingContract", "type": "address" }
			],
			"Person": [
				{ "name": "name", "type": "string" },
				{ "name": "wallet", "type": "address" }
			],
			"Mail": [
				{ "name": "from", "type": "Person" },
				{ "name": "to", "type": "Person" },
				{ "name": "contents", "type": "string" }
			]
		}"#;

		let value = from_str::<MessageTypes>(string).expect("alas error!");
		let mail = &String::from("Mail");
		assert_eq!(
			"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
			encode_type(&mail, &value).expect("alas error!")
		)
	}

	#[test]
	fn test_encode_type_hash() {
		let string = r#"{
			"EIP712Domain": [
				{ "name": "name", "type": "string" },
				{ "name": "version", "type": "string" },
				{ "name": "chainId", "type": "uint256" },
				{ "name": "verifyingContract", "type": "address" }
			],
			"Person": [
				{ "name": "name", "type": "string" },
				{ "name": "wallet", "type": "address" }
			],
			"Mail": [
				{ "name": "from", "type": "Person" },
				{ "name": "to", "type": "Person" },
				{ "name": "contents", "type": "string" }
			]
		}"#;

		let value = from_str::<MessageTypes>(string).expect("alas error!");
		let mail = &String::from("Mail");
		let hash = hex::encode(type_hash(&mail, &value).expect("alas error!").0);
		assert_eq!(
			hash,
			"a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
		);
	}

	#[test]
	fn test_encode_data() {
		let typed_data = from_str::<EIP712>(JSON).expect("alas error!");
		let encoded = encode_data("Mail".into(), &typed_data.types, &typed_data.message).expect("alas error!");
		assert_eq!(hex::encode(encoded), "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8")
	}

	#[test]
	fn test_hash_data() {
		let typed_data = from_str::<EIP712>(JSON).expect("alas error!");
		assert_eq!(
			hex::encode(hash_data(typed_data).expect("alas error!")),
			"be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
		)
	}
}
