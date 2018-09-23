extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate ethabi;
extern crate ethereum_types;
extern crate hex;
extern crate keccak_hash;
extern crate quickersort;

mod eip712;

pub use eip712::*;
use ethabi::{encode, Token};
use ethereum_types::{Address, U256};
use keccak_hash::{keccak, H256};
use serde_json::{Value};
use std::collections::{HashSet};
use std::str::FromStr;

fn build_dependencies<'a>(message_type: &'a String, message_types: &'a MessageTypes) -> Option<(HashSet<&'a String>)>
{
	if let Some(fields) = message_types.get(message_type) {
		let mut deps = HashSet::new();
		deps.insert(message_type);

		for field in fields {
			if deps.contains(&field.type_) {
				continue;
			}
			if let Some(set) = build_dependencies(&field.type_, &message_types) {
				deps.extend(set);
			}
		}
		return Some(deps);
	}
	return None;
}

fn encode_type(message_type: &String, message_types: &MessageTypes) -> String {
	let deps = {
		let mut temp = build_dependencies(message_type, message_types).unwrap();
		temp.remove(&message_type);
		let mut temp = temp.into_iter().collect::<Vec<_>>();
		quickersort::sort(&mut temp[..]);
		temp.insert(0, &message_type);
		temp
	};
	deps.into_iter().fold(String::new(), |mut acc, dep| {
		// this unwrap is safe because we're searching for a dependency that was recently pulled out of message_types
		let types = message_types.get(dep).unwrap().iter()
			.map(|value| {
				format!(
					"{} {}",
					value.type_,
					value.name
				)
			}).collect::<Vec<_>>();

		acc.push_str(&format!("{}({})", dep, types.join(",")));
		return acc;
	})
}

fn type_hash(message_type: &String, typed_data: &MessageTypes) -> H256 {
	keccak(encode_type(message_type, typed_data))
}

fn encode_data(message_type: String, message_types: MessageTypes, message: Value) -> Vec<u8> {
	let type_hash = type_hash(&message_type, &message_types).0.to_vec();
	let mut tokens = vec![Token::FixedBytes(type_hash)];

	for field in message_types.get(&message_type).unwrap() {
		let value = message[&field.name].clone();
		match &*field.type_ {
			"string" | "bytes32" => {
				let value = value.as_str().unwrap();
				let hash = (&keccak(value)).to_vec();
				tokens.push(Token::FixedBytes(hash));
			}
			"bool" => tokens.push(Token::Bool(value.as_bool().unwrap())),
			"uint256" => {
				let string: String = value.as_str().map(ToOwned::to_owned).unwrap();
				let uint = U256::from_str(&string).unwrap();
				tokens.push(Token::Uint(uint));
			}
			"address" => {
				let address = Address::from_str(value.as_str().unwrap().get(2..).unwrap()).unwrap();
				tokens.push(Token::Address(address));
			}
			ty if ty.rfind(']') == Some(ty.len() - 1) => {
				// Array type
				let array_type = ty.split('[').collect::<Vec<_>>()[0];
				let encoded = value
					.as_array()
					.unwrap()
					.into_iter()
					.map(|v| encode_data(array_type.into(), message_types.clone(), v.clone()))
					.fold(vec![], |mut acc, mut curr| {
						acc.append(&mut curr);
						acc
					});
				tokens.push(Token::FixedBytes(encoded));
			}
			t if message_types.get(t).is_some() => {
				let data = (&keccak(encode_data(field.type_.clone(), message_types.clone(), value))).to_vec();
				tokens.push(Token::FixedBytes(data));
			}
			_ => {}
		}
	}
	return encode(&tokens);
}

pub fn hash_data(typed_data: EIP712) -> Vec<u8> {
	// json schema validation logic!

	let mut preamble = (b"\x19\x01").to_vec();
	let (mut domain_hash , mut data_hash) = (
		encode_data("EIP712Domain".into(), typed_data.types.clone(), typed_data.domain),
		encode_data(typed_data.primary_type, typed_data.types, typed_data.message)
	);
	let mut concat = Vec::new();
	concat.append(&mut preamble);
	concat.append(&mut domain_hash);
	concat.append(&mut data_hash);

	keccak(concat).0.to_vec()
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::from_str;

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

		let value = from_str::<MessageTypes>(string).unwrap();
		let mail = &String::from("Mail");
		let person = &String::from("Person");

		let hashset = {
			let mut temp = HashSet::new();
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

		let value = from_str::<MessageTypes>(string).unwrap();
		let mail = &String::from("Mail");
		assert_eq!(
			"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
			encode_type(mail, &value)
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

		let value = from_str::<MessageTypes>(string).unwrap();
		let mail = &String::from("Mail");
		let hash = hex::encode(type_hash(mail, &value).0);
		assert_eq!(
			hash,
			"a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
		);
	}

	#[test]
	fn test_encode_data() {
		let string = r#"{
            "primaryType": "Mail",
			"domain": {
				"name": "Ether Mail",
				"version": "1",
				"chainId": 1,
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
		let typed_data = from_str::<EIP712>(string).unwrap();

		let encoded = encode_data("Mail".into(), typed_data.types, typed_data.message);
		assert_eq!(hex::encode(encoded), "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8")
	}
}
