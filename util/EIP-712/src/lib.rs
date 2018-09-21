extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate ethabi;
extern crate ethereum_types;
extern crate hex;
extern crate keccak_hash;
extern crate quickersort;

use ethabi::{encode, Token};
use ethereum_types::{Address, U256};
use keccak_hash::{keccak, H256};
use serde_json::{Value};
use std::collections::HashSet;
use std::str::FromStr;

#[derive(Serialize, Clone)]
pub struct TypedData {
	types: Value,
	primary_type: String,
	message: Value,
	domain: Value,
}

fn build_dependencies(message_type: String, typed_data: Value) -> Option<HashSet<String>> {
	if let Some(x) = typed_data.get(message_type.clone()) {
		let mut deps = HashSet::new();
		deps.insert(message_type);

		if !x.is_array() {
			return None;
		}

		for data_type in x.as_array().unwrap() {
			let type_key = data_type["type"].as_str().unwrap();
			if deps.contains(type_key) {
				continue;
			}
			if let Some(set) = build_dependencies(type_key.into(), typed_data.clone()) {
				set.into_iter().for_each(|dep| {
					deps.insert(dep);
				})
			}
		}
		return Some(deps);
	}
	return None;
}

fn encode_type(message_type: String, typed_data: Value) -> String {
	let deps: Vec<String> = {
		let mut temp = build_dependencies(message_type.clone(), typed_data.clone()).unwrap();
		temp.remove(&message_type);
		let mut temp = temp.into_iter().collect::<Vec<_>>();
		quickersort::sort(&mut temp[..]);
		temp.insert(0, message_type);
		temp
	};
	deps.into_iter().fold(String::new(), |mut acc, dep| {
		let types = typed_data[dep.clone()]
			.as_array()
			.unwrap()
			.into_iter()
			.map(|value| {
				format!(
					"{} {}",
					value["type"].as_str().unwrap(),
					value["name"].as_str().unwrap()
				)
			}).collect::<Vec<_>>();

		acc.push_str(&format!("{}({})", dep, types.join(",")));
		return acc;
	})
}

fn type_hash(message_type: String, typed_data: Value) -> H256 {
	keccak(encode_type(message_type, typed_data))
}

fn encode_data(message_type: String, types: Value, message: Value) -> Vec<u8> {
	let type_hash = type_hash(message_type.clone(), types.clone()).0.to_vec();
	let mut tokens = vec![Token::FixedBytes(type_hash)];

	let message_types = if types[message_type.clone()].is_array() {
		types[message_type].as_array().unwrap().clone()
	} else {
		vec![types[message_type].clone()]
	};

	for field in message_types {
		let value = message[field["name"].as_str().unwrap()].clone();
		let field_type = field["type"].as_str().unwrap();
		match field_type {
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
					.map(|v| encode_data(array_type.into(), types.clone(), v.clone()))
					.fold(vec![], |mut acc, mut curr| {
						acc.append(&mut curr);
						acc
					});
				tokens.push(Token::FixedBytes(encoded));
			}
			t if types[t].is_array() => {
				let data = (&keccak(encode_data(field_type.into(), types.clone(), value))).to_vec();
				tokens.push(Token::FixedBytes(data));
			}
			_ => {}
		}
	}
	return encode(&tokens);
}

fn struct_hash(struct_type: String, types: Value, message: Value) -> Vec<u8> {
	keccak(encode_data(struct_type, types, message)).0.to_vec()
}

pub fn hash_data(typed_data: TypedData) -> Vec<u8> {
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

// types: Vec<MessageType>
// primaryType: String // primaryType should exist in types.some(e => e.name === primaryType)
// message: Value //
// MessageType {
// 	fields: Vec<FieldType>
// 	name: String,
// }

// FieldType {
// 	name: String,
// 	type: String
// }


#[cfg(test)]
mod tests {
	use super::*;

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

		let value = from_str::<Value>(string).unwrap();
		let hashset = {
			let mut temp = HashSet::new();
			temp.insert("Mail".to_owned());
			temp.insert("Person".to_owned());
			temp
		};
		assert_eq!(build_dependencies("Mail".into(), value), Some(hashset));
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

		let value = from_str::<Value>(string).unwrap();
		assert_eq!(
			"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
			encode_type("Mail".into(), value)
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

		let value = from_str::<Value>(string).unwrap();
		let hash = hex::encode(type_hash("Mail".into(), value).0);
		assert_eq!(
			hash,
			"a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
		);
	}

	#[test]
	fn test_encode_data() {
		let typed_data = TypedData {
			primary_type: "Mail".into(),
			domain: json!({
				"name": "Ether Mail",
				"version": "1",
				"chainId": 1,
				"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
			}),
			message: json!({
				"from": {
					"name": "Cow",
					"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
				},
				"to": {
					"name": "Bob",
					"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
				},
				"contents": "Hello, Bob!"
			}),
			types: json!({
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
			}),
		};

		let encoded = encode_data("Mail".into(), typed_data.types, typed_data.message);
		assert_eq!(hex::encode(encoded),
			"a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8")
	}
}
