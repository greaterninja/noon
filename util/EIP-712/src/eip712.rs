use serde_json::{Value};
use serde::de::{self, Deserialize, Deserializer, Visitor, MapAccess};
use std::fmt;
use std::collections::HashMap;

pub type MessageTypes = HashMap<String, Vec<FieldType>>;

#[derive(Debug, Clone)]
pub struct EIP712 {
	pub types: MessageTypes,
	pub primary_type: String,
	pub message: Value,
	pub domain: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FieldType {
	pub name: String,
	#[serde(rename = "type")]
	pub type_: String
}

impl<'de> Deserialize<'de> for EIP712 {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
	{
		struct EIP712Visitor;

		impl<'de> Visitor<'de> for EIP712Visitor {
			type Value = EIP712;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("struct EIP712")
			}

			fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
				where
					V: MapAccess<'de>,
			{
				let mut types = None;
				let mut primary_type = None;
				let mut domain = None;
				let mut message = None;
				while let Some(key) = map.next_key()? {
					match key {
						"types" => {
							if types.is_some() {
								return Err(de::Error::duplicate_field("types"));
							}
							types = Some(map.next_value()?);
						}
						"domain" => {
							if domain.is_some() {
								return Err(de::Error::duplicate_field("domain"));
							}
							domain = Some(map.next_value()?);
						},
						"message" => {
							if message.is_some() {
								return Err(de::Error::duplicate_field("message"));
							}
							message = Some(map.next_value()?);
						},
						"primaryType" => {
							if primary_type.is_some() {
								return Err(de::Error::duplicate_field("primary_type"));
							}
							primary_type = Some(map.next_value()?);
						},
						// invalid keys don't count
						_ => {}
					}
				}

				let types = types.ok_or_else(|| de::Error::missing_field("types"))?;
				let primary_type = primary_type.ok_or_else(|| de::Error::missing_field("primary_type"))?;
				let domain = domain.ok_or_else(|| de::Error::missing_field("domain"))?;
				let message = message.ok_or_else(|| de::Error::missing_field("message"))?;

				Ok(EIP712 { types, primary_type, message, domain })
			}
		}

		const FIELDS: &'static [&'static str] = &["types", "primary_type", "message", "domain"];
		deserializer.deserialize_struct("EIP712", FIELDS, EIP712Visitor)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::from_str;
	#[test]
	fn test_deserialization() {
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
		let _ = from_str::<EIP712>(string).unwrap();
	}
}
