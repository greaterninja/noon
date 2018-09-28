use serde_json::Value;
use std::collections::HashMap;
use std::result;
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json::to_value;
use valico::json_schema;
use {Result, EIP712, ErrorKind, build_dependencies};

type FieldName = String;

#[derive(Clone)]
struct Schema {
	required: Vec<FieldName>,
	items: Option<Box<Schema>>,
	properties: HashMap<FieldName, Schema>,
	type_: String,
}

impl Serialize for Schema {
	fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
		where
			S: Serializer,
	{
		let mut schema = serializer.serialize_struct("Schema", 4)?;

		if self.required.len() > 0 {
			schema.serialize_field("required", &self.required)?;
		}

		if let Some(ref items) = self.items {
			schema.serialize_field("items", &*items)?;
		}

		if self.properties.len() > 0 {
			schema.serialize_field("properties", &self.properties)?;
		}

		schema.serialize_field("type", &self.type_)?;

		schema.end()
	}
}


fn get_json_type(field_type: &str) -> String {
	match field_type {
		"bool" => "boolean".into(),
		_ => "string".into()
	}
}

fn build_schema(data: &EIP712) -> Result<Value> {
	let dependencies = build_dependencies(&data.primary_type, &data.types)
		.ok_or_else(|| ErrorKind::NonExistentType)?
		.into_iter()
		.collect::<Vec<_>>();

	let mut schemas = dependencies
		.into_iter()
		.rfold(HashMap::new(), |mut schemas: HashMap<&str, Schema>, current_type| {
			let fields = data.types.get(current_type)
				.expect("build_dependencies returns a list of type-names that exist in types ;qed");

			let mut schema = Schema {
				type_: "object".into(),
				required: vec![],
				properties: HashMap::new(),
				items: None,
			};

			for field in fields {
				let is_array = field.type_.len() > 1 && field.type_.rfind(']') == Some(field.type_.len() - 1);

				if data.types.contains_key(&*field.type_) {
					if is_array {
						let type_schema = schemas.get(&*field.type_)
							.expect("build_dependencies returns the types in \
							the order they exist on the primary \
							type; rfold traverses the types in reverse order\
							and inserts the schema into `schemas` ;qed").clone();

						let obj_schema = Schema {
							type_: "array".into(),
							required: vec![],
							properties: HashMap::new(),
							items: Some(Box::new(type_schema)),
						};
						schema.properties.insert(field.name.clone(), obj_schema);
					} else {
						let type_schema = schemas.get(&*field.type_)
							.expect("build_dependencies returns the types in \
							the order they exist on the primary \
							type, rfold traverses the types in reverse order\
							and inserts the schema into `schemas` ;qed").clone();
						schema.properties.insert(field.name.clone(), type_schema);
					}
				} else {
					if is_array {
						let schema_mut = schema.properties.entry(field.name.clone()).or_insert(Schema {
							type_: "array".into(),
							required: vec![],
							properties: HashMap::new(),
							items: None,
						});

						schema_mut.items = Some(Box::new(Schema {
							type_: get_json_type(&field.type_),
							required: vec![],
							properties: HashMap::new(),
							items: None,
						}));
					} else {
						schema.properties.insert(field.name.clone(), Schema {
							type_: get_json_type(&field.type_),
							required: vec![],
							properties: HashMap::new(),
							items: None,
						});
					}
				}
				// add field names to the required array.
				schema.required.push(field.name.clone());
			}

			schemas.insert(current_type, schema);
			schemas
		});

	let schema = schemas.remove(&*data.primary_type)
		.expect("build_dependencies would've returned ErrorKind::NonExistentType; qed");
	return Ok(to_value(schema).expect("Serialize is implemented for Schema ;qed"));
}

pub fn validate_data(eip712: &EIP712) -> Result<()> {
	let schema = build_schema(eip712)?;
	let mut scope = json_schema::Scope::new();
	let r_schema = scope.compile_and_return(schema, true).ok().unwrap();

	let validation_state = r_schema.validate(&eip712.message);
	if !validation_state.is_valid() {
		return Err(ErrorKind::SchemaValidationError(format!("{:?}", validation_state.errors)))?
	}
	Ok(())
}
