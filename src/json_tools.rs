use serde_json::Value;

pub(crate) fn read_string_field(value: &Value, field: &str) -> Option<String> {
    let get = value.as_object().unwrap().get(field);
    match get {
        Some(v) => Some(v.as_str().unwrap().to_string()),
        None => None,
    }
}

pub(crate) fn read_metadata_string_field(value: &Value, field: &str) -> Option<String> {
    read_string_field(value.as_object().unwrap().get("metadata").unwrap(), field)
}
