use serde_json::Value;

pub(crate) fn read_string_field(value: &Value, field: &str) -> Option<String> {
    let get = value.as_object()?.get(field);
    match get {
        Some(v) => Some(v.as_str()?.to_string()),
        None => None,
    }
}

pub(crate) fn read_metadata_string_field(value: &Value, field: &str) -> Option<String> {
    read_string_field(value.as_object()?.get("metadata")?, field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_read_string_field() {
        let value = json!({"kind": "Secret", "count": 1});
        assert_eq!(read_string_field(&value, "kind").as_deref(), Some("Secret"));
        assert!(read_string_field(&value, "missing").is_none());
        assert!(read_string_field(&value, "count").is_none());
        assert!(read_string_field(&json!("not-an-object"), "kind").is_none());
    }

    #[test]
    fn test_read_metadata_string_field() {
        let value = json!({"metadata": {"name": "foo", "namespace": "bar"}});
        assert_eq!(read_metadata_string_field(&value, "name").as_deref(), Some("foo"));
        assert!(read_metadata_string_field(&value, "missing").is_none());
        assert!(read_metadata_string_field(&json!({}), "name").is_none());
        assert_eq!(
            read_metadata_string_field(&json!({"metadata": {"namespace": ""}}), "namespace").as_deref(),
            Some("")
        );
    }
}
