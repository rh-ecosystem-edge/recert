use anyhow::{bail, Context, Result};
use ciborium::value::Value as CborValue;
use serde_json::{value::Number as JsonNumber, Value as JsonValue};

const SELF_DESCRIBING_CBOR_TAG: u64 = 55799;

fn cbor_to_json(cbor: CborValue) -> Result<JsonValue> {
    Ok(match cbor {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(boolean) => JsonValue::Bool(boolean),
        CborValue::Text(string) => JsonValue::String(string),
        CborValue::Integer(int) => JsonValue::Number({
            let int: i128 = int.into();
            if let Ok(int) = u64::try_from(int) {
                JsonNumber::from(int)
            } else if let Ok(int) = i64::try_from(int) {
                JsonNumber::from(int)
            } else {
                JsonNumber::from_f64(int as f64).context("Integer not JSON compatible")?
            }
        }),
        CborValue::Float(float) => JsonValue::Number(JsonNumber::from_f64(float).context("Float not JSON compatible")?),
        CborValue::Array(vec) => JsonValue::Array(vec.into_iter().map(cbor_to_json).collect::<Result<Vec<_>>>()?),
        CborValue::Map(map) => JsonValue::Object(serde_json::Map::from_iter(
            map.into_iter()
                .map(|(k, v)| {
                    let key_str = match k {
                        CborValue::Bytes(bytes) => String::from_utf8(bytes).context("Invalid UTF-8 in CBOR map key")?,
                        CborValue::Text(text) => text,
                        _ => bail!("Unsupported CBOR map key type {:?}", k),
                    };
                    Ok((key_str, cbor_to_json(v)?))
                })
                .collect::<Result<Vec<(String, JsonValue)>>>()?,
        )),
        // TODO: Handle proposed-encoding tags for CBOR bytes? https://github.com/kubernetes/kubernetes/pull/125419
        // It seems that in a typical k8s cluster these are not used anywhere (secrets are
        // protobuf, and they're pretty much the only place where raw bytes are used in
        // values), so I don't have an example to test that implementation on. For now we will
        // crash on unhandled tags below to be safe.
        CborValue::Bytes(vec) => JsonValue::String(String::from_utf8(vec).context("Invalid UTF-8 in CBOR bytes")?),
        CborValue::Tag(value, _tag) => unimplemented!("Unsupported CBOR tag {:?}", value),
        _ => unimplemented!("Unsupported CBOR type {:?}", cbor),
    })
}

fn json_to_cbor(json: JsonValue) -> Result<CborValue> {
    Ok(match json {
        JsonValue::Null => CborValue::Null,
        JsonValue::Bool(boolean) => CborValue::Bool(boolean),
        JsonValue::String(string) => CborValue::Bytes(string.into_bytes()),
        JsonValue::Number(number) => {
            if let Some(int) = number.as_i64() {
                CborValue::Integer(int.into())
            } else if let Some(uint) = number.as_u64() {
                CborValue::Integer(uint.into())
            } else if let Some(float) = number.as_f64() {
                CborValue::Float(float)
            } else {
                bail!("Unsupported number type")
            }
        }
        JsonValue::Array(arr) => CborValue::Array(arr.into_iter().map(json_to_cbor).collect::<Result<Vec<_>>>()?),
        JsonValue::Object(map) => {
            // Fallback for regular JSON objects (shouldn't happen in our flow)
            let map_entries: Vec<(CborValue, CborValue)> = map
                .into_iter()
                .map(|(k, v)| Ok((CborValue::Bytes(k.into_bytes()), json_to_cbor(v)?)))
                .collect::<Result<Vec<_>>>()?;
            CborValue::Map(map_entries)
        }
    })
}

pub(crate) fn k8s_cbor_bytes_to_json(cbor_bytes: &[u8]) -> Result<JsonValue> {
    let v: CborValue = ciborium::de::from_reader(cbor_bytes)?;

    let (v, had_self_describing_tag) = match v {
        CborValue::Tag(value, contents) => match value {
            SELF_DESCRIBING_CBOR_TAG => {
                // Self-describing CBOR tag, unwrap the contents
                (*contents, true)
            }
            _ => panic!("Unsupported CBOR tag {}", value),
        },
        // We expected a self-describing CBOR tag at the root. Of course we could just proceed
        // as is (since it's just raw CBOR) but it's a bit fishy, so just bail
        _ => bail!("CBOR data that does not start with self-describing tag is not supported"),
    };

    cbor_to_json(v)
}

pub(crate) fn json_to_k8s_cbor_bytes(json: JsonValue) -> Result<Vec<u8>> {
    let cbor = json_to_cbor(json)?;

    // Put back the self-describing CBOR tag that we stripped
    let tagged_cbor = CborValue::Tag(SELF_DESCRIBING_CBOR_TAG, Box::new(cbor));

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&tagged_cbor, &mut bytes)?;

    Ok(bytes)
}
