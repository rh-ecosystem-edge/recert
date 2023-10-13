use crate::cluster_crypto::{
    locations::{FileLocation, LocationValueType, YamlLocation},
    pem_utils,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub(crate) fn globvec(location: &Path, globstr: &str) -> Result<Vec<PathBuf>> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    Ok(glob::glob_with(
        location
            .join(globstr)
            .to_str()
            .with_context(|| format!("non-unicode path {} while globbing {:?}", globstr, location))?,
        globoptions,
    )?
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .filter(|path| !path.is_symlink())
    .filter(|path| !path.is_dir())
    .collect::<Vec<_>>())
}

pub(crate) async fn read_file_to_string(file_path: PathBuf) -> Result<String> {
    let mut file = tokio::fs::File::open(file_path.clone()).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await.context("failed to read file")?;
    Ok(contents)
}

pub(crate) async fn get_filesystem_yaml(file_location: &FileLocation) -> Result<Value> {
    serde_yaml::from_str(read_file_to_string(file_location.path.clone().into()).await?.as_str()).context("failed to parse yaml")
}

pub(crate) enum RecreateYamlEncoding {
    Json,
    Yaml,
}

pub(crate) fn recreate_yaml_at_location_with_new_pem(
    mut resource: Value,
    yaml_location: &YamlLocation,
    new_pem: &pem::Pem,
    encoding: RecreateYamlEncoding,
) -> Result<String> {
    let value_at_json_pointer = resource.pointer_mut(&yaml_location.json_pointer).context("value disappeared")?;

    match &yaml_location.value {
        LocationValueType::Pem(pem_location_info) => {
            let newbundle = pem_utils::pem_bundle_replace_pem_at_index(
                decode_resource_data_entry(yaml_location, value_at_json_pointer.as_str().context("value no longer string")?)?,
                pem_location_info.pem_bundle_index,
                new_pem,
            )?;
            let encoded = encode_resource_data_entry(yaml_location, &newbundle);

            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                *value_at_json_pointer = encoded;
            } else {
                bail!("value not string");
            }
        }
        _ => bail!("called with non-pem location"),
    }

    match encoding {
        RecreateYamlEncoding::Json => serde_json::to_string(&resource).context("serializing json"),
        RecreateYamlEncoding::Yaml => serde_yaml::to_string(&resource).context("serializing yaml"),
    }
}

fn dataurl_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len() * 2);

    for char in s.chars() {
        if {
            // https://datatracker.ietf.org/doc/html/rfc2396#section-2.3
            matches!(char, 'a'..='z'
                | 'A'..='Z'
                | '0'..='9'
                | '-'
                | '_'
                | '.'
                | '!'
                | '~'
                | '*'
                | '\''
                | '('
                | ')')
        } {
            escaped.push(char);
        } else {
            escaped.push_str(&format!("%{:02X}", char as u32));
        }
    }

    escaped
}

// This is not fully compliant with the dataurl spec, but it's good enough for our purposes
pub(crate) fn dataurl_encode(data: &str) -> String {
    format!("data:,{}", dataurl_escape(data))
}

pub(crate) fn encode_resource_data_entry(k8slocation: &YamlLocation, value: &String) -> String {
    match k8slocation.encoding {
        crate::cluster_crypto::locations::FieldEncoding::None => value.to_string(),
        crate::cluster_crypto::locations::FieldEncoding::Base64 => base64_standard.encode(value.as_bytes()),
        crate::cluster_crypto::locations::FieldEncoding::DataUrl => dataurl_encode(value),
    }
}

pub(crate) fn decode_resource_data_entry(yaml_location: &YamlLocation, value_at_json_pointer: &str) -> Result<String> {
    Ok(match yaml_location.encoding {
        crate::cluster_crypto::locations::FieldEncoding::None => value_at_json_pointer.to_string(),
        crate::cluster_crypto::locations::FieldEncoding::Base64 => {
            String::from_utf8(base64_standard.decode(value_at_json_pointer.as_bytes())?)?
        }
        crate::cluster_crypto::locations::FieldEncoding::DataUrl => {
            let (decoded, _fragment) = data_url::DataUrl::process(value_at_json_pointer)
                .ok()
                .context("dataurl processing")?
                .decode_to_vec()
                .ok()
                .context("dataurl decoding")?;
            String::from_utf8(decoded)?
        }
    }
    .clone())
}

/// Annotates a kubernetes resources to indicate that it has been edited by recert. The
/// annotation has a string value that is a serialized json object with its keys being JSON
/// pointers of fields in this resource edited by recert and values being a list of PEM bundle
/// indices of cryptographic objects that were edited in that field (or "N/A" if the field was not
/// PEM-encoded).
///
/// For example:
///
/// metadata:
///   annotations:
///     ...
///     recert-edited: '{"/spec/config/storage/files/15/contents/source":["1","2","6","5","3","0","4"],"/spec/config/storage/files/21/contents/source":["0"]}'
///     ...
///
/// This annotation is purely informational and is not used programmatically by recert itself. It's
/// used to help troubleshooters notice this is not a "natural" cryptographic object, but instead
/// one that was manipulated by recert.
pub(crate) fn add_recert_edited_annotation(resource: &mut Value, yaml_location: &YamlLocation) -> Result<()> {
    if resource.pointer_mut("/metadata/annotations").is_none() {
        resource
            .pointer_mut("/metadata")
            .context("metadata must exist")?
            .as_object_mut()
            .context("metadata must be an object")?
            .insert(String::from("annotations"), Value::Object(serde_json::Map::new()));
    }

    let current_value_string = match resource.pointer_mut("/metadata/annotations/recert-edited") {
        Some(annotation_data) => annotation_data.as_str().context("recert annotation data must be a string")?,
        None => "{}",
    };

    let mut annotation_value: Value = serde_json::from_str(current_value_string).context("parsing recert annotation json")?;

    let edited_index = Value::String(match &yaml_location.value {
        LocationValueType::Pem(pem_info) => pem_info.pem_bundle_index.to_string(),
        _ => "N/A".to_string(),
    });

    match annotation_value.get_mut(&yaml_location.json_pointer) {
        Some(locations) => {
            locations.as_array_mut().context("locations must be an array")?.push(edited_index);
        }
        None => {
            annotation_value
                .as_object_mut()
                .context("annotation value must be an object")?
                .insert(yaml_location.json_pointer.clone(), Value::Array(vec![edited_index]));
        }
    }

    resource
        .pointer_mut("/metadata/annotations")
        .context("annotations must exist")?
        .as_object_mut()
        .context("annotations must be an object")?
        .insert(
            String::from("recert-edited"),
            Value::String(serde_json::to_string(&annotation_value).context("serializing recert annotation")?),
        );

    Ok(())
}
