use crate::cluster_crypto::{
    certificate::Certificate,
    locations::{FileLocation, JsonLocation, LocationValueType},
    pem_utils,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};
use tokio::io::AsyncReadExt;

pub(crate) static DRY_RUN: AtomicBool = AtomicBool::new(false);

pub async fn commit_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
    if !DRY_RUN.load(Relaxed) {
        tokio::fs::write(path, contents).await?;
    }

    Ok(())
}

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

pub(crate) async fn read_file_to_string(file_path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await.context("failed to read file")?;
    Ok(contents)
}

pub(crate) async fn get_filesystem_yaml(file_location: &FileLocation) -> Result<Value> {
    serde_yaml::from_str(read_file_to_string(&PathBuf::from(&file_location.path)).await?.as_str()).context("failed to parse yaml")
}

pub(crate) enum RecreateYamlEncoding {
    Json,
    Yaml,
}

pub(crate) fn recreate_yaml_at_location_with_new_pem(
    mut resource: Value,
    yaml_location: &JsonLocation,
    new_pem: &pem::Pem,
    encoding: RecreateYamlEncoding,
) -> Result<String> {
    let value_at_json_pointer = resource.pointer_mut(&yaml_location.json_pointer).context("value disappeared")?;

    match &yaml_location.value {
        LocationValueType::Pem(pem_location_info) => {
            let newbundle = pem_utils::pem_bundle_replace_pem_at_index(
                &decode_resource_data_entry(yaml_location, value_at_json_pointer)?,
                pem_location_info.pem_bundle_index,
                new_pem,
            )?;
            let encoded = encode_resource_data_entry(yaml_location, &newbundle);

            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                *value_at_json_pointer = encoded.as_str().context("encoded value not string")?.to_string();
            } else if let Value::Array(value_at_json_pointer) = value_at_json_pointer {
                *value_at_json_pointer = encoded.as_array().context("encoded value not array")?.clone();
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

pub(crate) fn encode_resource_data_entry(k8slocation: &JsonLocation, value: &String) -> Value {
    match k8slocation.encoding {
        crate::cluster_crypto::locations::FieldEncoding::None => Value::String(value.clone()),
        crate::cluster_crypto::locations::FieldEncoding::Base64 => Value::String(base64_standard.encode(value.as_bytes())),
        crate::cluster_crypto::locations::FieldEncoding::DataUrl => Value::String(dataurl_encode(value)),
        crate::cluster_crypto::locations::FieldEncoding::ByteArray => Value::Array(
            value
                .as_bytes()
                .iter()
                .map(|byte| Value::Number(serde_json::Number::from(*byte)))
                .collect(),
        ),
    }
}

pub(crate) fn decode_resource_data_entry(yaml_location: &JsonLocation, value_at_json_pointer: &Value) -> Result<String> {
    Ok(match yaml_location.encoding {
        crate::cluster_crypto::locations::FieldEncoding::None => {
            value_at_json_pointer.as_str().context("value no longer string")?.to_string()
        }
        crate::cluster_crypto::locations::FieldEncoding::Base64 => {
            String::from_utf8(base64_standard.decode(value_at_json_pointer.as_str().context("value no longer string")?.as_bytes())?)?
        }
        crate::cluster_crypto::locations::FieldEncoding::DataUrl => {
            let (decoded, _fragment) = data_url::DataUrl::process(value_at_json_pointer.as_str().context("value no longer string")?)
                .ok()
                .context("dataurl processing")?
                .decode_to_vec()
                .ok()
                .context("dataurl decoding")?;
            String::from_utf8(decoded)?
        }
        crate::cluster_crypto::locations::FieldEncoding::ByteArray => value_at_json_pointer
            .as_array()
            .context("value no longer array")?
            .iter()
            .map(|byte| -> Result<_> { Ok(byte.as_u64().context("byte not u64")? as u8) })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|byte| byte as char)
            .collect::<String>(),
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
#[allow(unreachable_code)]
pub(crate) fn add_recert_edited_annotation(_resource: &mut Value, _yaml_location: &JsonLocation) -> Result<()> {
    // TODO: These annotations could be a cause for rollouts, so for now avoid them as avoiding
    // rollout is more important than having those annotations
    return Ok(());

    if _resource.pointer_mut("/metadata/annotations").is_none() {
        _resource
            .pointer_mut("/metadata")
            .context("metadata must exist")?
            .as_object_mut()
            .context("metadata must be an object")?
            .insert(String::from("annotations"), Value::Object(serde_json::Map::new()));
    }

    let current_value_string = match _resource.pointer_mut("/metadata/annotations/recert-edited") {
        Some(annotation_data) => annotation_data.as_str().context("recert annotation data must be a string")?,
        None => "{}",
    };

    let mut annotation_value: Value = serde_json::from_str(current_value_string).context("parsing recert annotation json")?;

    let edited_index = Value::String(match &_yaml_location.value {
        LocationValueType::Pem(pem_info) => pem_info.pem_bundle_index.to_string(),
        _ => "N/A".to_string(),
    });

    match annotation_value.get_mut(&_yaml_location.json_pointer) {
        Some(locations) => {
            locations.as_array_mut().context("locations must be an array")?.push(edited_index);
        }
        None => {
            annotation_value
                .as_object_mut()
                .context("annotation value must be an object")?
                .insert(_yaml_location.json_pointer.clone(), Value::Array(vec![edited_index]));
        }
    }

    _resource
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

fn time_rfc3339(asn1time: &x509_certificate::asn1time::Time) -> String {
    match asn1time {
        x509_certificate::asn1time::Time::UtcTime(time) => time.to_rfc3339_opts(SecondsFormat::Secs, true),
        x509_certificate::asn1time::Time::GeneralTime(time) => {
            DateTime::<Utc>::from((*time).clone()).to_rfc3339_opts(SecondsFormat::Secs, true)
        }
    }
}

/// Updates the auth.openshift.io/certificate-not-{after,before} annotations to match the
/// validity period of the regenerated certificate. When such annotations are missing, it skips
/// them. Those annotations are used by cluster operators based on library-go to rotate those crypto
/// objects via the certrotation component.
///
/// Reference:
/// - https://github.com/openshift/library-go/blob/master/pkg/operator/certrotation/signer.go#L85
pub(crate) fn update_auth_certificate_annotations(resource: &mut Value, certificate: &Certificate) -> Result<()> {
    let cert: &x509_certificate::X509Certificate = &certificate.cert;
    let certificate: &x509_certificate::rfc5280::Certificate = cert.as_ref();

    if let Some(not_before) = resource.pointer_mut("/metadata/annotations/auth.openshift.io~1certificate-not-before") {
        *not_before = Value::String(time_rfc3339(&certificate.tbs_certificate.validity.not_before));
    }
    if let Some(not_after) = resource.pointer_mut("/metadata/annotations/auth.openshift.io~1certificate-not-after") {
        *not_after = Value::String(time_rfc3339(&certificate.tbs_certificate.validity.not_after));
    }

    Ok(())
}
