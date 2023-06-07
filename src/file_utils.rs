use crate::cluster_crypto::{
    locations::{FileLocation, LocationValueType, YamlLocation},
    pem_utils,
};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub(crate) fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .filter(|x| !x.is_symlink())
        .collect::<Vec<_>>()
}

pub(crate) async fn read_file_to_string(file_path: PathBuf) -> String {
    let mut file = tokio::fs::File::open(file_path.clone())
        .await
        .expect(format!("failed to open file {:?}", file_path).as_str());
    let mut contents = String::new();
    file.read_to_string(&mut contents).await.expect("failed to read file");
    contents
}

pub(crate) async fn get_filesystem_yaml(file_location: &FileLocation) -> Value {
    serde_yaml::from_str(read_file_to_string(file_location.path.clone().into()).await.as_str()).expect("failed to parse yaml")
}

pub(crate) fn recreate_yaml_at_location_with_new_pem(mut resource: Value, yaml_location: &YamlLocation, new_pem: &pem::Pem) -> String {
    match resource.pointer_mut(&yaml_location.json_pointer) {
        Some(value_at_json_pointer) => {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                let decoded = decode_resource_data_entry(yaml_location, value_at_json_pointer);

                match &yaml_location.value {
                    LocationValueType::Pem(pem_location_info) => {
                        let newbundle = pem_utils::pem_bundle_replace_pem_at_index(decoded, pem_location_info.pem_bundle_index, &new_pem);
                        let encoded = encode_resource_data_entry(&yaml_location, &newbundle);
                        *value_at_json_pointer = encoded;
                    }
                    _ => {
                        panic!("shouldn't happen");
                    }
                }
            }
        }
        None => {
            panic!("shouldn't happen {} {:#?}", resource.to_string(), yaml_location);
        }
    }
    let newcontents = serde_json::to_string(&resource).unwrap();
    newcontents
}

pub(crate) fn encode_resource_data_entry(k8slocation: &YamlLocation, value: &String) -> String {
    match k8slocation.encoding {
        crate::cluster_crypto::locations::FieldEncoding::None => value.to_string(),
        crate::cluster_crypto::locations::FieldEncoding::Base64 => base64_standard.encode(value.as_bytes()),
        crate::cluster_crypto::locations::FieldEncoding::DataUrl => {
            let mut url = dataurl::DataUrl::new();
            url.set_data(value.as_bytes());
            url.to_string()
        }
    }
}

pub(crate) fn decode_resource_data_entry(yaml_location: &YamlLocation, value_at_json_pointer: &mut String) -> String {
    let decoded = match yaml_location.encoding {
        crate::cluster_crypto::locations::FieldEncoding::None => value_at_json_pointer.to_string(),
        crate::cluster_crypto::locations::FieldEncoding::Base64 => {
            String::from_utf8_lossy(base64_standard.decode(value_at_json_pointer.as_bytes()).unwrap().as_slice()).to_string()
        }
        crate::cluster_crypto::locations::FieldEncoding::DataUrl => {
            if let Ok(url) = data_url::DataUrl::process(value_at_json_pointer) {
                let (decoded, _fragment) = url.decode_to_vec().unwrap();
                if let Ok(decoded) = String::from_utf8(decoded) {
                    decoded
                } else {
                    panic!("Failed to decode data-url");
                }
            } else {
                panic!("Failed to decode data-url");
            }
        }
    }
    .clone();
    decoded
}
