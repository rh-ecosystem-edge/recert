extern crate prost_build;

use std::io::Result;

fn main() -> Result<()> {
    if cfg!(feature = "generate") {
        generate_protobuf_code()?
    }
    Ok(())
}

fn generate_protobuf_code() -> Result<()> {
    let mut prost_build = prost_build::Config::new();

    prost_build.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    prost_build.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");

    prost_build.out_dir("src/protobuf_gen");

    prost_build.include_file("protobufs.rs");

    prost_build.compile_protos(
        &[
            "k8s.io/api/batch/v1/generated.proto",
            "k8s.io/api/core/v1/generated.proto",
            "k8s.io/api/admissionregistration/v1/generated.proto",
            "k8s.io/api/apps/v1/generated.proto",
            "route/v1/generated.proto",
            "oauth/v1/generated.proto",
        ],
        &["./src/protobuf"],
    )?;

    Ok(())
}
