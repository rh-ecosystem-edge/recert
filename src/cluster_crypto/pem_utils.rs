use anyhow::Result;

pub(crate) fn pem_bundle_replace_pem_at_index(original_pem_bundle: String, pem_index: u64, newpem: &pem::Pem) -> Result<String> {
    let pems = pem::parse_many(original_pem_bundle.clone())?;
    let mut newpems = vec![];
    for (i, pem) in pems.iter().enumerate() {
        if i == usize::try_from(pem_index)? {
            newpems.push(newpem.clone());
        } else {
            newpems.push(pem.clone());
        }
    }

    Ok(newpems
        .iter()
        .map(|value| pem::encode_config(value, pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF)))
        .collect::<Vec<String>>()
        .join(""))
}
