pub(crate) fn pem_bundle_replace_pem_at_index(original_pem_bundle: String, pem_index: u64, newpem: &pem::Pem) -> String {
    let pems = pem::parse_many(original_pem_bundle.clone()).unwrap();
    let mut newpems = vec![];
    for (i, pem) in pems.iter().enumerate() {
        if i == usize::try_from(pem_index).unwrap() {
            newpems.push(newpem.clone());
        } else {
            newpems.push(pem.clone());
        }
    }
    let newbundle = pem::encode_many_config(
        &newpems,
        pem::EncodeConfig {
            line_ending: pem::LineEnding::LF,
        },
    );
    newbundle
}
