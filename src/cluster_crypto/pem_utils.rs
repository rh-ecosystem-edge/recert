use anyhow::{ensure, Result};

pub fn pem_bundle_line_ending(pem_bundle: &str) -> Result<pem::LineEnding> {
    let bytes = pem_bundle.as_bytes();
    let (mut crlf_count, mut lf_count, mut cr_count) = (0usize, 0, 0);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                crlf_count += 1;
                i += 2;
            } else {
                cr_count += 1;
                i += 1;
            }
        } else if bytes[i] == b'\n' {
            lf_count += 1;
            i += 1;
        } else {
            i += 1;
        }
    }

    ensure!(
        (crlf_count == 0 || lf_count == 0) && cr_count == 0,
        "pem bundle has mixed line endings, crlf_count {} lf_count {} cr_count {}",
        crlf_count,
        lf_count,
        cr_count
    );

    if crlf_count > 0 {
        Ok(pem::LineEnding::CRLF)
    } else {
        Ok(pem::LineEnding::LF)
    }
}

pub(crate) fn pem_bundle_replace_pem_at_index(original_pem_bundle: &str, pem_index: u64, new_pem: &pem::Pem) -> Result<String> {
    let original_line_endings = pem_bundle_line_ending(original_pem_bundle)?;

    let original_pem = {
        let pems = pem::parse_many(original_pem_bundle)?;
        ensure!(
            usize::try_from(pem_index)? < pems.len(),
            format!("pem_index {} out of range {}", pem_index, pems.len())
        );
        pem::encode_config(
            &pems[usize::try_from(pem_index)?],
            pem::EncodeConfig::new().set_line_ending(original_line_endings),
        )
    };

    let original_pem = original_pem.trim_end();

    let found_indices = original_pem_bundle.match_indices(&original_pem).collect::<Vec<_>>();

    ensure!(
        !found_indices.is_empty(),
        format!("pem {} not found in pem bundle {}", original_pem, original_pem_bundle)
    );

    ensure!(
        found_indices.len() == 1,
        format!(
            "pem_index {} not unique in pem bundle, found in indices {:?}",
            pem_index, found_indices
        )
    );

    let new_pem = &pem::encode_config(new_pem, pem::EncodeConfig::new().set_line_ending(original_line_endings)).to_string();
    let new_pem = new_pem.trim_end();

    let new_bundle = original_pem_bundle.replace(original_pem, new_pem);

    // TODO: This causes a crash on AWS
    // ensure!(new_bundle != original_pem_bundle, format!("replacement did not change pem bundle"));

    let line_ending_raw = match original_line_endings {
        pem::LineEnding::LF => "\n",
        pem::LineEnding::CRLF => "\r\n",
    };

    ensure!(
        (new_bundle.ends_with(line_ending_raw) && original_pem_bundle.ends_with(line_ending_raw))
            || (!new_bundle.ends_with(line_ending_raw) && !original_pem_bundle.ends_with(line_ending_raw)),
        "line ending mismatch between original and new pem bundle"
    );

    let new_line_endings = pem_bundle_line_ending(new_bundle.as_str())?;

    let line_endings_match = matches!(
        (original_line_endings, new_line_endings),
        (pem::LineEnding::LF, pem::LineEnding::LF) | (pem::LineEnding::CRLF, pem::LineEnding::CRLF)
    );

    ensure!(
        line_endings_match,
        format!(
            "line endings changed from {:?} to {:?} when replacing pem",
            original_line_endings, new_line_endings,
        )
    );

    Ok(new_bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_pem(contents: &[u8]) -> pem::Pem {
        pem::Pem::new("CERTIFICATE", contents)
    }

    fn two_cert_bundle() -> (String, pem::Pem, pem::Pem) {
        let first = cert_pem(b"AAAA");
        let second = cert_pem(b"BBBB");
        let bundle = format!("{}{}", pem::encode(&first), pem::encode(&second));
        (bundle, first, second)
    }

    #[test]
    fn test_line_ending_lf() {
        let bundle = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        assert!(matches!(pem_bundle_line_ending(bundle).unwrap(), pem::LineEnding::LF));
    }

    #[test]
    fn test_line_ending_crlf() {
        let bundle = "-----BEGIN CERTIFICATE-----\r\nMIIB\r\n-----END CERTIFICATE-----\r\n";
        assert!(matches!(pem_bundle_line_ending(bundle).unwrap(), pem::LineEnding::CRLF));
    }

    #[test]
    fn test_line_ending_no_newlines_defaults_to_lf() {
        assert!(matches!(pem_bundle_line_ending("no-newlines").unwrap(), pem::LineEnding::LF));
    }

    #[test]
    fn test_line_ending_mixed_errors() {
        let bundle = "line\n\nmixed\r\n";
        let err = pem_bundle_line_ending(bundle).unwrap_err();
        assert!(err.to_string().contains("mixed line endings"));
    }

    #[test]
    fn test_line_ending_mixed_single_lf_and_crlf() {
        let bundle = "line\nmixed\r\n";
        let err = pem_bundle_line_ending(bundle).unwrap_err();
        assert!(err.to_string().contains("mixed line endings"));
    }

    #[test]
    fn test_line_ending_bare_cr_errors() {
        let err = pem_bundle_line_ending("line\rother\r").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mixed line endings"));
        assert!(msg.contains("cr_count 2"));
        assert!(msg.contains("lf_count 0"));
        assert!(msg.contains("crlf_count 0"));
    }

    #[test]
    fn test_line_ending_mixed_cr_and_lf_errors() {
        let err = pem_bundle_line_ending("line\nmixed\r").unwrap_err();
        assert!(err.to_string().contains("mixed line endings"));
    }

    #[test]
    fn test_line_ending_mixed_cr_and_crlf_errors() {
        let err = pem_bundle_line_ending("line\rmixed\r\n").unwrap_err();
        assert!(err.to_string().contains("mixed line endings"));
    }

    #[test]
    fn test_replace_pem_at_index() {
        let (bundle, first, _second) = two_cert_bundle();
        let replacement = cert_pem(b"CCCC");

        let replaced = pem_bundle_replace_pem_at_index(&bundle, 1, &replacement).unwrap();
        let parsed = pem::parse_many(&replaced).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].contents(), first.contents());
        assert_eq!(parsed[1].contents(), replacement.contents());
    }

    #[test]
    fn test_replace_pem_index_out_of_range() {
        let (bundle, _, _) = two_cert_bundle();
        let replacement = cert_pem(b"CCCC");
        let err = pem_bundle_replace_pem_at_index(&bundle, 5, &replacement).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn test_replace_pem_duplicate_block_errors() {
        let pem = cert_pem(b"AAAA");
        let encoded = pem::encode(&pem);
        let bundle = format!("{}{}", encoded, encoded);
        let err = pem_bundle_replace_pem_at_index(&bundle, 0, &cert_pem(b"CCCC")).unwrap_err();
        assert!(err.to_string().contains("not unique"));
    }
}
