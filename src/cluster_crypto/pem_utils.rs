use anyhow::{ensure, Result};

pub fn pem_bundle_line_ending(pem_bundle: &str) -> Result<pem::LineEnding> {
    enum State {
        Start,
        CR,
        LF,
    }

    let mut state = State::Start;

    let mut crlf_count = 0;
    let mut lf_count = 0;

    for c in pem_bundle.chars() {
        match state {
            State::Start => match c {
                '\r' => state = State::CR,
                '\n' => state = State::LF,
                _ => (),
            },
            State::CR => match c {
                '\r' => state = State::CR,
                '\n' => {
                    state = State::Start;
                    crlf_count += 1;
                }
                _ => (),
            },
            State::LF => match c {
                '\r' => {
                    state = State::CR;
                    crlf_count += 1;
                }
                '\n' => {
                    state = State::LF;
                    lf_count += 1;
                }
                _ => state = State::Start,
            },
        }
    }

    ensure!(
        crlf_count == 0 || lf_count == 0,
        format!("pem bundle has mixed line endings, crlf_count {} lf_count {}", crlf_count, lf_count)
    );

    if crlf_count > 0 {
        Ok(pem::LineEnding::CRLF)
    } else {
        Ok(pem::LineEnding::LF)
    }
}

pub(crate) fn pem_bundle_replace_pem_at_index(original_pem_bundle: String, pem_index: u64, newpem: &pem::Pem) -> Result<String> {
    let original_line_endings = pem_bundle_line_ending(original_pem_bundle.as_str())?;

    let original_pem = {
        let pems = pem::parse_many(original_pem_bundle.clone())?;
        ensure!(
            usize::try_from(pem_index)? < pems.len(),
            format!("pem_index {} out of range {}", pem_index, pems.len())
        );
        pem::encode_config(
            &pems[usize::try_from(pem_index)?],
            pem::EncodeConfig::new().set_line_ending(original_line_endings),
        )
    };

    let found_indices = original_pem_bundle.as_str().match_indices(&original_pem).collect::<Vec<_>>();

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
    let new_bundle = original_pem_bundle.replace(
        &original_pem,
        &pem::encode_config(newpem, pem::EncodeConfig::new().set_line_ending(original_line_endings)).to_string(),
    );

    ensure!(new_bundle != original_pem_bundle, format!("replacement did not change pem bundle"));

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
