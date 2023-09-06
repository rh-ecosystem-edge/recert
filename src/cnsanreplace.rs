use anyhow::{ensure, Result};

#[derive(Clone)]
pub(crate) struct CnSanReplace {
    pub(crate) old: String,
    pub(crate) new: String,
}

impl std::fmt::Display for CnSanReplace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Replacing all CN/SAN instances of {} with {}", self.old, self.new)
    }
}

impl CnSanReplace {
    pub(crate) fn cli_parse(value: &str) -> Result<Self> {
        // TODO: ' ' is legacy, remove eventually
        let split = if value.contains(':') { value.split(':') } else { value.split(' ') }.collect::<Vec<_>>();

        ensure!(
            split.len() == 2,
            "expected exactly one ':' in CN/SAN replace argument, found {}",
            split.len()
        );

        let old_domain = split[0].to_string();
        let new_domain = split[1].to_string();

        Ok(Self {
            old: old_domain,
            new: new_domain,
        })
    }
}

/// A collection of CnSanReplace, see cn_san_replace CLI argument for more information
pub(crate) struct CnSanReplaceRules(pub Vec<CnSanReplace>);

impl CnSanReplaceRules {
    pub(crate) fn replace(&self, input: &str) -> String {
        let mut output = input.to_string();

        for rule in &self.0 {
            if rule.old == input {
                output = rule.new.clone();
            }
        }

        output
    }
}

impl std::fmt::Display for CnSanReplaceRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for rule in &self.0 {
            writeln!(f, "{}", rule)?;
        }

        Ok(())
    }
}
