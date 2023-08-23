use anyhow::{self, Context, Result};

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
    pub(crate) fn new(old: String, new: String) -> Self {
        Self { old, new }
    }
}

impl TryFrom<String> for CnSanReplace {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let mut split = value.split_whitespace();
        let old = split.next().context("old value")?.to_string();
        let new = split.next().context("new value")?.to_string();

        Ok(Self::new(old, new))
    }
}

/// A collection of CnSanReplace, see cn_san_replace CLI argument for more information
pub(crate) struct CnSanReplaceRules(Vec<CnSanReplace>);

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

impl TryFrom<Vec<String>> for CnSanReplaceRules {
    type Error = anyhow::Error;

    fn try_from(value: Vec<String>) -> Result<Self> {
        Ok(Self(
            value
                .into_iter()
                .map(CnSanReplace::try_from)
                .collect::<Result<Vec<_>>>()
                .context("parsing cn-san-replace")?,
        ))
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
