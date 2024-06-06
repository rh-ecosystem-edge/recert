use anyhow::{Context, Result};
use std::collections::BTreeMap;

// https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/common/arguments/arguments.go#L71-L100
pub(crate) fn encode_with_delimeter(args: serde_json::Map<String, serde_json::Value>, delimeter: &str) -> Result<String> {
    if args.is_empty() {
        return Ok(String::from(""));
    }

    let sorted_args: BTreeMap<_, _> = args.iter().collect();
    Ok(sorted_args
        .iter()
        .map(|(key, values)| match values.as_array() {
            Some(v) => Ok(v
                .iter()
                .map(|value| {
                    Ok(format!(
                        "--{}={}",
                        shell_escape(key.as_str()).context(format!("could not shell escape key: {}", key))?,
                        shell_escape(&trim_quotes(&value.to_string())).context(format!("could not shell escape value: {}", value))?
                    ))
                })
                .collect::<Result<Vec<_>>>()?
                .join(delimeter)),
            None => Ok(format!(
                "--{}={}",
                shell_escape(key.as_str()).context(format!("could not shell escape key: {}", key))?,
                shell_escape(&trim_quotes(&values.to_string())).context(format!("could not shell escape value: {}", values))?
            )),
        })
        .collect::<Result<Vec<_>>>()?
        .join(delimeter))
}

// https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/common/arguments/arguments.go#L49-L62
fn shell_escape(s: &str) -> Result<String> {
    let re = regex::Regex::new(r"[^\w@%+=:,./-]").context("invalid regex")?;

    Ok(if re.is_match(s) {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    } else {
        String::from(s)
    })
}

fn trim_quotes(s: &str) -> String {
    match s.strip_prefix('"') {
        Some(without_prefix) => match without_prefix.strip_suffix('"') {
            Some(without_prefix_nor_suffix) => without_prefix_nor_suffix,
            None => s,
        },
        None => s,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encode_with_delimeter() -> Result<()> {
        let args = r#"
        {
            "cors-allowed-origins": ["//127\\.0\\.0\\.1(:|$)","//localhost(:|$)"],
            "etcd-servers": ["https://192.168.126.10:2379"],
            "tls-cipher-suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
            "tls-min-version": "VersionTLS12"
        }"#;

        let expected = r#"--cors-allowed-origins='//127\\.0\\.0\\.1(:|$)'  \\\n --cors-allowed-origins='//localhost(:|$)'  \\\n --etcd-servers=https://192.168.126.10:2379  \\\n --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  \\\n --tls-min-version=VersionTLS12"#;

        assert!(encode_with_delimeter(serde_json::from_str(args)?, r"  \\\n ").is_ok_and(|x| x == *expected));

        Ok(())
    }
}
