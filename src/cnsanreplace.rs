use std::{net::IpAddr, str::FromStr};

use anyhow::{ensure, Result};
use der::asn1::OctetString;

#[derive(Clone, serde::Serialize)]
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
        // Also allow comma separation to support IPv6
        let split = if value.contains(',') { value.split(',') } else { value.split(':') }.collect::<Vec<_>>();

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
#[derive(serde::Serialize)]
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

    pub(crate) fn replace_ip(&self, input: &OctetString) -> OctetString {
        for rule in &self.0 {
            if let Ok(ip) = IpAddr::from_str(&rule.old) {
                let octets = if let Ok(octets) = OctetString::new(match ip {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                }) {
                    octets
                } else {
                    continue;
                };

                if octets == *input {
                    let new_ip = match IpAddr::from_str(&rule.new) {
                        Ok(ip_addr) => ip_addr,
                        // Rules from IP to non-IP are not allowed
                        Err(_) => continue,
                    };

                    let output = OctetString::new(match new_ip {
                        IpAddr::V4(ip) => ip.octets().to_vec(),
                        IpAddr::V6(ip) => ip.octets().to_vec(),
                    });

                    match output {
                        Ok(output) => return output,
                        Err(_) => continue,
                    }
                }
            }
        }

        input.clone()
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
