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
    pub(crate) fn parse(value: &str) -> Result<Self> {
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
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn replace(&self, input: &str) -> String {
        let mut output = input.to_string();

        for rule in &self.0 {
            if rule.old == input {
                output.clone_from(&rule.new);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rules(pairs: &[&str]) -> CnSanReplaceRules {
        CnSanReplaceRules(pairs.iter().map(|p| CnSanReplace::parse(p).unwrap()).collect())
    }

    #[test]
    fn test_parse_hostname_colon() {
        let parsed = CnSanReplace::parse("old.example.com:new.example.com").unwrap();
        assert_eq!(parsed.old, "old.example.com");
        assert_eq!(parsed.new, "new.example.com");
    }

    #[test]
    fn test_parse_ipv6_comma() {
        let parsed = CnSanReplace::parse("2001:db8::1,2001:db8::50").unwrap();
        assert_eq!(parsed.old, "2001:db8::1");
        assert_eq!(parsed.new, "2001:db8::50");
    }

    #[test]
    fn test_parse_rejects_too_many_parts() {
        let err = CnSanReplace::parse("a:b:c").err().unwrap();
        assert!(err.to_string().contains("expected exactly one ':'"));
    }

    #[test]
    fn test_parse_rejects_missing_separator() {
        assert!(CnSanReplace::parse("onlyone").is_err());
    }

    #[test]
    fn test_replace_exact_match_only() {
        let rules = rules(&["old.com:new.com"]);

        assert_eq!(rules.replace("old.com"), "new.com");
        assert_eq!(rules.replace("api.old.com"), "api.old.com");
        assert_eq!(rules.replace("old.com.extra"), "old.com.extra");
    }

    #[test]
    fn test_replace_last_matching_rule_wins() {
        let rules = rules(&["old.com:first.com", "old.com:second.com"]);

        assert_eq!(rules.replace("old.com"), "second.com");
    }

    #[test]
    fn test_replace_ip_v4() {
        let rules = rules(&["192.0.2.1:192.0.2.50"]);
        let input = OctetString::new(Ipv4Addr::new(192, 0, 2, 1).octets().to_vec()).unwrap();
        let expected = OctetString::new(Ipv4Addr::new(192, 0, 2, 50).octets().to_vec()).unwrap();

        assert_eq!(rules.replace_ip(&input), expected);
    }

    #[test]
    fn test_replace_ip_v6() {
        let rules = rules(&["2001:db8::1,2001:db8::50"]);
        let input = OctetString::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets().to_vec()).unwrap();
        let expected = OctetString::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50).octets().to_vec()).unwrap();

        assert_eq!(rules.replace_ip(&input), expected);
    }

    #[test]
    fn test_replace_ip_skips_ip_to_hostname() {
        let rules = rules(&["192.0.2.1:example.com"]);
        let input = OctetString::new(Ipv4Addr::new(192, 0, 2, 1).octets().to_vec()).unwrap();

        assert_eq!(rules.replace_ip(&input), input);
    }

    #[test]
    fn test_replace_ip_unmatched_unchanged() {
        let rules = rules(&["192.0.2.1:192.0.2.50"]);
        let input = OctetString::new(Ipv4Addr::new(192, 0, 2, 9).octets().to_vec()).unwrap();

        assert_eq!(rules.replace_ip(&input), input);
    }

    #[test]
    fn test_is_empty() {
        assert!(CnSanReplaceRules(vec![]).is_empty());
        assert!(!rules(&["a:b"]).is_empty());
    }
}
