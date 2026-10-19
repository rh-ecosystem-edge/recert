use crate::cluster_crypto::certificate::{attribute_value_string, time_from_chrono, time_to_chrono, COMMON_NAME};
use crate::cnsanreplace::CnSanReplaceRules;
use anyhow::bail;
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use der::{
    asn1::{Ia5String, OctetString, PrintableStringRef, SetOfVec},
    oid::AssociatedOid,
    Any, Decode, Encode, Tag, Tagged,
};
use x509_cert::ext::pkix::name::GeneralName::{self, DnsName, IpAddress};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectAltName};
use x509_cert::{name::Name, TbsCertificate};

pub(crate) fn mutate_cert(
    tbs_certificate: &mut TbsCertificate,
    cn_san_replace_rules: &CnSanReplaceRules,
    extend_expiration: bool,
    force_expire: bool,
) -> Result<()> {
    mutate_cert_cn_san(tbs_certificate, cn_san_replace_rules).context("mutating CN/SAN")?;
    mutate_expiration(tbs_certificate, extend_expiration, force_expire).context("extending expiration")?;
    Ok(())
}

fn mutate_expiration(tbs_certificate: &mut TbsCertificate, extend_expiration: bool, force_expire: bool) -> Result<()> {
    match (extend_expiration, force_expire) {
        (true, true) => bail!("cannot both extend expiration and force expire"),
        (true, false) => extend_certificate_expiration(tbs_certificate).context("extending expiration")?,
        (false, true) => certficate_force_expire(tbs_certificate).context("forcefully expiring")?,
        (false, false) => (),
    };
    Ok(())
}

fn certficate_force_expire(tbs_certificate: &mut TbsCertificate) -> Result<()> {
    let (current_not_before, current_not_after) = get_certificate_expiration(tbs_certificate).context("evaluating current expiration")?;

    // Set not_after to now (by decreasing the not_after by the difference between now and
    // not_after), this essentially expires the certificate as now is immediately in the past.

    // We also rewind not_before by the same amount, so that we can still infer the original
    // duration of the certificate (it's still the difference between not after and not before) -
    // this is useful for the certificate expiration extension done by
    // extend_certificate_expiration in future invocations of recert
    let rewind_duration = current_not_after - chrono::Utc::now();

    set_certificate_expiration(
        tbs_certificate,
        current_not_before - rewind_duration,
        current_not_after - rewind_duration,
    )
}

fn extend_certificate_expiration(tbs_certificate: &mut TbsCertificate) -> Result<()> {
    let (current_not_before, current_not_after) = get_certificate_expiration(tbs_certificate).context("evaluating current expiration")?;

    let now = chrono::Utc::now();

    let certificate_duration = current_not_after - current_not_before;

    set_certificate_expiration(tbs_certificate, now, now + certificate_duration)
}

fn get_certificate_expiration(tbs_certificate: &TbsCertificate) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    Ok((
        time_to_chrono(&tbs_certificate.validity.not_before).context("not before")?,
        time_to_chrono(&tbs_certificate.validity.not_after).context("not after")?,
    ))
}

fn set_certificate_expiration(tbs_certificate: &mut TbsCertificate, not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Result<()> {
    tbs_certificate.validity.not_before = time_from_chrono(not_before).context("not before")?;
    tbs_certificate.validity.not_after = time_from_chrono(not_after).context("not after")?;
    Ok(())
}

pub(crate) fn mutate_cert_cn_san(tbs_certificate: &mut TbsCertificate, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
    mutate_cert_common_name(&mut tbs_certificate.subject, cn_san_replace_rules).context("mutating subject Common Name")?;
    mutate_cert_common_name(&mut tbs_certificate.issuer, cn_san_replace_rules).context("mutating issuer Common Name")?;
    mutate_cert_subject_alternative_name(tbs_certificate, cn_san_replace_rules).context("mutating Subject Alternative Name")?;
    Ok(())
}

pub(crate) fn mutate_cert_common_name(name: &mut Name, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
    for rdn in name.0.iter_mut() {
        if !rdn.0.iter().any(|attribute| attribute.oid == COMMON_NAME) {
            continue;
        }

        let mut attributes = rdn.0.clone().into_vec();

        for attribute in attributes.iter_mut().filter(|attribute| attribute.oid == COMMON_NAME) {
            let common_name = attribute_value_string(&attribute.value).context("decoding common name")?;
            let new_common_name = cn_san_replace_rules.replace(&common_name);

            if new_common_name == common_name {
                continue;
            }

            // Keep the original string type
            attribute.value = match attribute.value.tag() {
                Tag::PrintableString => Any::encode_from(
                    &PrintableStringRef::new(&new_common_name)
                        .with_context(|| format!("{new_common_name} is not a valid PrintableString"))?,
                )?,
                Tag::Utf8String => Any::encode_from(&new_common_name)?,
                tag => bail!("unsupported common name type {tag}"),
            };
        }

        // A SET OF has to be sorted, which the new value might affect when there are multiple
        // attributes
        rdn.0 = SetOfVec::try_from(attributes).context("re-creating relative distinguished name")?;
    }

    Ok(())
}

/// An AKID can identify the issuer by the issuer's own issuer name and serial number
/// (authorityCertIssuer + authorityCertSerialNumber) rather than (or in addition to) a key
/// identifier. If CN replacement renames that issuer's issuer, the name in the AKID goes stale and
/// the chain breaks. Go never writes this form (so OCP certs don't have it), so rather than
/// supporting it we refuse to produce a broken cert.
pub(crate) fn ensure_akid_issuer_unaffected(akid: &AuthorityKeyIdentifier, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
    for general_name in akid.authority_cert_issuer.iter().flatten() {
        if let GeneralName::DirectoryName(name) = general_name {
            let mut renamed = name.clone();
            mutate_cert_common_name(&mut renamed, cn_san_replace_rules).context("mutating AKID authority cert issuer")?;
            ensure!(
                renamed == *name,
                "CN replacement would rename the issuer named in this cert's authority key identifier, which is not supported"
            );
        }
    }

    Ok(())
}

pub(crate) fn mutate_cert_subject_alternative_name(
    tbs_certificate: &mut TbsCertificate,
    cn_san_replace_rules: &CnSanReplaceRules,
) -> Result<()> {
    for extension in tbs_certificate.extensions.iter_mut().flatten() {
        if extension.extn_id != SubjectAltName::OID {
            continue;
        }

        let san_extension = SubjectAltName::from_der(extension.extn_value.as_bytes()).context("decoding SAN extension")?;
        let new_san_extension = SubjectAltName(
            san_extension
                .0
                .iter()
                .map(|san| {
                    Ok(match san {
                        DnsName(name) => DnsName(Ia5String::new(&cn_san_replace_rules.replace(name.as_ref()))?),
                        IpAddress(ip) => IpAddress(cn_san_replace_rules.replace_ip(ip)),
                        san_name => san_name.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        );

        if new_san_extension != san_extension {
            extension.extn_value = OctetString::new(new_san_extension.to_der().context("encoding SAN extension")?)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_crypto::certificate::{name_attribute_values, name_string};
    use crate::cnsanreplace::CnSanReplace;
    use std::str::FromStr;
    use x509_cert::time::Time;

    fn rules(rules: &[&str]) -> CnSanReplaceRules {
        CnSanReplaceRules(rules.iter().map(|rule| CnSanReplace::parse(rule).unwrap()).collect())
    }

    #[test]
    fn test_mutate_common_name_keeps_string_type() {
        let mut name = Name::from_str("CN=old.example.com,O=Old Org").unwrap();
        let rules = rules(&["old.example.com:new.example.com"]);

        mutate_cert_common_name(&mut name, &rules).unwrap();

        assert_eq!(name_string(&name), "CN=new.example.com, O=Old Org");
        let cn = &name
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|a| a.oid == COMMON_NAME)
            .unwrap()
            .value;
        // Name::from_str encodes everything as UTF8String
        assert_eq!(cn.tag(), Tag::Utf8String);

        let mut name = Name::from_der(&hex::decode("3016311430120603550403130b6f6c642e6578616d706c65").unwrap()).unwrap();
        let rules = self::rules(&["old.example:new.example"]);
        mutate_cert_common_name(&mut name, &rules).unwrap();
        assert_eq!(name_attribute_values(&name, COMMON_NAME).unwrap(), vec!["new.example"]);
        let cn = &name
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|a| a.oid == COMMON_NAME)
            .unwrap()
            .value;
        assert_eq!(cn.tag(), Tag::PrintableString);

        // "*" can't be a PrintableString
        let rules = self::rules(&["new.example:*.example"]);
        assert!(mutate_cert_common_name(&mut name, &rules).is_err());
    }

    #[test]
    fn test_mutate_common_name_untouched() {
        // A BMPString CN, which we can't write, is fine as long as it doesn't need replacing
        let mut name = Name::from_der(&hex::decode("300f310d300b06035504031e0400680069").unwrap()).unwrap();
        let original = name.clone();
        mutate_cert_common_name(&mut name, &rules(&["something:else"])).unwrap();
        assert_eq!(name, original);
        assert!(mutate_cert_common_name(&mut name, &rules(&["hi:bye"])).is_err());
    }

    #[test]
    fn test_ensure_akid_issuer_unaffected() {
        let akid = |issuer: &str| AuthorityKeyIdentifier {
            key_identifier: None,
            authority_cert_issuer: Some(vec![GeneralName::DirectoryName(Name::from_str(issuer).unwrap())]),
            authority_cert_serial_number: None,
        };
        let rules = rules(&["old.example.com:new.example.com"]);

        assert!(ensure_akid_issuer_unaffected(&akid("CN=unrelated"), &rules).is_ok());
        assert!(ensure_akid_issuer_unaffected(&akid("CN=old.example.com,O=Org"), &rules).is_err());
        // Key identifier only, the usual form
        let key_id_only = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(vec![1, 2, 3]).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        assert!(ensure_akid_issuer_unaffected(&key_id_only, &rules).is_ok());
    }

    #[test]
    fn test_mutate_expiration() {
        let parse = |s: &str| -> DateTime<Utc> { DateTime::parse_from_rfc3339(s).unwrap().into() };
        let pem = pem::parse(include_str!("testdata/rsa_rfc5280.pem")).unwrap();
        let mut tbs = x509_cert::Certificate::from_der(pem.contents()).unwrap().tbs_certificate;

        set_certificate_expiration(&mut tbs, parse("2020-01-01T00:00:00Z"), parse("2020-01-11T00:00:00Z")).unwrap();
        extend_certificate_expiration(&mut tbs).unwrap();
        let (not_before, not_after) = get_certificate_expiration(&tbs).unwrap();
        assert_eq!(not_after - not_before, chrono::Duration::days(10));
        assert!((Utc::now() - not_before).num_seconds().abs() < 60);
        assert!(matches!(tbs.validity.not_after, Time::UtcTime(_)));

        certficate_force_expire(&mut tbs).unwrap();
        let (not_before, not_after) = get_certificate_expiration(&tbs).unwrap();
        assert_eq!(not_after - not_before, chrono::Duration::days(10));
        assert!((Utc::now() - not_after).num_seconds().abs() < 60);

        // Long-lived certs end up with GeneralizedTime after 2049
        set_certificate_expiration(&mut tbs, parse("2020-01-01T00:00:00Z"), parse("2120-01-01T00:00:00Z")).unwrap();
        extend_certificate_expiration(&mut tbs).unwrap();
        assert!(matches!(tbs.validity.not_before, Time::UtcTime(_)));
        assert!(matches!(tbs.validity.not_after, Time::GeneralTime(_)));
        let (not_before, not_after) = get_certificate_expiration(&tbs).unwrap();
        assert_eq!(
            not_after - not_before,
            parse("2120-01-01T00:00:00Z") - parse("2020-01-01T00:00:00Z")
        );
    }
}
