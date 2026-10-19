use super::{algorithms::KeyAlgorithm, keys::PublicKey};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use der::{
    asn1::{GeneralizedTime, ObjectIdentifier, UtcTime},
    oid::AssociatedOid,
    Any, Decode, Encode, Tag, Tagged,
};
use serde::{ser::SerializeStruct, Serialize};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use x509_cert::{
    ext::pkix::{
        name::GeneralName::{DnsName, IpAddress},
        SubjectAltName,
    },
    name::Name,
    time::Time,
    TbsCertificate,
};

pub(crate) const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const STATE_OR_PROVINCE_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
const ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const ORGANIZATIONAL_UNIT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");

#[derive(Clone, Debug)]
pub(crate) struct Certificate {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) sans: Vec<String>,
    pub(crate) public_key: PublicKey,
    pub(crate) cert: x509_cert::Certificate,
    /// The certificate exactly as it was encoded, which is what its signature covers. Re-encoding
    /// `cert` normalizes non-DER constructs, so it's not guaranteed to reproduce these bytes.
    pub(crate) der: Bytes,
}

impl Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut struct_serializer = serializer.serialize_struct("Certificate", 4)?;
        struct_serializer.serialize_field("issuer", &self.issuer)?;
        struct_serializer.serialize_field("subject", &self.subject)?;

        let validity = &self.tbs().validity;
        struct_serializer.serialize_field(
            "validity_start",
            &time_asn1_string(&validity.not_before).map_err(serde::ser::Error::custom)?,
        )?;
        struct_serializer.serialize_field(
            "validity_end",
            &time_asn1_string(&validity.not_after).map_err(serde::ser::Error::custom)?,
        )?;
        struct_serializer.serialize_field("sans", &self.sans)?;

        struct_serializer.serialize_field("pem", &base64_standard.encode(self.encode_pem()))?;
        struct_serializer.end()
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer && self.subject == other.subject && self.public_key == other.public_key
    }
}

impl Eq for Certificate {}

impl Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer.hash(state);
        self.subject.hash(state);
        self.public_key.hash(state);
    }
}

impl Certificate {
    pub(crate) fn from_der(der: &[u8]) -> Result<Self> {
        let cert = x509_cert::Certificate::from_der(der).context("parsing certificate DER")?;
        let tbs = &cert.tbs_certificate;

        let public_key = match KeyAlgorithm::from_algorithm_identifier(&tbs.subject_public_key_info.algorithm)
            .context("failed to get cert key algorithm")?
        {
            KeyAlgorithm::Rsa => {
                PublicKey::from_rsa_bytes(&Bytes::from(tbs.subject_public_key_info.to_der().context("encoding public key")?))
            }
            key_algorithm => {
                let cert_pem = Bytes::from(pem::Pem::new("CERTIFICATE", der).to_string().into_bytes());
                PublicKey::from_cert_bytes(&cert_pem, &key_algorithm).context("converting public key bytes")?
            }
        };

        Ok(Certificate {
            issuer: name_string(&tbs.issuer),
            subject: name_string(&tbs.subject),
            sans: sans(tbs).context("parsing cert SAN extensions")?,
            public_key,
            der: Bytes::copy_from_slice(der),
            cert,
        })
    }

    pub(crate) fn tbs(&self) -> &TbsCertificate {
        &self.cert.tbs_certificate
    }

    pub(crate) fn encode_pem(&self) -> String {
        pem::Pem::new("CERTIFICATE", self.der.as_ref()).to_string()
    }

    pub(crate) fn subject_is_issuer(&self) -> bool {
        self.tbs().subject == self.tbs().issuer
    }
}

fn sans(tbs: &TbsCertificate) -> Result<Vec<String>> {
    let mut sans = vec![];

    for extension in tbs.extensions.iter().flatten() {
        if extension.extn_id != SubjectAltName::OID {
            continue;
        }

        for san in SubjectAltName::from_der(extension.extn_value.as_bytes())?.0 {
            match san {
                DnsName(name) => sans.push(name.to_string()),
                IpAddress(ip) => {
                    let bytes = ip.as_bytes();
                    match bytes.len() {
                        4 => sans.push(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])).to_string()),
                        16 => sans.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes)?)).to_string()),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    Ok(sans)
}

/// The string value of a name attribute (e.g. a common name)
pub(crate) fn attribute_value_string(value: &Any) -> Result<String> {
    let bytes = value.value();

    Ok(match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::NumericString | Tag::VisibleString => {
            std::str::from_utf8(bytes).context("decoding string")?.to_string()
        }
        Tag::BmpString => {
            let code_units = bytes
                .chunks(2)
                .map(|pair| <[u8; 2]>::try_from(pair).map(u16::from_be_bytes))
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("odd BMPString length")?;
            String::from_utf16(&code_units).context("decoding BMPString")?
        }
        // Treated as Latin-1, which is what it's used for in practice
        Tag::TeletexString => bytes.iter().map(|&byte| char::from(byte)).collect(),
        tag => bail!("unsupported attribute value type {tag}"),
    })
}

/// All values of the given attribute type in the name, in order
pub(crate) fn name_attribute_values(name: &Name, attribute_type: ObjectIdentifier) -> Result<Vec<String>> {
    name.0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|attribute| attribute.oid == attribute_type)
        .map(|attribute| attribute_value_string(&attribute.value))
        .collect()
}

/// A human readable representation of a name, for logs and summaries. It only includes some
/// attributes, so it shouldn't be used to compare names.
pub(crate) fn name_string(name: &Name) -> String {
    let fields = [
        ("CN", COMMON_NAME),
        ("OU", ORGANIZATIONAL_UNIT_NAME),
        ("O", ORGANIZATION_NAME),
        ("L", LOCALITY_NAME),
        ("S", STATE_OR_PROVINCE_NAME),
        ("C", COUNTRY_NAME),
    ]
    .into_iter()
    .map(|(label, attribute_type)| -> Result<Vec<String>> {
        Ok(name_attribute_values(name, attribute_type)?
            .into_iter()
            .map(|value| format!("{label}={value}"))
            .collect())
    })
    .collect::<Result<Vec<_>>>();

    match fields {
        Ok(fields) => fields.concat().join(", "),
        Err(_) => "undecodable".to_string(),
    }
}

/// The time as it appears in the certificate (e.g. 240101000000Z)
fn time_asn1_string(time: &Time) -> Result<String> {
    let value = match time {
        Time::UtcTime(time) => Any::encode_from(time)?,
        Time::GeneralTime(time) => Any::encode_from(time)?,
    };
    Ok(std::str::from_utf8(value.value())?.to_string())
}

pub(crate) fn time_to_chrono(time: &Time) -> Result<DateTime<Utc>> {
    let seconds = i64::try_from(time.to_unix_duration().as_secs())?;
    DateTime::from_timestamp(seconds, 0).context("time out of range")
}

/// Converts to the time representation RFC 5280 requires: UTCTime through 2049, GeneralizedTime
/// after. Sub-second precision is dropped.
pub(crate) fn time_from_chrono(time: DateTime<Utc>) -> Result<Time> {
    let seconds = u64::try_from(time.timestamp()).context("times before 1970 are not supported")?;
    let date_time = der::DateTime::from_unix_duration(Duration::from_secs(seconds))?;

    Ok(if date_time.year() <= UtcTime::MAX_YEAR {
        Time::UtcTime(UtcTime::from_date_time(date_time)?)
    } else {
        Time::GeneralTime(GeneralizedTime::from_date_time(date_time))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_conversions() {
        let utc = time_from_chrono(DateTime::parse_from_rfc3339("2049-12-31T23:59:59.75Z").unwrap().into()).unwrap();
        assert!(matches!(utc, Time::UtcTime(_)));
        assert_eq!(time_asn1_string(&utc).unwrap(), "491231235959Z");
        assert_eq!(time_to_chrono(&utc).unwrap().to_rfc3339(), "2049-12-31T23:59:59+00:00");

        let generalized = time_from_chrono(DateTime::parse_from_rfc3339("2050-01-01T00:00:00Z").unwrap().into()).unwrap();
        assert!(matches!(generalized, Time::GeneralTime(_)));
        assert_eq!(time_asn1_string(&generalized).unwrap(), "20500101000000Z");
        assert_eq!(time_to_chrono(&generalized).unwrap().to_rfc3339(), "2050-01-01T00:00:00+00:00");

        assert!(time_from_chrono(DateTime::parse_from_rfc3339("1969-12-31T23:59:59Z").unwrap().into()).is_err());
    }

    #[test]
    fn test_attribute_value_string() {
        let any = |tag: Tag, bytes: &[u8]| Any::new(tag, bytes).unwrap();
        assert_eq!(attribute_value_string(&any(Tag::PrintableString, b"abc")).unwrap(), "abc");
        assert_eq!(attribute_value_string(&any(Tag::Utf8String, "ünï".as_bytes())).unwrap(), "ünï");
        assert_eq!(attribute_value_string(&any(Tag::BmpString, &[0, b'h', 0, 0xfc])).unwrap(), "hü");
        assert_eq!(attribute_value_string(&any(Tag::TeletexString, &[b'h', 0xfc])).unwrap(), "hü");
        assert!(attribute_value_string(&any(Tag::OctetString, b"abc")).is_err());
    }
}
