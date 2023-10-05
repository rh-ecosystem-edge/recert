use super::SUBJECT_ALTERNATIVE_NAME_OID;
use crate::cnsanreplace::CnSanReplaceRules;
use anyhow::bail;
use anyhow::{Context, Result};
use bcder::OctetString as BcderOctetString;
use bcder::Oid;
use bcder::Tag;
use der::asn1::Ia5String;
use der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName::{DnsName, IpAddress};
use x509_cert::ext::pkix::SubjectAltName;
use x509_certificate::rfc3280::{AttributeTypeAndValue, Name};
use x509_certificate::{rfc3280, rfc4519::OID_COMMON_NAME, rfc5280::TbsCertificate};

pub(crate) fn mutate_cert(
    tbs_certificate: &mut TbsCertificate,
    cn_san_replace_rules: &CnSanReplaceRules,
    extend_expiration: bool,
) -> Result<()> {
    mutate_cert_cn_san(tbs_certificate, cn_san_replace_rules).context("mutating CN/SAN")?;
    mutate_expiration(tbs_certificate, extend_expiration).context("extending expiration")?;
    Ok(())
}

fn mutate_expiration(tbs_certificate: &mut TbsCertificate, extend_expiration: bool) -> Result<()> {
    if !extend_expiration {
        return Ok(());
    }

    let (not_before, not_after) = match &tbs_certificate.validity.not_before {
        x509_certificate::asn1time::Time::UtcTime(not_before) => {
            match &tbs_certificate.validity.not_after {
                x509_certificate::asn1time::Time::UtcTime(not_after) => {
                    // Dereferncing is the only way to get a chrono::DateTime out of the
                    // x509_certificate::asn1time::UtcTime struct.
                    (*(not_before.clone()), *(not_after.clone()))
                }
                x509_certificate::asn1time::Time::GeneralTime(_) => bail!("GeneralTime not supported"),
            }
        }
        x509_certificate::asn1time::Time::GeneralTime(_) => bail!("GeneralTime not supported"),
    };

    let now = chrono::Utc::now();
    let extended_not_before = now;

    let extension = now - not_before;
    let extended_not_after = not_after + extension;

    tbs_certificate.validity.not_before = extended_not_before.into();
    tbs_certificate.validity.not_after = extended_not_after.into();

    Ok(())
}

pub(crate) fn mutate_cert_cn_san(
    tbs_certificate: &mut TbsCertificate,
    cn_san_replace_rules: &CnSanReplaceRules,
) -> Result<(), anyhow::Error> {
    mutate_cert_common_name(&mut tbs_certificate.subject, cn_san_replace_rules).context("mutating subject Common Name")?;
    mutate_cert_common_name(&mut tbs_certificate.issuer, cn_san_replace_rules).context("mutating issuer Common Name")?;
    mutate_cert_subject_alternative_name(tbs_certificate, cn_san_replace_rules).context("mutating Subject Alternative Name")?;
    Ok(())
}

enum CommonNameType {
    Unknown,
    PrintableString,
    Utf8String,
}

impl TryFrom<AttributeTypeAndValue> for CommonNameType {
    type Error = anyhow::Error;

    fn try_from(value: AttributeTypeAndValue) -> std::result::Result<Self, Self::Error> {
        let mut common_name_type = CommonNameType::Unknown;

        (*value.value).clone().decode(|cons| {
            if (cons.take_opt_value_if(Tag::PRINTABLE_STRING, |content| bcder::PrintableString::from_content(content))?).is_some() {
                common_name_type = CommonNameType::PrintableString;
            } else if (cons.take_opt_value_if(Tag::UTF8_STRING, |content| bcder::Utf8String::from_content(content))?).is_some() {
                common_name_type = CommonNameType::Utf8String;
            }

            Ok("".to_string())
        })?;

        Ok(common_name_type)
    }
}

pub(crate) fn mutate_cert_common_name(name: &mut Name, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
    name.iter_mut_by_oid(Oid(OID_COMMON_NAME.as_ref().into()))
        .map(|common_name| {
            let binding = cn_san_replace_rules.replace(common_name.to_string()?.as_str());
            let new_name = binding.as_str().clone();

            let common_name_type: CommonNameType = common_name.clone().try_into()?;

            match common_name_type {
                CommonNameType::Unknown => bail!("unknown common name type"),
                CommonNameType::PrintableString => {
                    *common_name =
                        rfc3280::AttributeTypeAndValue::new_printable_string(Oid(OID_COMMON_NAME.as_ref().into()), new_name.clone())
                            .ok()
                            .context("failed to generate utf-8 common name")?
                }
                CommonNameType::Utf8String => {
                    *common_name = rfc3280::AttributeTypeAndValue::new_utf8_string(Oid(OID_COMMON_NAME.as_ref().into()), new_name)
                        .ok()
                        .context("failed to generate utf-8 common name")?
                }
            }

            Ok(())
        })
        .collect::<Result<Vec<()>>>()?;
    Ok(())
}

pub(crate) fn mutate_cert_subject_alternative_name(
    tbs_certificate: &mut TbsCertificate,
    cn_san_replace_rules: &CnSanReplaceRules,
) -> Result<()> {
    if let Some(extensions) = &mut tbs_certificate.extensions {
        extensions
            .iter_mut()
            .filter(|ext| ext.id == Oid(&SUBJECT_ALTERNATIVE_NAME_OID))
            .map(|ext| {
                let san_extension = SubjectAltName::from_der(ext.value.as_slice().context("empty SAN extension")?)?;
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

                ext.value = BcderOctetString::new(bytes::Bytes::copy_from_slice(
                    new_san_extension
                        .to_der()
                        .context("failed to generate SAN extension")
                        .ok()
                        .context("failed to generate SAN extension")?
                        .as_slice(),
                ));
                Ok(())
            })
            .collect::<Result<Vec<()>>>()
            .context("mutating cert CN/SAN extensions")?;
    }
    Ok(())
}
