use crate::cluster_crypto::certificate::SUBJECT_ALTERNATIVE_NAME_OID;
use crate::cnsanreplace::CnSanReplaceRules;
use anyhow::bail;
use anyhow::{Context, Result};
use bcder::OctetString as BcderOctetString;
use bcder::Oid;
use bcder::Tag;
use chrono::{DateTime, Utc};
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

    tbs_certificate.validity.not_before = (current_not_before - rewind_duration).into();
    tbs_certificate.validity.not_after = (current_not_after - rewind_duration).into();

    Ok(())
}

fn extend_certificate_expiration(tbs_certificate: &mut TbsCertificate) -> Result<()> {
    let (current_not_before, current_not_after) = get_certificate_expiration(tbs_certificate).context("evaluating current expiration")?;

    let now = chrono::Utc::now();

    let certificate_duration = current_not_after - current_not_before;

    tbs_certificate.validity.not_before = now.into();
    tbs_certificate.validity.not_after = (now + certificate_duration).into();

    Ok(())
}

fn get_certificate_expiration(tbs_certificate: &mut TbsCertificate) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let current_not_before: DateTime<Utc> = match &tbs_certificate.validity.not_before {
        x509_certificate::asn1time::Time::UtcTime(not_before) => *(not_before.clone()),
        x509_certificate::asn1time::Time::GeneralTime(not_before) => (*not_before).clone().into(),
    };

    let current_not_after: DateTime<Utc> = match &tbs_certificate.validity.not_after {
        x509_certificate::asn1time::Time::UtcTime(not_after) => *(not_after.clone()),
        x509_certificate::asn1time::Time::GeneralTime(not_after) => (*not_after).clone().into(),
    };

    Ok((current_not_before, current_not_after))
}

pub(crate) fn mutate_cert_cn_san(tbs_certificate: &mut TbsCertificate, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
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
            if (cons.take_opt_value_if(Tag::PRINTABLE_STRING, bcder::PrintableString::from_content)?).is_some() {
                common_name_type = CommonNameType::PrintableString;
            } else if (cons.take_opt_value_if(Tag::UTF8_STRING, bcder::Utf8String::from_content)?).is_some() {
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
            let new_name = binding.as_str();

            let common_name_type: CommonNameType = common_name.clone().try_into()?;

            match common_name_type {
                CommonNameType::Unknown => bail!("unknown common name type"),
                CommonNameType::PrintableString => {
                    *common_name = rfc3280::AttributeTypeAndValue::new_printable_string(Oid(OID_COMMON_NAME.as_ref().into()), new_name)
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
