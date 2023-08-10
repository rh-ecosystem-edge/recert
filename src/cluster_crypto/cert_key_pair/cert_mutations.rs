use super::SUBJECT_ALTERNATIVE_NAME_OID;
use crate::cnsanreplace::CnSanReplaceRules;
use anyhow;
use anyhow::{Context, Result};
use bcder::OctetString;
use bcder::Oid;
use der::asn1::Ia5String;
use der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName::DnsName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_certificate::rfc3280::Name;
use x509_certificate::{rfc3280, rfc4519::OID_COMMON_NAME, rfc5280::TbsCertificate};

pub(crate) fn mutate_cert(tbs_certificate: &mut TbsCertificate, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
    mutate_cert_cn_san(tbs_certificate, cn_san_replace_rules).context("mutating CN/SAN")?;
    Ok(())
}

pub(crate) fn mutate_cert_cn_san(
    tbs_certificate: &mut TbsCertificate,
    cn_san_replace_rules: &CnSanReplaceRules,
) -> Result<(), anyhow::Error> {
    mutate_cert_common_name(&mut tbs_certificate.subject, cn_san_replace_rules).context("mutating subject Common Name")?;
    mutate_cert_common_name(&mut tbs_certificate.issuer, cn_san_replace_rules).context("mutating subject Common Name")?;
    mutate_cert_subject_alternative_name(tbs_certificate, cn_san_replace_rules).context("mutating Subject Alternative Name")?;
    Ok(())
}

pub(crate) fn mutate_cert_common_name(name: &mut Name, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
    name.iter_mut_by_oid(Oid(OID_COMMON_NAME.as_ref().into()))
        .map(|common_name| {
            *common_name = rfc3280::AttributeTypeAndValue::new_utf8_string(
                Oid(OID_COMMON_NAME.as_ref().into()),
                cn_san_replace_rules.replace(common_name.to_string()?.as_str()).as_str(),
            )
            .ok()
            .context("failed to generate utf-8 common name")?;

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
                                DnsName(name) => DnsName(Ia5String::new(&cn_san_replace_rules.replace(&name.to_string()))?),
                                san_name => san_name.clone(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                );

                ext.value = OctetString::new(bytes::Bytes::copy_from_slice(
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
