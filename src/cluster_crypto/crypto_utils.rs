use super::{cert_key_pair::CertKeyPair, distributed_jwt, keys};
use bcder::{encode::Values, Mode};
use jwt_simple::prelude::RSAPublicKeyLike;
use rsa::{
    self,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    RsaPrivateKey,
};
use serde_json::{Map, Value};
use std::{cell::RefCell, io::Write, process::Command, rc::Rc};
use x509_certificate::{rfc5280, InMemorySigningKeyPair};

/// Shell out to openssl to verify that a certificate is signed by a given signing certificate. We
/// use this when our certificate lib doesn't support the signature algorithm used by the
/// certificates.
pub(crate) fn openssl_is_signed(potential_signer: &Rc<RefCell<CertKeyPair>>, signee: &Rc<RefCell<CertKeyPair>>) -> bool {
    // TODO: This condition is a hack. We should trust the openssl command we run further down to
    // tell us this, but we don't because currently the way this openssl command works, if you pass
    // it the same cert in both arguments, even when said cert is not self-signed, openssl would
    // give it a green light and say it's valid. So we do this hack to avoid pretending
    // certificates are their own signer when they're not. This is a hack because it's possible
    // that a certificate is not self-signed and has the same issuer and subject and it would pass
    // here undetected. This is not a big deal in our use case because these certs are all coming
    // from our trusted installer/operators.
    if potential_signer == signee
        && !(*(**potential_signer).borrow().distributed_cert)
            .borrow()
            .certificate
            .original
            .subject_is_issuer()
    {
        return false;
    }

    let mut signing_cert_file = tempfile::NamedTempFile::new().unwrap();
    signing_cert_file
        .write_all(
            &(*(**potential_signer).borrow().distributed_cert)
                .borrow()
                .certificate
                .original
                .encode_pem()
                .as_bytes(),
        )
        .unwrap();
    let mut signed_cert_file = tempfile::NamedTempFile::new().unwrap();
    signed_cert_file
        .write_all(
            &(*(**signee).borrow().distributed_cert)
                .borrow()
                .certificate
                .original
                .encode_pem()
                .as_bytes(),
        )
        .unwrap();
    let mut openssl_verify_command = Command::new("openssl");
    openssl_verify_command
        .arg("verify")
        .arg("-no_check_time")
        .arg("-no-CAfile")
        .arg("-no-CApath")
        .arg("-partial_chain")
        .arg("-trusted")
        .arg(signing_cert_file.path())
        .arg(signed_cert_file.path());
    let openssl_verify_output = openssl_verify_command.output().unwrap();
    openssl_verify_output.status.success()
}

pub(crate) fn verify_jwt(
    public_key: &keys::PublicKey,
    distributed_jwt: &distributed_jwt::DistributedJwt,
) -> Result<jwt_simple::prelude::JWTClaims<Map<String, Value>>, jwt_simple::Error> {
    match &public_key {
        keys::PublicKey::Rsa(bytes) => jwt_simple::prelude::RS256PublicKey::from_der(bytes).unwrap(),
        keys::PublicKey::Ec(_) => return Err(jwt_simple::Error::msg("EC public keys are not supported")),
    }
    .verify_token::<Map<String, Value>>(&distributed_jwt.jwt.str, None)
}

pub(crate) fn generate_rsa_key() -> (RsaPrivateKey, InMemorySigningKeyPair) {
    let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(
        String::from_utf8_lossy(
            &std::process::Command::new("openssl")
                .args(&["genrsa", "2048"])
                .output()
                .expect("failed to execute openssl")
                .stdout,
        )
        .to_string()
        .as_str(),
    )
    .unwrap();

    let rsa_pkcs8_der_bytes: Vec<u8> = rsa_private_key.to_pkcs8_der().unwrap().as_bytes().into();
    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&rsa_pkcs8_der_bytes).unwrap();
    (rsa_private_key, key_pair)
}

pub(crate) fn encode_tbs_cert_to_der(tbs_certificate: &rfc5280::TbsCertificate) -> Vec<u8> {
    let mut tbs_der = Vec::<u8>::new();
    tbs_certificate.encode_ref().write_encoded(Mode::Der, &mut tbs_der).unwrap();
    tbs_der
}
