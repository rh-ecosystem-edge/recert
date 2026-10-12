use crate::cluster_crypto::{
    crypto_utils::{sign, SigningKey},
    keys::PublicKey,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64_url, Engine as _};
use std::{io::Write, process::Command};

/// The `openssl dgst` digest flag for JWT algorithms that are signed over a digest. EdDSA signs the
/// raw message and is handled separately via `openssl pkeyutl`.
fn digest_for_alg(alg: &str) -> Option<&'static str> {
    match alg {
        "RS256" | "ES256" => Some("-sha256"),
        "ES384" => Some("-sha384"),
        _ => None,
    }
}

/// Width in bytes of each of the R and S components of a JWS ECDSA signature (RFC 7518 §3.4).
fn ecdsa_component_width(alg: &str) -> Option<usize> {
    match alg {
        "ES256" => Some(32),
        "ES384" => Some(48),
        _ => None,
    }
}

/// Reads one short-form DER TLV with the expected tag, returning (value, rest). ECDSA signatures
/// for P-256/P-384 never need long-form lengths.
fn read_der_tlv(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8])> {
    match input {
        [tag, len, rest @ ..] if *tag == expected_tag && *len < 0x80 && rest.len() >= *len as usize => Ok(rest.split_at(*len as usize)),
        _ => bail!("malformed DER element (expected tag {:#04x})", expected_tag),
    }
}

/// Converts a minimal non-negative DER INTEGER value into a big-endian unsigned integer padded to `width`.
fn der_uint_to_fixed(value: &[u8], width: usize) -> Result<Vec<u8>> {
    let magnitude = match value {
        [] => bail!("empty DER INTEGER"),
        [0x00] => bail!("zero ECDSA signature component"),
        [0x00, next, ..] if next & 0x80 == 0 => bail!("non-minimal DER INTEGER"),
        [0x00, rest @ ..] => rest,
        [first, ..] if first & 0x80 != 0 => bail!("negative DER INTEGER"),
        _ => value,
    };
    if magnitude.len() > width {
        bail!("ECDSA signature component wider than {} bytes", width);
    }
    let mut out = vec![0u8; width - magnitude.len()];
    out.extend_from_slice(magnitude);
    Ok(out)
}

fn fixed_to_der_uint(component: &[u8]) -> Result<Vec<u8>> {
    let start = component.iter().position(|&b| b != 0).context("zero ECDSA signature component")?;
    let magnitude = &component[start..];
    let pad = magnitude[0] & 0x80 != 0;
    let mut out = vec![0x02, (magnitude.len() + usize::from(pad)) as u8];
    if pad {
        out.push(0x00);
    }
    out.extend_from_slice(magnitude);
    Ok(out)
}

/// Converts an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature to JWS `R‖S` form.
fn ecdsa_der_to_jose(der_sig: &[u8], alg: &str) -> Result<Vec<u8>> {
    let width = ecdsa_component_width(alg).with_context(|| format!("{} is not an ECDSA JWT algorithm", alg))?;
    let (seq, trailing) = read_der_tlv(der_sig, 0x30)?;
    if !trailing.is_empty() {
        bail!("trailing bytes after DER ECDSA signature");
    }
    let (r, rest) = read_der_tlv(seq, 0x02)?;
    let (s, rest) = read_der_tlv(rest, 0x02)?;
    if !rest.is_empty() {
        bail!("unexpected extra elements in DER ECDSA signature");
    }
    let mut jose = der_uint_to_fixed(r, width).context("ECDSA r")?;
    jose.extend(der_uint_to_fixed(s, width).context("ECDSA s")?);
    Ok(jose)
}

/// Converts a JWS `R‖S` ECDSA signature to ASN.1 DER form, as expected by OpenSSL.
fn ecdsa_jose_to_der(jose_sig: &[u8], alg: &str) -> Result<Vec<u8>> {
    let width = ecdsa_component_width(alg).with_context(|| format!("{} is not an ECDSA JWT algorithm", alg))?;
    if jose_sig.len() != 2 * width {
        bail!("{} signature must be {} bytes, got {}", alg, 2 * width, jose_sig.len());
    }
    let (r, s) = jose_sig.split_at(width);
    let mut body = fixed_to_der_uint(r).context("ECDSA r")?;
    body.extend(fixed_to_der_uint(s).context("ECDSA s")?);
    let mut der = vec![0x30, body.len() as u8];
    der.extend(body);
    Ok(der)
}

fn openssl_verify(alg: &str, pub_pem: &str, signature: &[u8], header_payload: &str) -> Result<bool> {
    let mut cert_file = tempfile::NamedTempFile::new()?;
    cert_file.write_all(pub_pem.as_bytes())?;
    cert_file.flush()?;

    let mut signature_file = tempfile::NamedTempFile::new()?;
    signature_file.write_all(signature)?;
    signature_file.flush()?;

    let mut header_payload_file = tempfile::NamedTempFile::new()?;
    header_payload_file.write_all(header_payload.as_bytes())?;
    header_payload_file.flush()?;

    let cert_path = cert_file.path().to_str().context("cert path")?;
    let sig_path = signature_file.path().to_str().context("sig path")?;
    let data_path = header_payload_file.path().to_str().context("data path")?;

    let mut command = Command::new("openssl");
    match alg {
        "EdDSA" => command.args([
            "pkeyutl", "-verify", "-inkey", cert_path, "-pubin", "-rawin", "-in", data_path, "-sigfile", sig_path,
        ]),
        _ => match digest_for_alg(alg) {
            Some(digest) => command.args(["dgst", digest, "-verify", cert_path, "-signature", sig_path, data_path]),
            None => {
                log::warn!("unsupported JWT alg {}", alg);
                return Ok(false);
            }
        },
    };
    let output = command.output()?;

    Ok(output.status.success())
}

pub(crate) fn verify(jwt: &str, public_key: &PublicKey) -> Result<bool> {
    let pub_pem = public_key.pem()?.to_string();

    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("jwt not 3 parts");
    }

    let header_decoded = base64_url.decode(parts[0].as_bytes())?;
    let signature_decoded = base64_url.decode(parts[2].as_bytes())?;

    let header_payload = format!("{}.{}", parts[0], parts[1]);

    let header_json = serde_json::from_slice::<serde_json::Value>(&header_decoded)?;

    let alg = header_json
        .get("alg")
        .context("jwt missing alg")?
        .as_str()
        .context("alg not string")?;

    if ecdsa_component_width(alg).is_none() {
        return openssl_verify(alg, &pub_pem, &signature_decoded, &header_payload);
    }

    if let Ok(der_sig) = ecdsa_jose_to_der(&signature_decoded, alg) {
        if openssl_verify(alg, &pub_pem, &der_sig, &header_payload)? {
            return Ok(true);
        }
    }

    // Older recert versions emitted raw DER ECDSA signatures; accept them only when strictly well-formed
    // so those tokens can still be matched to their signer and re-signed in JWS form.
    if ecdsa_der_to_jose(&signature_decoded, alg).is_ok() {
        return openssl_verify(alg, &pub_pem, &signature_decoded, &header_payload);
    }

    Ok(false)
}

pub(crate) fn resign(jwt: &str, private_key: &SigningKey) -> Result<String> {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Ok(jwt.to_string());
    }

    let header_decoded = base64_url.decode(parts[0].as_bytes())?;
    let payload = parts[1];

    let mut header_json = serde_json::from_slice::<serde_json::Value>(&header_decoded)?;

    let new_alg = private_key.jwt_alg().context("determining JWT algorithm")?;

    let jwt_key_id = private_key.jwt_key_id().context("calculating key id")?;

    let header_obj = header_json.as_object_mut().context("header not object")?;
    header_obj.insert("alg".to_string(), serde_json::Value::String(new_alg.to_string()));
    header_obj.insert("kid".to_string(), serde_json::Value::String(jwt_key_id));

    let header_json = serde_json::to_string(&header_json)?;

    let header_payload = format!("{}.{}", base64_url.encode(header_json.as_bytes()), payload);

    let signature = sign(private_key, header_payload.as_bytes()).context("signing JWT")?;
    let signature = if ecdsa_component_width(new_alg).is_some() {
        ecdsa_der_to_jose(&signature, new_alg).context("converting OpenSSL ECDSA signature to JWS form")?
    } else {
        signature
    };

    Ok(format!("{}.{}", header_payload, base64_url.encode(signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_crypto::crypto_utils::{generate_rsa_key, SigningKey};
    use crate::cluster_crypto::keys::{PrivateKey, PublicKey};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as b64;

    fn unsigned_rs256_jwt() -> String {
        let header = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = b64.encode(br#"{"sub":"test"}"#);
        format!("{}.{}.AA", header, payload)
    }

    fn rsa_signing_key() -> &'static SigningKey {
        static KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| generate_rsa_key(2048).unwrap())
    }

    fn dummy_rsa_public_key() -> PublicKey {
        PublicKey::Rsa(bytes::Bytes::from_static(b"not-a-real-key"))
    }

    fn rsa_public_key() -> PublicKey {
        let private_key = PrivateKey::try_from(&rsa_signing_key().in_memory_signing_key_pair).unwrap();
        PublicKey::try_from(&private_key).unwrap()
    }

    #[test]
    fn test_verify_rejects_non_three_part_jwt() {
        assert!(verify("not-a-jwt", &dummy_rsa_public_key()).is_err());
    }

    #[test]
    fn test_verify_ec_public_key_bad_signature_returns_false() {
        let key = crate::cluster_crypto::crypto_utils::generate_ec_key(x509_certificate::EcdsaCurve::Secp256r1).unwrap();
        let private_key = key.to_private_key().unwrap();
        let public_key = PublicKey::try_from(&private_key).unwrap();

        let header = b64.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
        let payload = b64.encode(br#"{"sub":"test"}"#);
        let jwt = format!("{}.{}.AA", header, payload);
        assert!(!verify(&jwt, &public_key).unwrap());
    }

    #[test]
    fn test_verify_unsupported_alg_returns_false() {
        let header = b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let jwt = format!("{}.{}.AA", header, b64.encode(br#"{"sub":"test"}"#));
        assert!(!verify(&jwt, &dummy_rsa_public_key()).unwrap());
    }

    #[test]
    fn test_resign_passthrough_when_not_three_parts() {
        assert_eq!(resign("not-a-jwt", rsa_signing_key()).unwrap(), "not-a-jwt");
    }

    #[test]
    fn test_resign_overwrites_hs256_alg_with_key_alg() {
        let header = b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let jwt = format!("{}.{}.AA", header, b64.encode(br#"{"sub":"test"}"#));
        let resigned = resign(&jwt, rsa_signing_key()).unwrap();
        let parts: Vec<_> = resigned.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert!(header.get("kid").and_then(|v| v.as_str()).is_some());
    }

    #[test]
    fn test_verify_missing_alg_errors() {
        let header = b64.encode(br#"{"typ":"JWT"}"#);
        let jwt = format!("{}.{}.AA", header, b64.encode(br#"{"sub":"test"}"#));
        assert!(verify(&jwt, &dummy_rsa_public_key())
            .unwrap_err()
            .to_string()
            .contains("jwt missing alg"));
    }

    #[test]
    fn test_resign_and_verify_es256_roundtrip() {
        let key = crate::cluster_crypto::crypto_utils::generate_ec_key(x509_certificate::EcdsaCurve::Secp256r1).unwrap();
        let resigned = resign(&unsigned_rs256_jwt(), &key).unwrap();
        let parts: Vec<_> = resigned.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert!(header.get("kid").and_then(|v| v.as_str()).is_some());

        let private_key = key.to_private_key().unwrap();
        let public_key = PublicKey::try_from(&private_key).unwrap();
        assert!(verify(&resigned, &public_key).unwrap());
    }

    #[test]
    fn test_resign_and_verify_rs256_roundtrip() {
        let key = rsa_signing_key();
        let jwt = unsigned_rs256_jwt();
        let resigned = resign(&jwt, key).unwrap();
        let parts: Vec<_> = resigned.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert!(header.get("kid").and_then(|v| v.as_str()).is_some());
        assert!(verify(&resigned, &rsa_public_key()).unwrap());
    }

    fn ec_key(curve: x509_certificate::EcdsaCurve) -> (SigningKey, PublicKey) {
        let key = crate::cluster_crypto::crypto_utils::generate_ec_key(curve).unwrap();
        let public_key = PublicKey::try_from(&key.to_private_key().unwrap()).unwrap();
        (key, public_key)
    }

    fn replace_signature(jwt: &str, signature: &[u8]) -> String {
        let (signing_input, _) = jwt.rsplit_once('.').unwrap();
        format!("{}.{}", signing_input, b64.encode(signature))
    }

    fn decoded_signature(jwt: &str) -> Vec<u8> {
        b64.decode(jwt.rsplit_once('.').unwrap().1).unwrap()
    }

    #[test]
    fn test_der_jose_roundtrip_with_leading_zeroes_and_sign_bytes() {
        for (alg, width) in [("ES256", 32usize), ("ES384", 48usize)] {
            // r has leading zero bytes in JOSE; s has its high bit set so DER needs a sign-protection byte.
            let mut r = vec![0u8; width];
            r[2..].iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8) | 1);
            let s = vec![0xffu8; width];
            let jose = [r.clone(), s.clone()].concat();

            let der = ecdsa_jose_to_der(&jose, alg).unwrap();
            let (seq, rest) = read_der_tlv(&der, 0x30).unwrap();
            assert!(rest.is_empty());
            let (der_r, rest) = read_der_tlv(seq, 0x02).unwrap();
            let (der_s, _) = read_der_tlv(rest, 0x02).unwrap();
            assert_eq!(der_r, &r[2..]);
            assert_eq!(der_s[0], 0x00);
            assert_eq!(&der_s[1..], &s[..]);

            assert_eq!(ecdsa_der_to_jose(&der, alg).unwrap(), jose);
        }
    }

    #[test]
    fn test_der_to_jose_rejects_malformed() {
        let valid = ecdsa_jose_to_der(&[[0x01u8; 32], [0x02u8; 32]].concat(), "ES256").unwrap();
        let mut trailing = valid.clone();
        trailing.push(0x00);
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            trailing,
            valid[..valid.len() - 1].to_vec(),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00],       // zero s
            vec![0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01],       // negative r
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01], // non-minimal r
            vec![0x30, 0x03, 0x02, 0x01, 0x01],                         // missing s
            vec![0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01],             // empty r
            vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],       // SET instead of SEQUENCE
            vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // long-form length
            vec![0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // extra INTEGER
            [vec![0x30, 0x25, 0x02, 0x21], vec![0x01; 33], vec![0x02, 0x01, 0x01]].concat(), // r too wide
        ];
        for case in cases {
            assert!(ecdsa_der_to_jose(&case, "ES256").is_err(), "accepted {:02x?}", case);
        }
        assert!(ecdsa_der_to_jose(&valid, "RS256").is_err());
    }

    #[test]
    fn test_jose_to_der_rejects_wrong_width_and_zero() {
        assert!(ecdsa_jose_to_der(&[0x01; 63], "ES256").is_err());
        assert!(ecdsa_jose_to_der(&[0x01; 96], "ES256").is_err());
        assert!(ecdsa_jose_to_der(&[[0u8; 32], [1u8; 32]].concat(), "ES256").is_err());
        assert!(ecdsa_jose_to_der(&[[1u8; 32], [0u8; 32]].concat(), "ES256").is_err());
        assert!(ecdsa_jose_to_der(&[0x01; 64], "RS256").is_err());
    }

    #[test]
    fn test_resign_ecdsa_emits_jose_width_and_verifies() {
        for (curve, alg, len) in [
            (x509_certificate::EcdsaCurve::Secp256r1, "ES256", 64),
            (x509_certificate::EcdsaCurve::Secp384r1, "ES384", 96),
        ] {
            let (key, public_key) = ec_key(curve);
            let resigned = resign(&unsigned_rs256_jwt(), &key).unwrap();
            let header: serde_json::Value = serde_json::from_slice(&b64.decode(resigned.split('.').next().unwrap()).unwrap()).unwrap();
            assert_eq!(header["alg"], alg);
            assert_eq!(decoded_signature(&resigned).len(), len);
            assert!(verify(&resigned, &public_key).unwrap());

            let (_, other_public_key) = ec_key(curve);
            assert!(!verify(&resigned, &other_public_key).unwrap());
        }
    }

    #[test]
    fn test_verify_accepts_legacy_der_and_resign_migrates_to_jose() {
        for (curve, len) in [
            (x509_certificate::EcdsaCurve::Secp256r1, 64),
            (x509_certificate::EcdsaCurve::Secp384r1, 96),
        ] {
            let (key, public_key) = ec_key(curve);
            let jose_jwt = resign(&unsigned_rs256_jwt(), &key).unwrap();
            let alg = key.jwt_alg().unwrap();
            let der = ecdsa_jose_to_der(&decoded_signature(&jose_jwt), alg).unwrap();
            let legacy_jwt = replace_signature(&jose_jwt, &der);

            assert!(verify(&legacy_jwt, &public_key).unwrap());

            let (new_key, new_public_key) = ec_key(curve);
            assert!(!verify(&legacy_jwt, &new_public_key).unwrap());

            let migrated = resign(&legacy_jwt, &new_key).unwrap();
            assert_eq!(decoded_signature(&migrated).len(), len);
            assert!(verify(&migrated, &new_public_key).unwrap());
        }
    }

    #[test]
    fn test_verify_rejects_malformed_ecdsa_signatures() {
        let (key, public_key) = ec_key(x509_certificate::EcdsaCurve::Secp256r1);
        let jwt = resign(&unsigned_rs256_jwt(), &key).unwrap();
        let sig = decoded_signature(&jwt);

        let mut flipped = sig.clone();
        flipped[10] ^= 0x01;
        let mut der_with_trailing = ecdsa_jose_to_der(&sig, "ES256").unwrap();
        der_with_trailing.push(0x00);

        for bad in [
            flipped,
            sig[..63].to_vec(),
            [sig.clone(), vec![0]].concat(),
            der_with_trailing,
            vec![0u8; 64],
        ] {
            assert!(!verify(&replace_signature(&jwt, &bad), &public_key).unwrap());
        }
    }

    #[test]
    fn test_resign_and_verify_eddsa_roundtrip() {
        let key = crate::cluster_crypto::crypto_utils::generate_ed25519_key().unwrap();
        let public_key = PublicKey::try_from(&key.to_private_key().unwrap()).unwrap();
        let resigned = resign(&unsigned_rs256_jwt(), &key).unwrap();
        assert_eq!(decoded_signature(&resigned).len(), 64);
        assert!(verify(&resigned, &public_key).unwrap());
    }
}
