//! Per-sandbox certificate authority for TLS interception.
//!
//! The CA certificate is installed in the sandbox trust store at creation; the proxy
//! mints a leaf certificate per intercepted host. The CA *key* never leaves the host.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A certificate authority that issues leaf certificates on demand.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    leaves: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl Ca {
    /// Generate a fresh CA and return it as `(certificate PEM, private key PEM)`, for storing.
    pub fn generate_pem(common_name: &str) -> Result<(String, String), rcgen::Error> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Generate a fresh CA.
    pub fn generate(common_name: &str) -> Result<Self, rcgen::Error> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key)?;
        let pem = cert.pem();
        Self::from_pem(&pem, &key.serialize_pem())
    }

    /// Load a CA from PEM (so the sandbox keeps trusting it across daemon restarts).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, rcgen::Error> {
        let key = KeyPair::from_pem(key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key)?;
        let der = rustls_pem_to_der(cert_pem);
        Ok(Self {
            issuer,
            cert_pem: cert_pem.to_owned(),
            cert_der: der,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate in PEM, for the sandbox trust store.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate in DER.
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    /// TLS server config presenting a leaf certificate for `host` (cached).
    pub fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, String> {
        if let Some(c) = self.leaves.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into().map_err(|e: rcgen::Error| e.to_string())?),
        }];
        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| e.to_string())?;
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone(), self.cert_der.clone()], key)
            .map_err(|e| e.to_string())?;
        let cfg = Arc::new(cfg);
        self.leaves
            .lock()
            .unwrap()
            .insert(host.to_owned(), cfg.clone());
        Ok(cfg)
    }
}

/// Decode the first CERTIFICATE block of a PEM string (no extra dependency needed).
fn rustls_pem_to_der(pem: &str) -> CertificateDer<'static> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    CertificateDer::from(b64decode(&body))
}

fn b64decode(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for v in s.bytes().filter_map(val) {
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_and_caches_leaves_and_survives_reload() {
        let ca = Ca::generate("osbx test CA").unwrap();
        let a = ca.server_config("api.example.test").unwrap();
        let b = ca.server_config("api.example.test").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(ca.server_config("10.0.0.1").is_ok()); // IP SAN
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(!ca.cert_der().is_empty());
    }

    #[test]
    fn pem_der_roundtrip_matches_rcgen() {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["x.test".to_owned()]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let c = p.self_signed(&key).unwrap();
        assert_eq!(rustls_pem_to_der(&c.pem()).as_ref(), c.der().as_ref());
    }
}
