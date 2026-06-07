use std::collections::HashMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use base64::Engine;
use rama::crypto::dep::rcgen::{BasicConstraints,
                               CertificateParams,
                               DistinguishedName,
                               DnType,
                               ExtendedKeyUsagePurpose,
                               IsCa, Issuer, KeyPair,
                               KeyUsagePurpose};
use rama::error::OpaqueError;
use rama::net::tls::client::ClientHello;
use rama::net::tls::DataEncoding;
use rama::net::tls::server::{DynamicCertIssuer, ServerAuthData};
use rama::telemetry::tracing;
use time::OffsetDateTime;

const DEFAULT_CA_DIR_NAME: &str = ".inspect";
const DEFAULT_CA_CERT_DER: &str = "mitm-root-ca.der";
const DEFAULT_CA_CERT_PEM: &str = "mitm-root-ca.crt";
const DEFAULT_CA_KEY_PEM: &str = "mitm-root-ca.key";
const DEFAULT_CA_CN: &str = "Inspect Local MITM Root CA";

#[derive(Debug)]
pub struct Ca {
    ca_cert_der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

impl Default for Ca {
    fn default() -> Self {
        Self::load_or_create_default().expect("failed to load/create default root CA")
    }
}

impl Ca {
    fn load_or_create_default() -> Result<Self> {
        let dir = default_ca_dir()?;
        ensure_ca_artifacts(&dir, false)?;
        Self::load_from_dir(&dir)
    }

    fn load_from_dir(dir: &Path) -> Result<Self> {
        let key_pem = std::fs::read_to_string(dir.join(DEFAULT_CA_KEY_PEM))
            .with_context(|| format!("read {}", dir.join(DEFAULT_CA_KEY_PEM).display()))?;
        let ca_cert_der = std::fs::read(dir.join(DEFAULT_CA_CERT_DER))
            .with_context(|| format!("read {}", dir.join(DEFAULT_CA_CERT_DER).display()))?;

        let key_pair = KeyPair::from_pem(&key_pem).context("parse CA private key PEM")?;
        let issuer = Issuer::new(ca_params()?, key_pair);

        Ok(Self { ca_cert_der, issuer })
    }

    fn sign_for_host(&self, host: &str, issuer: &Issuer<'_, KeyPair>) -> anyhow::Result<ServerAuthData> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, host);
            dn
        };

        let (yesterday, tomorrow) = validity_period_leaf();
        params.not_before = yesterday;
        params.not_after = tomorrow;

        let key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&key_pair, issuer)?;

        Ok(ServerAuthData {
            private_key: DataEncoding::Pem(
                key_pair
                    .serialize_pem()
                    .try_into()
                    .expect("valid PEM key"),
            ),
            cert_chain: DataEncoding::Pem(
                cert.pem()
                    .try_into()
                    .expect("valid PEM cert"),
            ),
            ocsp: None,
        })
    }
}

fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec![])?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DEFAULT_CA_CN);
        dn
    };
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let (not_before, not_after) = validity_period_ca();
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

fn validity_period_ca() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    let day = time::Duration::new(86_400, 0);
    let ten_years = time::Duration::new(86_400 * 365 * 10, 0);
    (
        now.checked_sub(day).unwrap_or(now),
        now.checked_add(ten_years).unwrap_or(now),
    )
}

fn validity_period_leaf() -> (OffsetDateTime, OffsetDateTime) {
    let day = time::Duration::new(86_400, 0);
    let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
    (yesterday, tomorrow)
}

fn default_ca_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("INSPECT_CA_DIR") {
        return Ok(PathBuf::from(dir));
    }

    let home = std::env::var("HOME").context("HOME is not set; set INSPECT_CA_DIR explicitly")?;
    Ok(PathBuf::from(home).join(DEFAULT_CA_DIR_NAME))
}

pub fn generate_default_ca_files(force: bool) -> Result<PathBuf> {
    let dir = default_ca_dir()?;
    ensure_ca_artifacts(&dir, force)?;
    Ok(dir)
}

fn ensure_ca_artifacts(dir: &Path, force: bool) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))?;

    let der = dir.join(DEFAULT_CA_CERT_DER);
    let crt = dir.join(DEFAULT_CA_CERT_PEM);
    let key = dir.join(DEFAULT_CA_KEY_PEM);

    if !force && der.exists() && crt.exists() && key.exists() {
        tracing::info!("root CA already exists: {}", dir.display());
        return Ok(());
    }

    let key_pair = KeyPair::generate().context("generate CA key pair")?;
    let params = ca_params()?;
    let cert = params.self_signed(&key_pair).context("self-sign root CA")?;

    std::fs::write(&key, key_pair.serialize_pem())
        .with_context(|| format!("write {}", key.display()))?;
    std::fs::write(&crt, cert.pem())
        .with_context(|| format!("write {}", crt.display()))?;
    std::fs::write(&der, cert.der())
        .with_context(|| format!("write {}", der.display()))?;

    let fp = cert.der();
    let sha256_b64 = base64::engine::general_purpose::STANDARD.encode(fp);
    tracing::info!("generated root CA at {}", dir.display());
    tracing::info!("root CA DER SHA256(base64): {}", sha256_b64);

    Ok(())
}

#[derive(Debug, Default)]
pub struct DynamicIssuer {
    ca: Arc<Ca>,
    cache: RwLock<HashMap<String, ServerAuthData>>,
}

impl DynamicCertIssuer for DynamicIssuer {
    async fn issue_cert(
        &self,
        client_hello: ClientHello,
        _server_name: Option<rama::net::address::Domain>,
    ) -> Result<ServerAuthData, OpaqueError> {
        let sni = match client_hello.ext_server_name() {
            Some(domain) => domain.to_string(),
            None => return Err(OpaqueError::from_display("missing SNI")),
        };

        if let Some(data) = self.cache.read().unwrap().get(&sni).cloned() {
            return Ok(data);
        }

        let ca = self.ca.clone();
        let data = self
            .ca
            .sign_for_host(&sni, &ca.issuer)
            .map_err(OpaqueError::from_display)?;

        self.cache.write().unwrap().insert(sni, data.clone());
        Ok(data)
    }
}