use crate::mitm::tls_sni::IngressSNI;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rama::extensions::{Extension, Extensions};
use rama::tls::boring::core::hash::MessageDigest;
use rama::tls::boring::core::x509::X509;
use rama::tls::client::NegotiatedTlsParameters;
use serde_json::{Value, json};

#[derive(Debug, Clone, Extension)]
pub(crate) struct ExtendedTlsParameters {
    pub negotiated: NegotiatedTlsParameters,
    pub protocol_version: Option<String>,
    pub cipher: Option<String>,
    pub cipher_standard_name: Option<String>,
    pub cipher_description: Option<String>,
    pub bits: Option<u32>,
    pub algorithm_bits: Option<u32>,
    pub curve_name: Option<String>,
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
}

impl ExtendedTlsParameters {
    pub(crate) fn capture(
        ssl: &rama::tls::boring::core::ssl::SslRef,
        negotiated: NegotiatedTlsParameters,
    ) -> Self {
        let cipher = ssl.current_cipher();
        let mut client_random = vec![0; ssl.client_random(&mut [])];
        ssl.client_random(&mut client_random);
        let mut server_random = vec![0; ssl.server_random(&mut [])];
        ssl.server_random(&mut server_random);
        Self {
            negotiated,
            protocol_version: Some(ssl.version_str().to_owned()),
            cipher: cipher.map(|c| c.name().to_owned()),
            cipher_standard_name: cipher.and_then(|c| c.standard_name().map(str::to_owned)),
            cipher_description: cipher.map(|c| c.description()),
            bits: cipher.map(|c| c.bits().secret as u32),
            algorithm_bits: cipher.map(|c| c.bits().algorithm as u32),
            curve_name: ssl.curve_name().map(str::to_owned),
            client_random,
            server_random,
        }
    }
}

pub fn tls_sni_from_extensions(extensions: &Extensions) -> Option<String> {
    extensions
        .get_ref::<IngressSNI>()
        .map(|sni| sni.0.to_string())
}

pub(crate) fn upstream_tls_info_from_extensions(extensions: &Extensions) -> Option<Value> {
    let params = extensions.get_ref::<ExtendedTlsParameters>()?;

    let negotiated = &params.negotiated;

    let certificates = negotiated
        .peer_certificate_chain
        .as_ref()
        .map_or_else(Vec::new, |chain| {
            chain
                .iter()
                .filter_map(|der| certificate_der_to_json(der).ok())
                .collect::<Vec<_>>()
        });

    Some(json!({
        "secure_protocol": params
            .protocol_version
            .clone()
            .unwrap_or_else(|| format!("{:?}", negotiated.protocol_version)),
        "alpn": negotiated
            .application_layer_protocol
            .as_ref()
            .map(|proto| proto.to_string()),
        "cipher": params.cipher,
        "cipher_standard_name": params.cipher_standard_name,
        "cipher_description": params.cipher_description,
        "bits": params.bits,
        "algorithm_bits": params.algorithm_bits,
        "key_exchange_curve": params.curve_name,
        "client_random": hex_upper(&params.client_random),
        "server_random": hex_upper(&params.server_random),
        "certificate_chain": certificates,
    }))
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

fn certificate_der_to_json(der: &[u8]) -> anyhow::Result<Value> {
    let cert = X509::from_der(der)?;

    let subject = x509_name_to_string(cert.subject_name());
    let issuer = x509_name_to_string(cert.issuer_name());

    let serial_number = cert.serial_number().to_bn()?.to_hex_str()?.to_string();

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let sha256 = cert.digest(MessageDigest::sha256())?;
    let thumbprint_sha256 = sha256
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join("");

    let subject_alt_names = cert
        .subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(json!({
        "subject": subject,
        "issuer": issuer,
        "serial_number": serial_number,
        "not_before": not_before,
        "not_after": not_after,
        "thumbprint_sha256": thumbprint_sha256,
        "subject_alt_names": subject_alt_names,
    }))
}

fn x509_name_to_string(name: &rama::tls::boring::core::x509::X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("UNKNOWN");

            let value = entry
                .data()
                .as_utf8()
                .map(|value| value.to_string())
                .unwrap_or_else(|_| STANDARD.encode(entry.data().as_slice()));

            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}
