use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::{
    STANDARD,
    STANDARD_NO_PAD,
    URL_SAFE,
    URL_SAFE_NO_PAD,
};
use flate2::read::{DeflateDecoder, GzDecoder};
use serde_json::Value;
use std::io::Read;

#[derive(Clone, Debug)]
pub struct DecodedBody {
    pub bytes: Vec<u8>,
    pub content_encoding: Option<String>,
    pub decoded: bool,
}

pub fn decode_body_by_headers(headers: &Value, body: &[u8]) -> DecodedBody {
    let Some(content_encoding) = header_value(headers, "content-encoding") else {
        return DecodedBody {
            bytes: body.to_vec(),
            content_encoding: None,
            decoded: false,
        };
    };

    match decode_by_content_encoding(&content_encoding, body) {
        Ok(bytes) => DecodedBody {
            bytes,
            content_encoding: Some(content_encoding),
            decoded: true,
        },
        Err(_) => DecodedBody {
            bytes: body.to_vec(),
            content_encoding: Some(content_encoding),
            decoded: false,
        },
    }
}

fn decode_by_content_encoding(content_encoding: &str, body: &[u8]) -> Result<Vec<u8>> {
    let mut current = body.to_vec();

    // Content-Encoding can be a stack, e.g. "br, gzip".
    // Decode in reverse application order.
    let encodings = content_encoding
        .split(',')
        .map(|encoding| encoding.trim().to_ascii_lowercase())
        .filter(|encoding| !encoding.is_empty())
        .collect::<Vec<_>>();

    for encoding in encodings.into_iter().rev() {
        current = match encoding.as_str() {
            "identity" => current,
            "gzip" => {
                let mut out = Vec::new();
                GzDecoder::new(current.as_slice())
                    .read_to_end(&mut out)
                    .context("decode gzip body")?;
                out
            }
            "deflate" => {
                let mut out = Vec::new();
                DeflateDecoder::new(current.as_slice())
                    .read_to_end(&mut out)
                    .context("decode deflate body")?;
                out
            }
            "br" => {
                let mut out = Vec::new();
                let mut decoder = brotli::Decompressor::new(current.as_slice(), 4096);
                decoder
                    .read_to_end(&mut out)
                    .context("decode brotli body")?;
                out
            }
            "zstd" => zstd::stream::decode_all(current.as_slice())
                .context("decode zstd body")?,
            _ => current,
        };
    }

    Ok(current)
}

pub fn header_value(headers: &Value, name: &str) -> Option<String> {
    let headers = normalize_headers(headers);
    let obj = headers.as_object()?;
    let value = obj.get(&name.to_ascii_lowercase())
        .or_else(|| {
            obj.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })?;

    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(values) => Some(
            values
                .iter()
                .filter_map(|value| match value {
                    Value::String(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
        other => Some(other.to_string()),
    }
}

fn normalize_headers(headers: &Value) -> Value {
    match headers {
        Value::String(s) => serde_json::from_str::<Value>(s).unwrap_or(Value::Null),
        other => other.clone(),
    }
}

pub fn format_body_for_display_with_headers(headers: &Value, body: &[u8]) -> String {
    let decoded = decode_body_by_headers(headers, body);
    format_body_for_display(&decoded.bytes)
}

pub fn format_body_for_har(headers: &Value, body: &[u8]) -> Value {
    let decoded = decode_body_by_headers(headers, body);
    let mime_type = header_value(headers, "content-type")
        .and_then(|value| value.split(';').next().map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty())
        .unwrap_or_default();

    let decoded_size = decoded.bytes.len() as i64;
    let body_size = body.len() as i64;
    let compression = (decoded_size - body_size).max(0);

    let mut content = serde_json::json!({
        "size": decoded_size,
        "mimeType": mime_type,
        "compression": compression,
    });

    if is_textual_content_type(headers) {
        match String::from_utf8(decoded.bytes) {
            Ok(text) => {
                content["text"] = Value::String(text);
            }
            Err(err) => {
                let bytes = err.into_bytes();
                content["text"] = Value::String(STANDARD.encode(bytes));
                content["encoding"] = Value::String("base64".to_string());
            }
        }
    } else {
        content["text"] = Value::String(STANDARD.encode(decoded.bytes));
        content["encoding"] = Value::String("base64".to_string());
    }

    content
}

fn is_textual_content_type(headers: &Value) -> bool {
    let Some(content_type) = header_value(headers, "content-type")
        .map(|value| value.to_ascii_lowercase()) else {
        return false;
    };

    content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("javascript")
        || content_type.contains("graphql")
        || content_type.contains("x-www-form-urlencoded")
}

pub fn format_body_for_display(bytes: &[u8]) -> String {
    if let Some(kind) = binary_magic_kind(bytes) {
        return format!("<binary body detected by magic number: {kind}>\n\n{}", hexdump_with_ascii(bytes));
    }

    if let Ok(text) = std::str::from_utf8(bytes)
        && looks_like_text(text) {
        if let Some(decoded_text) = decode_base64_text_for_display(text) {
            return format!("<base64 text decoded for display>\n\n{decoded_text}");
        }

        return text.to_string();
    }

    hexdump_with_ascii(bytes)
}

fn decode_base64_text_for_display(text: &str) -> Option<String> {
    let compact = text
        .split_whitespace()
        .collect::<String>();

    if !looks_like_base64_text(&compact) {
        return None;
    }

    let decoded = decode_base64_variants(&compact)?;
    let decoded_text = String::from_utf8(decoded).ok()?;

    if !looks_like_text(&decoded_text) {
        return None;
    }

    if !looks_like_useful_decoded_text(&decoded_text) {
        return None;
    }

    Some(decoded_text)
}

fn looks_like_base64_text(text: &str) -> bool {
    if text.len() < 64 {
        return false;
    }

    if text.len() % 4 == 1 {
        return false;
    }

    let mut base64_chars = 0usize;
    let mut padding_chars = 0usize;

    for ch in text.chars() {
        match ch {
            'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '+'
            | '/'
            | '-'
            | '_' => {
                base64_chars += 1;
            }
            '=' => {
                padding_chars += 1;
            }
            _ => return false,
        }
    }

    if padding_chars > 2 {
        return false;
    }

    base64_chars * 100 / text.len() >= 95
}

fn decode_base64_variants(text: &str) -> Option<Vec<u8>> {
    if let Ok(decoded) = STANDARD.decode(text) {
        return Some(decoded);
    }

    if let Ok(decoded) = STANDARD_NO_PAD.decode(text) {
        return Some(decoded);
    }

    if let Ok(decoded) = URL_SAFE.decode(text) {
        return Some(decoded);
    }

    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(text) {
        return Some(decoded);
    }

    let padded = base64_with_padding(text);

    if padded != text {
        if let Ok(decoded) = STANDARD.decode(&padded) {
            return Some(decoded);
        }

        if let Ok(decoded) = URL_SAFE.decode(&padded) {
            return Some(decoded);
        }
    }

    None
}

fn base64_with_padding(text: &str) -> String {
    match text.len() % 4 {
        0 => text.to_string(),
        2 => format!("{text}=="),
        3 => format!("{text}="),
        _ => text.to_string(),
    }
}

fn looks_like_useful_decoded_text(text: &str) -> bool {
    let trimmed = text.trim_start();

    trimmed.starts_with('{')
        || trimmed.starts_with('[')
        || trimmed.starts_with('<')
        || trimmed.contains('\n')
        || trimmed.contains("\r\n")
        || trimmed.contains(':')
        || trimmed.contains(',')
}

fn binary_magic_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some("png");
    }

    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("jpeg");
    }

    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("gif");
    }

    if bytes.starts_with(b"%PDF-") {
        return Some("pdf");
    }

    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08") {
        return Some("zip");
    }

    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some("gzip");
    }

    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some("zstd");
    }

    if bytes.starts_with(b"\x00asm") {
        return Some("wasm");
    }

    if bytes.starts_with(b"\x7fELF") {
        return Some("elf");
    }

    if bytes.starts_with(b"BM") {
        return Some("bmp");
    }

    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        return Some("webp");
    }

    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE") {
        return Some("wav");
    }

    if bytes.starts_with(b"OggS") {
        return Some("ogg");
    }

    if bytes.len() >= 12 && bytes.get(4..12) == Some(b"ftypavif") {
        return Some("avif");
    }

    if bytes.len() >= 12 && bytes.get(4..8) == Some(b"ftyp") {
        return Some("mp4");
    }

    None
}

fn looks_like_text(text: &str) -> bool {
    let mut total = 0usize;
    let mut control = 0usize;

    for ch in text.chars() {
        total += 1;

        if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
            control += 1;
        }
    }

    total == 0 || control * 100 / total <= 5
}

fn hexdump_with_ascii(bytes: &[u8]) -> String {
    const WIDTH: usize = 16;
    let mut out = String::new();

    for (line, chunk) in bytes.chunks(WIDTH).enumerate() {
        let offset = line * WIDTH;
        out.push_str(&format!("{offset:08x}  "));
        for i in 0..WIDTH {
            if i < chunk.len() {
                out.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                out.push_str("   ");
            }
            if i == 7 {
                out.push(' ');
            }
        }

        out.push_str(" |");
        for &b in chunk {
            let ch = match b {
                0x20..=0x7e => b as char,
                _ => '.',
            };
            out.push(ch);
        }
        for _ in chunk.len()..WIDTH {
            out.push(' ');
        }
        out.push('|');
        if offset + chunk.len() < bytes.len() {
            out.push('\n');
        }
    }
    out
}