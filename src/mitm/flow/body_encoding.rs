use std::io::Read;

use bytes::Bytes;
use flate2::read;
use http::{HeaderMap, HeaderValue};

pub(crate) fn decoded_body_or_raw(headers: &HeaderMap, body: &Bytes) -> Bytes {
    decode_content_encoded_body(headers, body).unwrap_or_else(|| {
        decode_body_by_magic_number(body).unwrap_or_else(|| body.clone())
    })
}

pub(crate) fn decode_content_encoded_body(headers: &HeaderMap, body: &Bytes) -> Option<Bytes> {
    let content_encoding = headers.get(http::header::CONTENT_ENCODING)?;
    decode_by_content_encoding_header(content_encoding, body)
}

pub(crate) fn decode_by_content_encoding_header(
    header_value: &HeaderValue,
    body: &Bytes,
) -> Option<Bytes> {
    let encoding = header_value
        .to_str()
        .ok()?
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    match encoding.as_str() {
        "" | "identity" => Some(body.clone()),
        "gzip" | "x-gzip" => {
            let mut buf = Vec::new();
            read::GzDecoder::new(body.as_ref())
                .read_to_end(&mut buf)
                .ok()?;
            Some(Bytes::from(buf))
        }
        "deflate" => {
            let mut buf = Vec::new();
            read::DeflateDecoder::new(body.as_ref())
                .read_to_end(&mut buf)
                .ok()?;
            Some(Bytes::from(buf))
        }
        "br" => {
            let mut buf = Vec::new();
            let mut decoder = brotli::Decompressor::new(body.as_ref(), 4096);
            decoder.read_to_end(&mut buf).ok()?;
            Some(Bytes::from(buf))
        }
        "zstd" => zstd::stream::decode_all(body.as_ref())
            .ok()
            .map(Bytes::from),
        _ => None,
    }
}

pub(crate) fn decode_body_by_magic_number(body: &Bytes) -> Option<Bytes> {
    let bytes = body.as_ref();

    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut buf = Vec::new();
        read::GzDecoder::new(bytes).read_to_end(&mut buf).ok()?;
        return Some(Bytes::from(buf));
    }

    None
}

pub(crate) fn body_file_name(base: &str, headers: &HeaderMap) -> String {
    let suffixes = content_encoding_suffixes(headers);

    if suffixes.is_empty() {
        base.to_string()
    } else {
        format!("{base}.{}", suffixes.join("."))
    }
}

pub(crate) fn content_encoding_suffixes(headers: &HeaderMap) -> Vec<&'static str> {
    let Some(content_encoding) = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
    else {
        return Vec::new();
    };

    content_encoding
        .split(',')
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter_map(|encoding| match encoding.as_str() {
            "gzip" | "x-gzip" => Some("gz"),
            "br" => Some("br"),
            "zstd" => Some("zst"),
            "deflate" => Some("deflate"),
            "identity" => None,
            _ => None,
        })
        .collect()
}