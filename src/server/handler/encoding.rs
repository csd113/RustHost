//! # Handler Encoding Helpers
//!
//! **File:** `encoding.rs`
//! **Location:** `src/server/handler/encoding.rs`

use hyper::{header, Request};

/// Encoding negotiated from `Accept-Encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Brotli,
    Gzip,
    Identity,
}

const MIN_COMPRESS_BYTES: u64 = 1_024;

/// Choose the best encoding the client accepts.
///
/// Prefers Brotli (superior compression ratio) over Gzip.
/// Returns `Identity` when neither is offered or the header is absent.
pub(super) fn best_encoding<B>(req: &Request<B>) -> Encoding {
    let Some(accept) = req.headers().get(header::ACCEPT_ENCODING) else {
        return Encoding::Identity;
    };
    let Ok(s) = accept.to_str() else {
        return Encoding::Identity;
    };
    let wildcard_q = encoding_quality(s, "*");
    let br_q = encoding_quality(s, "br").or(wildcard_q);
    let gzip_q = encoding_quality(s, "gzip").or(wildcard_q);
    let identity_q = encoding_quality(s, "identity").or(Some(1_000));
    let br_q = br_q.unwrap_or(0);
    let gzip_q = gzip_q.unwrap_or(0);
    let identity_q = identity_q.unwrap_or(0);

    if br_q > 0 && br_q >= gzip_q && br_q >= identity_q {
        Encoding::Brotli
    } else if gzip_q > 0 && gzip_q >= identity_q {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

fn encoding_quality(header_value: &str, name: &str) -> Option<u16> {
    header_value
        .split(',')
        .filter_map(parse_accept_encoding_part)
        .find_map(|(encoding, quality)| encoding.eq_ignore_ascii_case(name).then_some(quality))
}

fn parse_accept_encoding_part(part: &str) -> Option<(&str, u16)> {
    let mut segments = part.trim().split(';');
    let encoding = segments.next()?.trim();
    if encoding.is_empty() {
        return None;
    }

    let mut quality = 1_000u16;
    for parameter in segments {
        let (key, value) = parameter.trim().split_once('=')?;
        if key.trim().eq_ignore_ascii_case("q") {
            quality = parse_quality_value(value.trim())?;
        }
    }

    Some((encoding, quality))
}

fn parse_quality_value(raw: &str) -> Option<u16> {
    let (whole, fractional) = raw.split_once('.').map_or((raw, ""), |parts| parts);
    match whole {
        "0" => {
            let mut thousandths = 0u16;
            let mut seen = 0usize;
            for ch in fractional.chars().take(3) {
                let digit = ch.to_digit(10)?;
                thousandths = thousandths.saturating_mul(10);
                thousandths = thousandths.saturating_add(u16::try_from(digit).ok()?);
                seen = seen.saturating_add(1);
            }
            let scale = 3usize.saturating_sub(seen);
            Some(thousandths.saturating_mul(10u16.saturating_pow(u32::try_from(scale).ok()?)))
        }
        "1" => {
            if fractional.chars().all(|c| c == '0') {
                Some(1_000)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(super) fn should_compress(content_type: &str, file_len: u64) -> bool {
    if file_len < MIN_COMPRESS_BYTES {
        return false;
    }

    is_compressible_content_type(content_type)
}

pub(super) fn is_compressible_content_type(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || matches!(
            content_type,
            "application/json"
                | "application/ld+json"
                | "application/manifest+json"
                | "application/x-ndjson"
                | "application/geo+json"
                | "application/toml"
                | "application/yaml"
                | "application/wasm"
                | "image/svg+xml"
        )
}
