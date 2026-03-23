//! # MIME Type Mapping
//!
//! **Directory:** `src/server/`
//!
//! Maps file extensions to MIME type strings.  Unknown extensions fall
//! back to `application/octet-stream` so the browser offers a download
//! rather than attempting to display binary data.

/// Return the MIME type string for a given lowercase file extension.
///
/// # Examples
/// ```
/// use rusthost::server::mime;
/// assert_eq!(mime::for_extension("html"), "text/html; charset=utf-8");
/// assert_eq!(mime::for_extension("xyz"),  "application/octet-stream");
/// ```
#[must_use]
pub fn for_extension(ext: &str) -> &'static str {
    // 3.4 — Normalise to lowercase in a fixed stack buffer to avoid a heap
    // allocation on every served file request. Extensions longer than 16 bytes
    // are not in the table, so we short-circuit to the fallback immediately.
    let bytes = ext.as_bytes();
    let mut buf = [0u8; 16];
    if bytes.len() > buf.len() {
        return "application/octet-stream";
    }
    // Use zip to avoid any index that could theoretically panic under clippy's
    // indexing_slicing lint; the length guard above already guarantees safety.
    for (slot, &b) in buf.iter_mut().zip(bytes.iter()) {
        *slot = b.to_ascii_lowercase();
    }
    // get() instead of a bare slice to satisfy clippy::indexing_slicing.
    let lower = std::str::from_utf8(buf.get(..bytes.len()).unwrap_or_default()).unwrap_or("");
    match lower {
        // Text
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "txt" | "wat" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "xml" => "text/xml; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",

        // Data
        "json" | "map" => "application/json",
        "jsonld" => "application/ld+json",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "zip" => "application/zip",

        // Images
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "avif" => "image/avif",

        // Fonts
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",

        // Audio / Video
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        // Modern audio (M-14)
        "opus" => "audio/opus",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "m4a" => "audio/mp4",
        // Modern video (M-14)
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",

        // Web app manifest — required for PWA installation (M-14)
        "webmanifest" => "application/manifest+json",

        // 3D / WebGL (M-14)
        "glb" => "model/gltf-binary",
        "gltf" => "model/gltf+json",

        // Data formats (M-14)
        "ndjson" => "application/x-ndjson",
        "geojson" => "application/geo+json",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",

        // Web fonts — additional (M-14)
        "eot" => "application/vnd.ms-fontobject",

        // Fallback
        _ => "application/octet-stream",
    }
}
