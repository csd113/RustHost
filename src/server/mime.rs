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
/// assert_eq!(mime::for_extension("html"), "text/html; charset=utf-8");
/// assert_eq!(mime::for_extension("xyz"),  "application/octet-stream");
/// ```
pub fn for_extension(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        // Text
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "xml" => "text/xml; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",

        // Data
        "json" => "application/json",
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
        "mp4" => "video/mp4",
        "webm" => "video/webm",

        // Fallback
        _ => "application/octet-stream",
    }
}
