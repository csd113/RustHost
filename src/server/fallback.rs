//! # Fallback Page
//!
//! **File:** `fallback.rs`
//! **Location:** `src/server/fallback.rs`
//!
//! The built-in HTML page served when `./data/site/index.html` is missing
//! and directory listing is disabled.  Served with HTTP 200 so the browser
//! shows a helpful message rather than an error screen.

/// HTML content of the built-in "no content" page.
///
/// the previous version named `RustHost` explicitly, allowing
/// adversaries scanning the Tor network to fingerprint the software and look up
/// version-specific CVEs.  A generic message gives away nothing about the
/// implementation.  The HTTP status is also changed to 503 (see `handler.rs`
/// fallback arm) so the response is not cached or indexed as a live endpoint.
pub const NO_SITE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>No content available</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #f7f7f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      color: #1a1a1a;
    }
    .card {
      background: #fff;
      border: 1px solid #e0e0da;
      border-radius: 12px;
      padding: 2.5rem 3rem;
      max-width: 520px;
      width: 90%;
    }
    h1   { font-size: 1.25rem; font-weight: 500; margin-bottom: 1rem; }
    p    { color: #555; line-height: 1.7; margin-bottom: 0.75rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>No content available</h1>
    <p>This server is running but no content has been configured yet.</p>
  </div>
</body>
</html>
"#;
