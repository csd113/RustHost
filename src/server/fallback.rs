//! # Fallback Page
//!
//! **Directory:** `src/server/`
//!
//! The built-in HTML page served when `./data/site/index.html` is missing
//! and directory listing is disabled.  Served with HTTP 200 so the browser
//! shows a helpful message rather than an error screen.

/// HTML content of the built-in "no site" page.
pub const NO_SITE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>No site found — RustHost</title>
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
    code {
      background: #f1f0ec;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.9em;
    }
    .dim { color: #999; font-size: 0.875rem; margin-top: 1.5rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>No site found</h1>
    <p>
      RustHost is running, but there are no files to serve yet.
    </p>
    <p>
      Drop your HTML, CSS, and assets into
      <code>./data/site/</code>, then press
      <kbd>R</kbd> in the RustHost dashboard to reload.
    </p>
    <p class="dim">RustHost — single-binary hosting appliance</p>
  </div>
</body>
</html>
"#;
