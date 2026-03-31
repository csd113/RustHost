//! # Handler Path Helpers
//!
//! **File:** `pathing.rs`
//! **Location:** `src/server/handler/pathing.rs`

use std::{
    borrow::Cow,
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::CustomErrorPage;

const MAX_DIRECTORY_LISTING_ENTRIES: usize = 512;

pub(super) fn cache_control_for(content_type: &str, path: &str) -> &'static str {
    if content_type.starts_with("text/html") {
        return "no-store";
    }
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if is_hashed_asset(file_name) {
        "max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

pub fn is_hashed_asset(name: &str) -> bool {
    name.split('.')
        .any(|seg| (8..=16).contains(&seg.len()) && seg.chars().all(|c| c.is_ascii_hexdigit()))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut stack: Vec<std::path::Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if matches!(stack.last(), Some(std::path::Component::Normal(_))) {
                    stack.pop();
                }
            }
            std::path::Component::CurDir => {}
            c => stack.push(c),
        }
    }
    stack.iter().collect()
}

pub fn resolved_path_has_dotfile(resolved: &Path, root: &Path) -> bool {
    resolved
        .strip_prefix(root)
        .unwrap_or(resolved)
        .components()
        .any(|c| {
            matches!(c, std::path::Component::Normal(name)
                if name.to_str().is_some_and(|s| s.starts_with('.')))
        })
}

#[derive(Debug, PartialEq)]
pub(super) enum Resolved {
    File(PathBuf),
    NotFound,
    Fallback,
    Forbidden,
    DirectoryListing(PathBuf),
    Redirect(String),
    CustomError(Arc<CustomErrorPage>),
}

pub(super) struct ResolveOptions<'a> {
    pub canonical_root: &'a Path,
    pub url_path: &'a str,
    pub index_file: &'a str,
    pub dir_listing: bool,
    pub expose_dotfiles: bool,
    pub spa_routing: bool,
    pub error_404_page: Option<Arc<CustomErrorPage>>,
}

#[must_use]
pub(super) fn resolve_path(opts: &ResolveOptions<'_>) -> Resolved {
    let ResolveOptions {
        canonical_root,
        url_path,
        index_file,
        dir_listing,
        expose_dotfiles,
        spa_routing,
        error_404_page,
    } = opts;
    let dir_listing = *dir_listing;
    let expose_dotfiles = *expose_dotfiles;
    let spa_routing = *spa_routing;

    if !expose_dotfiles {
        for component in Path::new(url_path).components() {
            if let std::path::Component::Normal(name) = component {
                if name.to_str().is_some_and(|s| s.starts_with('.')) {
                    return Resolved::Forbidden;
                }
            }
        }
    }

    let relative = url_path.trim_start_matches('/');
    let candidate = canonical_root.join(relative);

    let target = if candidate.is_dir() {
        if !url_path.ends_with('/') {
            return Resolved::Redirect(format!("{url_path}/"));
        }
        let idx = candidate.join(index_file);
        if idx.exists() {
            idx
        } else if dir_listing {
            return Resolved::DirectoryListing(candidate);
        } else {
            return Resolved::Fallback;
        }
    } else {
        candidate
    };

    let Ok(canonical) = target.canonicalize() else {
        if !canonical_root.exists() {
            return Resolved::Fallback;
        }
        let normalized = normalize_path(&target);
        return if normalized.starts_with(canonical_root) {
            resolve_not_found(
                canonical_root,
                index_file,
                spa_routing,
                error_404_page.as_ref(),
            )
        } else {
            Resolved::Forbidden
        };
    };

    if !canonical.starts_with(canonical_root) {
        return Resolved::Forbidden;
    }

    if !expose_dotfiles && resolved_path_has_dotfile(&canonical, canonical_root) {
        return Resolved::Forbidden;
    }

    Resolved::File(canonical)
}

fn resolve_not_found(
    canonical_root: &Path,
    index_file: &str,
    spa_routing: bool,
    error_404_page: Option<&Arc<CustomErrorPage>>,
) -> Resolved {
    if spa_routing {
        let spa_index = canonical_root.join(index_file);
        if spa_index.exists() {
            match spa_index.canonicalize() {
                Ok(resolved) if resolved.starts_with(canonical_root) => {
                    return Resolved::File(resolved);
                }
                Ok(resolved) => {
                    log::warn!(
                        "Refusing SPA fallback outside the site root: {}",
                        resolved.display()
                    );
                    return Resolved::Forbidden;
                }
                Err(_) => {
                    return Resolved::NotFound;
                }
            }
        }
    }

    if let Some(page) = error_404_page {
        return Resolved::CustomError(Arc::clone(page));
    }
    Resolved::NotFound
}

pub(super) fn sanitize_header_value(s: &str) -> Cow<'_, str> {
    if s.chars().any(|c| c.is_ascii_control()) {
        Cow::Owned(s.chars().filter(|c| !c.is_ascii_control()).collect())
    } else {
        Cow::Borrowed(s)
    }
}

pub(super) fn build_directory_listing(dir: &Path, url_path: &str, expose_dotfiles: bool) -> String {
    let mut items = String::new();
    let mut truncated = false;

    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                if expose_dotfiles || !name.starts_with('.') {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        names.sort();
        if names.len() > MAX_DIRECTORY_LISTING_ENTRIES {
            names.truncate(MAX_DIRECTORY_LISTING_ENTRIES);
            truncated = true;
        }

        let base = html_escape(url_path.trim_end_matches('/'));
        for name in &names {
            let encoded_name = percent_encode_path(name);
            let escaped_name = html_escape(name);
            let _ = writeln!(
                items,
                "  <li><a href=\"{base}/{encoded_name}\">{escaped_name}</a></li>"
            );
        }
    }

    let escaped_path = html_escape(url_path);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Index of {escaped_path}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 700px;
            margin: 2rem auto; padding: 0 1rem; }}
    li   {{ line-height: 1.8; }}
  </style>
</head>
<body>
  <h2>Index of {escaped_path}</h2>
  {truncation_notice}
  <ul>
{items}  </ul>
</body>
</html>
"#,
        truncation_notice = if truncated {
            "<p>Directory listing truncated to the first 512 entries.</p>"
        } else {
            ""
        }
    )
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[must_use]
pub fn percent_decode(input: &str) -> String {
    use percent_encoding::percent_decode_str;

    percent_decode_str(input)
        .decode_utf8()
        .ok()
        .and_then(|decoded| {
            if decoded.contains('\0') {
                None
            } else {
                Some(decoded.into_owned())
            }
        })
        .unwrap_or_else(|| input.to_owned())
}
