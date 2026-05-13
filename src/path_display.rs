use std::{
    borrow::Cow,
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

const DISPLAY_ROOT: &str = "rusthost-data";

/// Format paths for UI output.
///
/// When a path contains the `rusthost-data` directory, trim any leading parent
/// segments so displays start at that folder. Paths outside that tree keep
/// their original form.
#[must_use]
pub fn display_path(path: &Path) -> Cow<'_, str> {
    let mut trimmed = PathBuf::new();
    let mut found_root = false;

    for component in path.components() {
        if found_root {
            trimmed.push(component.as_os_str());
            continue;
        }

        if matches!(component, Component::Normal(name) if name == OsStr::new(DISPLAY_ROOT)) {
            found_root = true;
            trimmed.push(component.as_os_str());
        }
    }

    if found_root {
        Cow::Owned(trimmed.display().to_string())
    } else {
        path.to_string_lossy()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::display_path;

    #[test]
    fn trims_leading_segments_before_rusthost_data() {
        let path = Path::new("/Users/example/Desktop/rusthost-data/site");

        assert_eq!(display_path(path), "rusthost-data/site");
    }

    #[test]
    fn keeps_paths_without_rusthost_data_unchanged() {
        let path = Path::new("/tmp/custom-data/site");

        assert_eq!(display_path(path), "/tmp/custom-data/site");
    }
}
