use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTHOST_GIT_COMMIT");
    emit_git_rerun_hints();

    println!(
        "cargo:rustc-env=RUSTHOST_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_else(|_| String::from("unknown"))
    );
    println!(
        "cargo:rustc-env=RUSTHOST_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| String::from("unknown"))
    );
    println!(
        "cargo:rustc-env=RUSTHOST_GIT_COMMIT={}",
        resolve_git_commit().unwrap_or_else(|| String::from("unknown"))
    );
}

fn emit_git_rerun_hints() {
    let git_path = Path::new(".git");
    if git_path.is_file() {
        println!("cargo:rerun-if-changed={}", git_path.display());
    }

    let Some(git_dir) = resolve_git_dir(git_path) else {
        return;
    };

    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());

    if let Ok(head_contents) = fs::read_to_string(&head_path) {
        if let Some(reference) = head_contents.strip_prefix("ref: ").map(str::trim) {
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join(reference).display()
            );
        }
    }

    let packed_refs = git_dir.join("packed-refs");
    if packed_refs.exists() {
        println!("cargo:rerun-if-changed={}", packed_refs.display());
    }
}

fn resolve_git_commit() -> Option<String> {
    env::var("RUSTHOST_GIT_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(git_rev_parse_head)
}

fn git_rev_parse_head() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let commit = String::from_utf8(output.stdout).ok()?;
    let trimmed = commit.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn resolve_git_dir(git_path: &Path) -> Option<PathBuf> {
    if git_path.is_dir() {
        return Some(git_path.to_path_buf());
    }

    let git_file = fs::read_to_string(git_path).ok()?;
    let path = git_file.strip_prefix("gitdir: ")?.trim();
    let resolved = Path::new(path);
    Some(if resolved.is_absolute() {
        resolved.to_path_buf()
    } else {
        git_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(resolved)
    })
}
