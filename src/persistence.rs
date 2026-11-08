//! Publication of small application-owned files in a trusted directory.
//!
//! A stable OS lock serializes writers (including other processes). The fixed
//! staging name is reclaimed only under that lock, including after a crash.
//! Publication never truncates the live file. A post-publication sync error is
//! reported as an error, but the visible file may already be the new generation.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

pub struct Directory {
    path: PathBuf,
    _lock: File,
}

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        create_dir_all(path)?;
        #[cfg(unix)]
        for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(ancestor)?;
        }
        let lock_path = path.join(".rusthost-persist.lock");
        reject_special(&lock_path)?;
        let lock = private_options()
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        // Fail promptly on contention; callers can retry without blocking shutdown.
        lock.try_lock().map_err(io::Error::other)?;
        let dir = Self {
            path: path.to_owned(),
            _lock: lock,
        };
        dir.clean_stage()?;
        Ok(dir)
    }

    fn clean_stage(&self) -> io::Result<()> {
        match std::fs::remove_file(self.path.join(".rusthost-persist.tmp")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn write(
        &mut self,
        name: impl AsRef<std::ffi::OsStr>,
        contents: &[u8],
        replace: bool,
    ) -> io::Result<bool> {
        self.stage(name.as_ref(), replace, |file| file.write_all(contents))
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Exclusive access serializes use of the single staging filename within this process."
    )]
    fn stage(
        &mut self,
        name: &std::ffi::OsStr,
        replace: bool,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<bool> {
        if name == ".rusthost-persist.lock"
            || name == ".rusthost-persist.tmp"
            || Path::new(name).components().count() != 1
            || !matches!(
                Path::new(name).components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid persistent filename",
            ));
        }
        let target = self.path.join(name);
        let temporary = self.path.join(".rusthost-persist.tmp");
        let result = (|| {
            if replace {
                reject_special(&target)?;
            }
            let mut file = private_options().create_new(true).open(&temporary)?;
            write(&mut file)?;
            file.sync_all()?;
            drop(file);
            if replace {
                std::fs::rename(&temporary, &target)?;
            } else {
                // hard_link is an atomic no-clobber publication of the synced inode.
                match std::fs::hard_link(&temporary, &target) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
                    Err(e) => return Err(e),
                }
            }
            #[cfg(unix)]
            sync_dir(&self.path)?;
            Ok(true)
        })();
        let cleanup = self.clean_stage();
        result.and_then(|published| cleanup.map(|()| published))
    }
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

fn reject_special(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "persistent path is not a regular file",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    reject_special(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "persistent path is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persistent file exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub fn create_dir_all(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        sync_dir(path)?;
        sync_dir(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        )?;
    }
    Ok(())
}

// std has no portable directory flush on Windows. File contents are synced;
// power-loss durability of the rename needs platform-specific validation.
#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub fn create_default(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid default filename"))?;
    Directory::open(parent)?.write(name, contents, false)?;
    Ok(())
}
