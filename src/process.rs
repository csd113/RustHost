//! Bounded execution for small administrative helpers, never a shell command.
use std::{
    io,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

pub fn run_bounded(command: &mut Command, timeout: Duration) -> io::Result<ExitStatus> {
    // Null streams avoid blocked pipes and unbounded captured helper output.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "administrative helper timed out",
                ))
            }
            Err(error) => break Err(error),
        }
    };
    // Always reap after timeout/error. An uninterruptible OS process is still
    // a platform limitation; no safe portable API can forcibly bound wait().
    let _ = child.kill();
    let _ = child.wait();
    result
}
