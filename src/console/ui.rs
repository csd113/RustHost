use std::fmt::Write as _;
use std::net::IpAddr;

pub const RULE: &str = "──────────────────────────────────────────────────────────";

#[must_use]
pub fn green(s: &str) -> String {
    format!("\x1b[32m{s}\x1b[0m")
}

#[must_use]
pub fn yellow(s: &str) -> String {
    format!("\x1b[33m{s}\x1b[0m")
}

#[must_use]
pub fn red(s: &str) -> String {
    format!("\x1b[31m{s}\x1b[0m")
}

#[must_use]
pub fn dim(s: &str) -> String {
    format!("\x1b[2m{s}\x1b[0m")
}

#[must_use]
pub fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}

pub fn push_header(out: &mut String, title: &str) {
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {}\r", bold(title));
    let _ = writeln!(out, "{RULE}\r");
}

pub fn push_controls_footer(out: &mut String, controls: &str) {
    let _ = writeln!(out, "{RULE}\r");
    out.push_str(controls);
    out.push_str("\r\n");
    let _ = writeln!(out, "{RULE}\r");
}

#[must_use]
pub fn local_http_url(bind_addr: IpAddr, port: u16) -> String {
    match bind_addr {
        IpAddr::V4(addr) if addr.is_unspecified() => {
            format!("http://127.0.0.1:{port}")
        }
        IpAddr::V6(addr) if addr.is_unspecified() => {
            format!("http://[::1]:{port}")
        }
        IpAddr::V6(addr) => format!("http://[{addr}]:{port}"),
        IpAddr::V4(addr) => format!("http://{addr}:{port}"),
    }
}

#[must_use]
pub fn local_https_url(bind_addr: IpAddr, port: u16) -> String {
    match bind_addr {
        IpAddr::V4(addr) if addr.is_unspecified() => omit_default_https_port("127.0.0.1", port),
        IpAddr::V6(addr) if addr.is_unspecified() => omit_default_https_port("[::1]", port),
        IpAddr::V6(addr) => omit_default_https_port(&format!("[{addr}]"), port),
        IpAddr::V4(addr) => omit_default_https_port(&addr.to_string(), port),
    }
}

fn omit_default_https_port(host: &str, port: u16) -> String {
    if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    }
}
