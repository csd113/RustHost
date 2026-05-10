use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use rusthost::config::Config;
use tokio::io::{AsyncRead, AsyncReadExt as _};

pub fn reserve_port_for(bind_addr: IpAddr) -> Result<u16, std::io::Error> {
    let listener = std::net::TcpListener::bind(SocketAddr::new(bind_addr, 0))?;
    Ok(listener.local_addr()?.port())
}

pub fn reserve_port() -> Result<u16, std::io::Error> {
    reserve_port_for(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

pub fn response_to_str(raw: &[u8]) -> Result<&str, Box<dyn std::error::Error>> {
    std::str::from_utf8(raw)
        .map_err(|e| format!("response contained non-UTF-8 bytes (error: {e}):\n{raw:?}").into())
}

pub fn status_code(raw: &[u8]) -> Result<u16, Box<dyn std::error::Error>> {
    let text = response_to_str(raw)?;
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line in response:\n{text}").into())
}

pub fn header_value(raw: &[u8], name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let needle = format!("{}:", name.to_ascii_lowercase());
    let text = response_to_str(raw)?;
    Ok(text
        .lines()
        .skip(1)
        .find(|line| line.to_ascii_lowercase().starts_with(&needle))
        .and_then(|line| {
            line.split_once(':')
                .map(|(_, value)| value.trim().to_owned())
        }))
}

#[allow(dead_code)]
pub fn body_bytes(raw: &[u8]) -> Result<&[u8], Box<dyn std::error::Error>> {
    let text = response_to_str(raw)?;
    let sep = text
        .find("\r\n\r\n")
        .ok_or("response missing header terminator")?;
    Ok(raw
        .get(sep + 4..)
        .ok_or("response body slice out of bounds")?)
}

pub fn build_test_config(
    site_root: &Path,
    bind_addr: IpAddr,
    port: u16,
) -> Result<Config, Box<dyn std::error::Error>> {
    use std::num::NonZeroU16;

    let dir_name = site_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("site_root must have a valid UTF-8 directory name")?
        .to_owned();

    let mut config = Config::default();
    config.server.port =
        NonZeroU16::new(port).ok_or("reserve_port() returned port 0, which is invalid")?;
    config.server.bind = bind_addr;
    config.server.auto_port_fallback = false;
    config.server.open_browser_on_start = false;
    config.site.directory = dir_name;
    config.site.index_file = "index.html".into();
    config.tor.enabled = false;
    config.console.interactive = false;
    Ok(config)
}

fn find_header_end(buf: &[u8], search_from: usize) -> Option<usize> {
    let tail = buf.get(search_from..)?;
    let pos = tail.windows(4).position(|window| window == b"\r\n\r\n")?;
    Some(search_from.saturating_add(pos).saturating_add(4))
}

pub async fn read_headers_only<S>(stream: &mut S) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut staging = [0u8; 4096];

    loop {
        let search_from = buf.len().saturating_sub(3);
        let n = stream.read(&mut staging).await?;
        if n == 0 {
            return Err("connection closed before \\r\\n\\r\\n header terminator".into());
        }
        buf.extend_from_slice(
            staging
                .get(..n)
                .ok_or("read returned more bytes than the staging buffer can hold")?,
        );
        if let Some(end) = find_header_end(&buf, search_from) {
            buf.truncate(end);
            return Ok(buf);
        }
    }
}

pub async fn read_one_response<S>(stream: &mut S) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut staging = [0u8; 4096];
    let header_end;

    loop {
        let search_from = buf.len().saturating_sub(3);
        let n = stream.read(&mut staging).await?;
        if n == 0 {
            return Err("connection closed before \\r\\n\\r\\n header terminator".into());
        }
        buf.extend_from_slice(
            staging
                .get(..n)
                .ok_or("read returned more bytes than the staging buffer can hold")?,
        );
        if let Some(end) = find_header_end(&buf, search_from) {
            header_end = end;
            break;
        }
    }

    let header_bytes = buf.get(..header_end).ok_or("header_end is out of bounds")?;
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| format!("response headers are not valid UTF-8: {e}"))?;

    let status: u16 = header_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    let content_length: usize = header_str
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split_once(':').map(|parts| parts.1))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);

    let has_body = content_length > 0 && !matches!(status, 204 | 304);

    if !has_body {
        buf.truncate(header_end);
        return Ok(buf);
    }

    let already_have = buf.len().saturating_sub(header_end);
    let total_needed = header_end
        .checked_add(content_length)
        .ok_or("Content-Length value causes usize overflow")?;

    if already_have < content_length {
        buf.resize(total_needed, 0);
        let fill_start = header_end
            .checked_add(already_have)
            .ok_or("fill_start overflows usize")?;
        let body_slice = buf
            .get_mut(fill_start..total_needed)
            .ok_or("body slice range is out of bounds")?;
        stream.read_exact(body_slice).await?;
    } else {
        buf.truncate(total_needed);
    }

    Ok(buf)
}
