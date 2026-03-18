use std::{
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::HeaderValue;
use time::{OffsetDateTime, UtcOffset, macros::format_description};

#[cfg(not(unix))]
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hash, Hasher},
};

#[cfg(unix)]
use std::io::Read;

const CSRF_TOKEN_LEN: usize = 10;

pub(crate) fn resolve_relative_path(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let mut result = root.to_path_buf();
    for component in path.components() {
        match component {
            Component::Normal(part) => result.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("Permission Denied".to_owned());
            }
        }
    }

    if result.starts_with(root) {
        Ok(result)
    } else {
        Err("Permission Denied".to_owned())
    }
}

pub(crate) fn decode_request_path(path: &str) -> Result<Vec<String>, String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let decoded = percent_decode_bytes(segment, false);
            String::from_utf8(decoded).map_err(|_err| format!("invalid path: {segment}"))
        })
        .collect()
}

pub(crate) fn percent_decode_lossy(value: &str, plus_as_space: bool) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(value, plus_as_space)).into_owned()
}

fn percent_decode_bytes(value: &str, plus_as_space: bool) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' if plus_as_space => {
                result.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                {
                    result.push(high << 4 | low);
                    index += 3;
                } else {
                    result.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                result.push(byte);
                index += 1;
            }
        }
    }

    result
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn encode_link_path(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| percent_encode_path_segment(part))
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            result.push(byte as char);
        } else {
            result.push('%');
            result.push(hex_char(byte >> 4));
            result.push(hex_char(byte & 0x0f));
        }
    }
    result
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => '0',
    }
}

pub(crate) fn root_link(base_url: &str) -> String {
    format!("<a href=\"{base_url}\"><strong>[Root]</strong></a>")
}

pub(crate) fn escape_html(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(ch),
        }
    }
    result
}

pub(crate) fn human_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = size as f64;
    let mut unit = 0usize;

    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{size} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub(crate) fn now_string() -> String {
    format_local_time(SystemTime::now())
}

pub(crate) fn format_local_time(time: SystemTime) -> String {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    OffsetDateTime::from(time)
        .to_offset(offset)
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
        .unwrap_or_else(|_| "1970-01-01 00:00:00".to_owned())
}

pub(crate) fn truncate_to_second(time: SystemTime) -> SystemTime {
    let (secs, _) = system_time_parts(time);
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs((-secs) as u64)
    }
}

pub(crate) fn system_time_parts(time: SystemTime) -> (i64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, 0),
        Err(error) => {
            let duration = error.duration();
            if duration.subsec_nanos() == 0 {
                (-(duration.as_secs() as i64), 0)
            } else {
                (-(duration.as_secs() as i64) - 1, 0)
            }
        }
    }
}

pub(crate) fn fmt_http_date(time: SystemTime) -> String {
    httpdate::fmt_http_date(time)
}

pub(crate) fn path_matches_compression(path: &Path, exts: &[String]) -> bool {
    let path = path.to_string_lossy();
    exts.iter().any(|ext| path.ends_with(ext))
}

pub(crate) fn upload_redirect_target(base_url: &str, request_path: &str) -> String {
    if base_url == "/" {
        request_path.to_owned()
    } else {
        format!("{}{}", base_url, request_path.trim_start_matches('/'))
    }
}

pub(crate) fn header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub(crate) fn generate_csrf_token() -> Result<String, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; CSRF_TOKEN_LEN];
    fill_random_bytes(&mut bytes)?;

    let mut token = String::with_capacity(CSRF_TOKEN_LEN);
    for byte in bytes {
        token.push(ALPHABET[(byte as usize) % ALPHABET.len()] as char);
    }
    Ok(token)
}

fn fill_random_bytes(bytes: &mut [u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut file = std::fs::File::open("/dev/urandom").map_err(|err| err.to_string())?;
        file.read_exact(bytes).map_err(|err| err.to_string())?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let mut filled = 0usize;
        let seed_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        while filled < bytes.len() {
            let mut hasher = RandomState::new().build_hasher();
            seed_time.hash(&mut hasher);
            std::process::id().hash(&mut hasher);
            filled.hash(&mut hasher);

            let block = hasher.finish().to_le_bytes();
            let count = (bytes.len() - filled).min(block.len());
            bytes[filled..filled + count].copy_from_slice(&block[..count]);
            filled += count;
        }

        Ok(())
    }
}
