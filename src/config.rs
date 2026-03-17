use std::{
    env, fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    str::FromStr,
};

use axum::http::Uri;
use clap::{Arg, ArgAction, Command};

use crate::util::{generate_csrf_token, now_string, resolve_relative_path};

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) root: PathBuf,
    pub(crate) index: bool,
    pub(crate) upload: Option<UploadConfig>,
    pub(crate) redirect_to: Option<String>,
    pub(crate) sort: bool,
    pub(crate) cache: bool,
    pub(crate) range: bool,
    pub(crate) cert: Option<PathBuf>,
    pub(crate) certpass: Option<String>,
    pub(crate) cors: bool,
    pub(crate) coop: bool,
    pub(crate) coep: bool,
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) upload_size_limit: u64,
    pub(crate) auth: Option<AuthConfig>,
    pub(crate) compress: Vec<String>,
    pub(crate) threads: usize,
    pub(crate) try_file_404: Option<PathBuf>,
    pub(crate) silent: bool,
    pub(crate) open: bool,
    pub(crate) base_url: String,
}

#[derive(Clone)]
pub(crate) struct UploadConfig {
    pub(crate) csrf_token: String,
}

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) username: String,
    pub(crate) password: String,
}

pub(crate) fn build_cli() -> Command {
    Command::new("simple-http-server")
        .display_name("Simple HTTP(s) Server")
        .bin_name("simple-http-server")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("root")
                .index(1)
                .value_parser(clap::builder::ValueParser::new(parse_existing_dir))
                .help("Root directory"),
        )
        .arg(
            Arg::new("index")
                .short('i')
                .long("index")
                .action(ArgAction::SetTrue)
                .help("Enable automatic render index page [index.html, index.htm]"),
        )
        .arg(
            Arg::new("upload")
                .short('u')
                .long("upload")
                .action(ArgAction::SetTrue)
                .help("Enable upload files. (multiple select) (CSRF token required)"),
        )
        .arg(
            Arg::new("csrf")
                .long("csrf")
                .value_name("TOKEN")
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("Use a custom CSRF token for upload. WARNING: this is dangerous as the token is passed via the command line and may be visible in process listings"),
        )
        .arg(
            Arg::new("redirect")
                .long("redirect")
                .value_name("URL")
                .value_parser(clap::builder::ValueParser::new(parse_redirect_url))
                .help("takes a URL to redirect to using HTTP 301 Moved Permanently"),
        )
        .arg(
            Arg::new("nosort")
                .long("nosort")
                .action(ArgAction::SetTrue)
                .help("Disable directory entries sort (by: name, modified, size)"),
        )
        .arg(
            Arg::new("nocache")
                .long("nocache")
                .action(ArgAction::SetTrue)
                .help("Disable http cache"),
        )
        .arg(
            Arg::new("norange")
                .long("norange")
                .action(ArgAction::SetTrue)
                .help("Disable header::Range support (partial request)"),
        )
        .arg(
            Arg::new("cert")
                .long("cert")
                .value_name("FILE")
                .value_parser(clap::builder::ValueParser::new(parse_existing_file))
                .help("TLS/SSL certificate (pkcs#12 format, requires tls feature)"),
        )
        .arg(
            Arg::new("cors")
                .long("cors")
                .action(ArgAction::SetTrue)
                .help("Enable CORS via the \"Access-Control-Allow-Origin\" header"),
        )
        .arg(
            Arg::new("coop")
                .long("coop")
                .action(ArgAction::SetTrue)
                .help("Add \"Cross-Origin-Opener-Policy\" HTTP header and set it to \"same-origin\""),
        )
        .arg(
            Arg::new("coep")
                .long("coep")
                .action(ArgAction::SetTrue)
                .help("Add \"Cross-Origin-Embedder-Policy\" HTTP header and set it to \"require-corp\""),
        )
        .arg(
            Arg::new("certpass")
                .long("certpass")
                .value_name("PASSWORD")
                .help("TLS/SSL certificate password (requires tls feature)"),
        )
        .arg(
            Arg::new("upload_size_limit")
                .short('l')
                .long("upload-size-limit")
                .value_name("SIZE")
                .default_value("8M")
                .value_parser(clap::builder::ValueParser::new(parse_upload_size_limit))
                .help("Upload file size limit [bytes, or K/M/G/T suffix interpreted with powers of 1024, such as 30K, 50M, 1G]"),
        )
        .arg(
            Arg::new("ip")
                .long("ip")
                .value_name("IP")
                .default_value("0.0.0.0")
                .value_parser(clap::builder::ValueParser::new(parse_ip_addr))
                .help("IP address to bind"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .default_value("8000")
                .value_parser(clap::builder::ValueParser::new(parse_port))
                .help("Port number"),
        )
        .arg(
            Arg::new("auth")
                .short('a')
                .long("auth")
                .value_name("USER:PASS")
                .value_parser(clap::builder::ValueParser::new(parse_auth_arg))
                .help("HTTP Basic Auth (username:password)"),
        )
        .arg(
            Arg::new("compress")
                .short('c')
                .long("compress")
                .value_name("EXT")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .num_args(1..)
                .help("Enable file compression: gzip/deflate\nExample: -c=js,d.ts\nNote: disabled on partial request!"),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("NUM")
                .default_value("3")
                .value_parser(clap::builder::ValueParser::new(parse_threads))
                .help("How many worker threads"),
        )
        .arg(
            Arg::new("try-file-404")
                .long("try-file")
                .visible_alias("try-file-404")
                .value_name("PATH")
                .value_parser(clap::builder::ValueParser::new(parse_try_file_arg))
                .help("Serve this file in place of missing paths. Relative paths are resolved against the server root; absolute paths are used as-is."),
        )
        .arg(
            Arg::new("silent")
                .short('s')
                .long("silent")
                .action(ArgAction::SetTrue)
                .help("Disable all outputs"),
        )
        .arg(
            Arg::new("open")
                .short('o')
                .long("open")
                .action(ArgAction::SetTrue)
                .help("Open the page in the default browser"),
        )
        .arg(
            Arg::new("base-url")
                .short('b')
                .long("base-url")
                .value_name("PATH")
                .default_value("/")
                .help("Base URL prefix for directory indexes and upload redirects. It is normalized to start with '/' and to end with '/' when not root."),
        )
}

pub(crate) fn build_config(matches: clap::ArgMatches) -> Result<Config, String> {
    let root = matches
        .get_one::<PathBuf>("root")
        .cloned()
        .map(|path| fs::canonicalize(path).map_err(|err| err.to_string()))
        .transpose()?
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let upload = if matches.get_flag("upload") {
        let csrf_token = if let Some(custom_token) = matches.get_one::<String>("csrf") {
            if !matches.get_flag("silent") {
                eprintln!(
                    "WARNING: Using a custom CSRF token is dangerous. The token is visible in process listings and shell history. Consider using the auto-generated token instead."
                );
            }
            custom_token.clone()
        } else {
            generate_csrf_token()?
        };

        Some(UploadConfig { csrf_token })
    } else {
        None
    };

    let auth = matches
        .get_one::<String>("auth")
        .map(|value| parse_auth(value))
        .transpose()?;

    let compress = matches
        .get_many::<String>("compress")
        .map(|values| values.map(|value| format!(".{value}")).collect())
        .unwrap_or_default();

    let try_file_404 = matches
        .get_one::<PathBuf>("try-file-404")
        .map(|path| resolve_try_file_path(&root, path))
        .transpose()?;

    let base_url = normalize_base_url(
        matches
            .get_one::<String>("base-url")
            .map(String::as_str)
            .unwrap_or("/"),
    )?;

    Ok(Config {
        root,
        index: matches.get_flag("index"),
        upload,
        redirect_to: matches.get_one::<String>("redirect").cloned(),
        sort: !matches.get_flag("nosort"),
        cache: !matches.get_flag("nocache"),
        range: !matches.get_flag("norange"),
        cert: matches.get_one::<PathBuf>("cert").cloned(),
        certpass: matches.get_one::<String>("certpass").cloned(),
        cors: matches.get_flag("cors"),
        coop: matches.get_flag("coop"),
        coep: matches.get_flag("coep"),
        ip: *matches
            .get_one::<IpAddr>("ip")
            .ok_or_else(|| "missing --ip".to_owned())?,
        port: *matches
            .get_one::<u16>("port")
            .ok_or_else(|| "missing --port".to_owned())?,
        upload_size_limit: *matches
            .get_one::<u64>("upload_size_limit")
            .ok_or_else(|| "missing --upload-size-limit".to_owned())?,
        auth,
        compress,
        threads: *matches
            .get_one::<usize>("threads")
            .ok_or_else(|| "missing --threads".to_owned())?,
        try_file_404,
        silent: matches.get_flag("silent"),
        open: matches.get_flag("open"),
        base_url,
    })
}

pub(crate) fn parse_auth(value: &str) -> Result<AuthConfig, String> {
    let mut parts = value.splitn(2, ':');
    let username = parts.next().unwrap_or_default();
    let password = parts.next().unwrap_or_default();

    if username.is_empty() {
        Err("no username found".to_owned())
    } else if password.is_empty() {
        Err("no password found".to_owned())
    } else {
        Ok(AuthConfig {
            username: username.to_owned(),
            password: password.to_owned(),
        })
    }
}

pub(crate) fn print_startup(config: &Config) {
    let compression = if config.compress.is_empty() {
        "disabled".to_owned()
    } else {
        format!(
            "{:?}",
            config
                .compress
                .iter()
                .map(|value| format!("*{value}"))
                .collect::<Vec<_>>()
        )
    };

    println!(
        "     Index: {}, Cache: {}, Cors: {}, Coop: {}, Coep: {}, Range: {}, Sort: {}, Threads: {}\n      Upload: {}, CSRF Token: {}\n        Auth: {}\n Compression: {}\n       HTTPS: {}, Cert: {}, Cert-Password: {}\n        Root: {}\n     BaseURL: {}\n  TryFile404: {}\n     Address: {}\n========== [{}] ==========",
        enable_string(config.index),
        enable_string(config.cache),
        enable_string(config.cors),
        enable_string(config.coop),
        enable_string(config.coep),
        enable_string(config.range),
        enable_string(config.sort),
        config.threads,
        enable_string(config.upload.is_some()),
        config
            .upload
            .as_ref()
            .map(|upload| upload.csrf_token.as_str())
            .unwrap_or(""),
        enable_string(config.auth.is_some()),
        compression,
        enable_string(config.cert.is_some()),
        config
            .cert
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        enable_string(config.certpass.is_some()),
        config.root.to_string_lossy(),
        config.base_url,
        config
            .try_file_404
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        if config.cert.is_some() {
            format!("https://{}", bind_addr_string(config.ip, config.port))
        } else {
            format!("http://{}", bind_addr_string(config.ip, config.port))
        },
        now_string()
    );
}

pub(crate) fn bind_addr_string(ip: IpAddr, port: u16) -> String {
    if ip.is_ipv4() {
        format!("{ip}:{port}")
    } else {
        format!("[{ip}]:{port}")
    }
}

pub(crate) fn enable_string(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

fn parse_existing_dir(value: &str) -> Result<PathBuf, String> {
    match fs::metadata(value) {
        Ok(metadata) if metadata.is_dir() => Ok(PathBuf::from(value)),
        Ok(_) => Err("Not directory".to_owned()),
        Err(err) => Err(err.to_string()),
    }
}

fn parse_existing_file(value: &str) -> Result<PathBuf, String> {
    match fs::metadata(value) {
        Ok(metadata) if metadata.is_file() => Ok(PathBuf::from(value)),
        Ok(_) => Err("Not a regular file".to_owned()),
        Err(err) => Err(err.to_string()),
    }
}

fn parse_try_file_arg(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() {
        Err("Path can not be empty".to_owned())
    } else {
        Ok(PathBuf::from(value))
    }
}

pub(crate) fn normalize_base_url(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("base-url can not be empty".to_owned());
    }

    let mut normalized = if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    };

    if normalized != "/" && !normalized.ends_with('/') {
        normalized.push('/');
    }

    Ok(normalized)
}

pub(crate) fn resolve_try_file_path(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        resolve_relative_path(root, path)?
    };

    match fs::metadata(&resolved) {
        Ok(metadata) if metadata.is_file() => {
            fs::canonicalize(&resolved).map_err(|err| err.to_string())
        }
        Ok(_) => Err("Not a file".to_owned()),
        Err(err) => Err(err.to_string()),
    }
}

fn parse_redirect_url(value: &str) -> Result<String, String> {
    let uri = Uri::from_str(value).map_err(|err| err.to_string())?;
    if uri.scheme_str().is_some() && uri.authority().is_some() {
        Ok(value.to_owned())
    } else {
        Err("URL must be absolute".to_owned())
    }
}

fn parse_ip_addr(value: &str) -> Result<IpAddr, String> {
    IpAddr::from_str(value).map_err(|err| err.to_string())
}

fn parse_port(value: &str) -> Result<u16, String> {
    value.parse::<u16>().map_err(|err| err.to_string())
}

fn parse_threads(value: &str) -> Result<usize, String> {
    match value.parse::<u8>() {
        Ok(0) => Err("Not positive number".to_owned()),
        Ok(value) => Ok(value as usize),
        Err(err) => Err(err.to_string()),
    }
}

fn parse_upload_size_limit(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("size limit can not be empty".to_owned());
    }

    let suffix_start = trimmed
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (number, suffix) = trimmed.split_at(suffix_start);

    if number.is_empty() {
        return Err("size limit must start with a number".to_owned());
    }

    let value = number.parse::<u64>().map_err(|err| err.to_string())?;
    let multiplier = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" => 1024,
        "M" | "MB" => 1024_u64.pow(2),
        "G" | "GB" => 1024_u64.pow(3),
        "T" | "TB" => 1024_u64.pow(4),
        _ => {
            return Err(
                "unsupported size suffix, use bytes or K/M/G/T suffixes with powers of 1024, for example 30K, 50M, 1G"
                    .to_owned(),
            );
        }
    };

    value
        .checked_mul(multiplier)
        .ok_or_else(|| "size limit is too large".to_owned())
}

fn parse_auth_arg(value: &str) -> Result<String, String> {
    parse_auth(value).map(|_| value.to_owned())
}

#[cfg(target_os = "windows")]
pub(crate) fn open_in_browser(url: &str) -> io::Result<()> {
    command_status(ProcessCommand::new("cmd").args(["/C", "start", "", url]))
}

#[cfg(target_os = "macos")]
pub(crate) fn open_in_browser(url: &str) -> io::Result<()> {
    command_status(ProcessCommand::new("open").arg(url))
}

#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn open_in_browser(url: &str) -> io::Result<()> {
    command_status(ProcessCommand::new("xdg-open").arg(url))
}

#[cfg(not(any(unix, target_os = "windows")))]
pub(crate) fn open_in_browser(_url: &str) -> io::Result<()> {
    Err(io::Error::other(
        "opening a browser is not supported on this platform",
    ))
}

fn command_status(command: &mut ProcessCommand) -> io::Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("command exited with {status}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_base_url() {
        assert_eq!(normalize_base_url("/").unwrap(), "/");
        assert_eq!(normalize_base_url("prefix").unwrap(), "/prefix/");
        assert_eq!(normalize_base_url("/prefix").unwrap(), "/prefix/");
        assert_eq!(normalize_base_url("/prefix/").unwrap(), "/prefix/");
    }

    #[test]
    fn resolves_root_relative_try_file() {
        let root = make_temp_dir();
        let nested = root.join("assets");
        fs::create_dir_all(&nested).unwrap();
        let file = nested.join("404.html");
        fs::write(&file, "not found").unwrap();

        let resolved = resolve_try_file_path(&root, Path::new("assets/404.html")).unwrap();
        assert_eq!(resolved, fs::canonicalize(file).unwrap());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_try_file_that_escapes_root() {
        let root = make_temp_dir();
        let outside = root.parent().unwrap().join("outside-file.txt");
        fs::write(&outside, "outside").unwrap();

        let err = resolve_try_file_path(&root, Path::new("../outside-file.txt")).unwrap_err();
        assert_eq!(err, "Permission Denied");

        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_upload_size_limit_with_suffixes() {
        assert_eq!(parse_upload_size_limit("30K").unwrap(), 30 * 1024);
        assert_eq!(parse_upload_size_limit("50m").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_upload_size_limit("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_upload_size_limit("42").unwrap(), 42);
        assert_eq!(parse_upload_size_limit("2kb").unwrap(), 2 * 1024);
    }

    #[test]
    fn rejects_invalid_upload_size_limit_suffix() {
        let err = parse_upload_size_limit("1KiB").unwrap_err();
        assert_eq!(
            err,
            "unsupported size suffix, use bytes or K/M/G/T suffixes with powers of 1024, for example 30K, 50M, 1G"
        );
    }

    fn make_temp_dir() -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "simple-http-server-test-{}-{}",
            std::process::id(),
            generate_csrf_token().unwrap()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
