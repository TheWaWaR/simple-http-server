use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    mem,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, Bytes},
    extract::{FromRequest, Multipart, Query, Request, State, connect_info::ConnectInfo},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use flate2::{
    Compression,
    write::{DeflateEncoder, GzEncoder},
};
use http_body::{Frame, SizeHint};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::{
    config::{Config, parse_auth},
    server::PeerAddr,
    util::{
        decode_request_path, encode_link_path, escape_html, fmt_http_date, format_local_time,
        generate_csrf_token, header_value, human_size, now_string, path_matches_compression,
        percent_decode_lossy, resolve_relative_path, root_link, system_time_parts,
        truncate_to_second, upload_redirect_target,
    },
};

const ORDER_ASC: &str = "asc";
const ORDER_DESC: &str = "desc";
const DEFAULT_ORDER: &str = ORDER_DESC;
const SORT_FIELDS: &[&str] = &["name", "modified", "size"];
const FILE_CHUNK_SIZE: usize = 64 * 1024;
const BODY_CHANNEL_CAPACITY: usize = 8;

struct AppError {
    status: StatusCode,
    message: String,
}

struct DirectoryEntry {
    filename: String,
    metadata: fs::Metadata,
}

struct PendingUpload {
    temp_path: PathBuf,
    final_path: PathBuf,
}

#[derive(Clone)]
struct RequestMeta {
    method: Method,
    headers: HeaderMap,
}

#[derive(Deserialize)]
struct DirectoryQuery {
    sort: Option<String>,
    order: Option<String>,
}

#[derive(Clone, Copy)]
enum CompressionEncoding {
    Gzip,
    Deflate,
}

#[derive(Clone)]
struct EntityTag {
    weak: bool,
    tag: String,
}

struct ChannelBody {
    receiver: mpsc::Receiver<io::Result<Bytes>>,
    exact_len: Option<u64>,
}

struct ChannelWriter {
    sender: mpsc::Sender<io::Result<Bytes>>,
    buffer: Vec<u8>,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn from_io(err: io::Error) -> Self {
        let status = match err.kind() {
            io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
            io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::new(status, err.to_string())
    }
}

impl EntityTag {
    fn strong_eq(&self, other: &Self) -> bool {
        !self.weak && !other.weak && self.tag == other.tag
    }

    fn weak_eq(&self, other: &Self) -> bool {
        self.tag == other.tag
    }

    fn header_value(&self) -> String {
        if self.weak {
            format!("W/\"{}\"", self.tag)
        } else {
            format!("\"{}\"", self.tag)
        }
    }
}

impl ChannelBody {
    fn new(receiver: mpsc::Receiver<io::Result<Bytes>>, exact_len: Option<u64>) -> Self {
        Self {
            receiver,
            exact_len,
        }
    }
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll_recv(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        let mut size_hint = SizeHint::new();
        if let Some(len) = self.exact_len {
            size_hint.set_exact(len);
        }
        size_hint
    }
}

impl ChannelWriter {
    fn new(sender: mpsc::Sender<io::Result<Bytes>>) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(FILE_CHUNK_SIZE),
        }
    }

    fn finish(mut self) -> io::Result<()> {
        self.flush_buffer(true)
    }

    fn flush_buffer(&mut self, force: bool) -> io::Result<()> {
        while self.buffer.len() >= FILE_CHUNK_SIZE {
            let remainder = self.buffer.split_off(FILE_CHUNK_SIZE);
            let chunk = mem::replace(&mut self.buffer, remainder);
            self.send_chunk(chunk)?;
        }

        if force && !self.buffer.is_empty() {
            let chunk = mem::take(&mut self.buffer);
            self.send_chunk(chunk)?;
        }

        Ok(())
    }

    fn send_chunk(&self, chunk: Vec<u8>) -> io::Result<()> {
        self.sender
            .blocking_send(Ok(Bytes::from(chunk)))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "response body dropped"))
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        self.flush_buffer(false)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer(true)
    }
}

pub(crate) async fn handle_request(
    State(config): State<Arc<Config>>,
    ConnectInfo(remote_addr): ConnectInfo<PeerAddr>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let path_for_log = percent_decode_lossy(req.uri().path(), false);

    let mut response = match handle_request_inner(config.clone(), req).await {
        Ok(response) => response,
        Err(err) => {
            if !config.silent && err.status.is_server_error() {
                eprintln!(
                    "[{}] - {} - {} - {} {} - {}",
                    now_string(),
                    remote_addr.0.ip(),
                    err.status.as_u16(),
                    method,
                    path_for_log,
                    err.message
                );
            }
            error_response(err.status, &err.message, &config.base_url)
        }
    };

    if config.cors {
        apply_cors_headers(response.headers_mut());
    }

    if !config.silent {
        println!(
            "[{}] - {} - {} - {} {}",
            now_string(),
            remote_addr.0.ip(),
            response.status().as_u16(),
            method,
            path_for_log
        );
    }

    response
}

async fn handle_request_inner(config: Arc<Config>, req: Request) -> Result<Response, AppError> {
    let request_meta = RequestMeta {
        method: req.method().clone(),
        headers: req.headers().clone(),
    };

    if let Some(response) = authorize(config.as_ref(), &request_meta.headers)? {
        return Ok(response);
    }

    if config.cors && request_meta.method == Method::OPTIONS {
        return Ok(no_content_response());
    }

    if let Some(location) = &config.redirect_to {
        return Ok(redirect_response(StatusCode::MOVED_PERMANENTLY, location));
    }

    let path_segments = decode_request_path(req.uri().path())
        .map_err(|message| AppError::new(StatusCode::BAD_REQUEST, message))?;
    let relative_path = build_relative_path(&path_segments);
    let fs_path = resolve_relative_path(&config.root, &relative_path)
        .map_err(|message| AppError::new(StatusCode::FORBIDDEN, message))?;

    if config.upload.is_some() && request_meta.method == Method::POST {
        let request_path = req.uri().path().to_owned();
        if !is_multipart_request(&request_meta.headers) {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "The request is not multipart",
            ));
        }

        save_files(config.as_ref(), req, &fs_path).await?;
        let redirect_target = upload_redirect_target(&config.base_url, &request_path);
        return Ok(redirect_response(StatusCode::FOUND, &redirect_target));
    }

    let metadata = match fs::metadata(&fs_path) {
        Ok(metadata) => metadata,
        Err(err) => match err.kind() {
            io::ErrorKind::NotFound => {
                if let Some(path) = &config.try_file_404
                    && matches!(fs::metadata(path), Ok(metadata) if metadata.is_file())
                {
                    return send_file(
                        config.as_ref(),
                        &request_meta,
                        path,
                        Some(StatusCode::NOT_FOUND),
                        request_meta.method == Method::HEAD,
                    )
                    .await;
                }
                return Err(AppError::from_io(err));
            }
            _ => return Err(AppError::from_io(err)),
        },
    };

    if metadata.is_dir() {
        let directory_query = Query::<DirectoryQuery>::try_from_uri(req.uri())
            .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, err.body_text()))?;
        list_directory(
            config.as_ref(),
            &request_meta,
            &directory_query.0,
            &fs_path,
            &path_segments,
            request_meta.method == Method::HEAD,
        )
        .await
    } else {
        send_file(
            config.as_ref(),
            &request_meta,
            &fs_path,
            None,
            request_meta.method == Method::HEAD,
        )
        .await
    }
}

fn authorize(config: &Config, headers: &HeaderMap) -> Result<Option<Response>, AppError> {
    let Some(auth) = &config.auth else {
        return Ok(None);
    };

    let Some(header_value) = headers.get(header::AUTHORIZATION) else {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"main\""),
        );
        return Ok(Some(response));
    };

    let Ok(header_value) = header_value.to_str() else {
        return Ok(Some(text_response(
            StatusCode::UNAUTHORIZED,
            "Wrong username or password.",
        )));
    };

    let Some(encoded) = header_value.strip_prefix("Basic ") else {
        return Ok(Some(text_response(
            StatusCode::UNAUTHORIZED,
            "Wrong username or password.",
        )));
    };

    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|err| AppError::new(StatusCode::UNAUTHORIZED, err.to_string()))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|err| AppError::new(StatusCode::UNAUTHORIZED, err.to_string()))?;

    let parsed =
        parse_auth(&decoded).map_err(|err| AppError::new(StatusCode::UNAUTHORIZED, err))?;
    if parsed.username == auth.username && parsed.password == auth.password {
        Ok(None)
    } else {
        Ok(Some(text_response(
            StatusCode::UNAUTHORIZED,
            "Wrong username or password.",
        )))
    }
}

fn text_response(status: StatusCode, body: &str) -> Response {
    build_response(
        status,
        "text/plain; charset=utf-8",
        body.as_bytes().to_vec(),
        false,
        None,
    )
}

fn no_content_response() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
}

fn redirect_response(status: StatusCode, location: &str) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn error_response(status: StatusCode, message: &str, base_url: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n</head>\n<body>\n  {}\n  <hr />\n  <div>[<strong style=color:red;>ERROR {}</strong>]: {}</div>\n</body>\n</html>\n",
        root_link(base_url),
        status.as_u16(),
        escape_html(message)
    );
    build_response(
        status,
        "text/html; charset=utf-8",
        html.into_bytes(),
        false,
        None,
    )
}

fn apply_cors_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, HEAD, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
}

fn is_multipart_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.starts_with("multipart/form-data"))
        .unwrap_or(false)
}

async fn save_files(config: &Config, req: Request, path: &Path) -> Result<(), AppError> {
    let mut multipart = Multipart::from_request(req, &())
        .await
        .map_err(|err| multipart_rejection_to_error(config, err))?;

    let mut csrf_value = None;
    let mut files = Vec::new();

    while let Some(field) = match multipart.next_field().await {
        Ok(field) => field,
        Err(err) => {
            cleanup_pending_uploads(&files);
            return Err(multipart_error_to_error(config, err));
        }
    } {
        let field_name = field.name().unwrap_or_default().to_owned();

        if field_name == "csrf" {
            csrf_value = Some(match field.text().await {
                Ok(text) => text,
                Err(err) => {
                    cleanup_pending_uploads(&files);
                    return Err(multipart_error_to_error(config, err));
                }
            });
            continue;
        }

        if field_name != "files" {
            continue;
        }

        let Some(raw_filename) = field.file_name().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(filename) = Path::new(&raw_filename).file_name() else {
            continue;
        };

        let final_path = path.join(filename);
        let temp_path = build_upload_temp_path(path)?;
        let mut temp_file = match tokio::fs::File::create(&temp_path).await {
            Ok(file) => file,
            Err(err) => {
                cleanup_pending_uploads(&files);
                return Err(AppError::from_io(err));
            }
        };
        let mut field = field;
        while let Some(chunk) = match field.chunk().await {
            Ok(chunk) => chunk,
            Err(err) => {
                let _ = fs::remove_file(&temp_path);
                cleanup_pending_uploads(&files);
                return Err(multipart_error_to_error(config, err));
            }
        } {
            temp_file.write_all(&chunk).await.map_err(|err| {
                let _ = fs::remove_file(&temp_path);
                cleanup_pending_uploads(&files);
                AppError::from_io(err)
            })?;
        }
        temp_file.flush().await.map_err(|err| {
            let _ = fs::remove_file(&temp_path);
            cleanup_pending_uploads(&files);
            AppError::from_io(err)
        })?;

        files.push(PendingUpload {
            temp_path,
            final_path,
        });
    }

    let Some(upload) = &config.upload else {
        cleanup_pending_uploads(&files);
        return Err(AppError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "Upload is not enabled",
        ));
    };

    let token = csrf_value.ok_or_else(|| {
        cleanup_pending_uploads(&files);
        AppError::new(StatusCode::BAD_REQUEST, "csrf parameter not provided")
    })?;

    if token != upload.csrf_token {
        cleanup_pending_uploads(&files);
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "csrf token does not match",
        ));
    }

    if files.is_empty() {
        cleanup_pending_uploads(&files);
        return Err(AppError::new(StatusCode::BAD_REQUEST, "no files provided"));
    }

    for pending in files {
        if pending.final_path.exists() {
            fs::remove_file(&pending.final_path).map_err(AppError::from_io)?;
        }
        fs::rename(&pending.temp_path, &pending.final_path).map_err(|err| {
            let _ = fs::remove_file(&pending.temp_path);
            AppError::from_io(err)
        })?;
    }

    Ok(())
}

fn multipart_rejection_to_error(
    config: &Config,
    err: axum::extract::multipart::MultipartRejection,
) -> AppError {
    let status = err.status();
    AppError::new(
        status,
        format_multipart_error(config, status, err.body_text()),
    )
}

fn multipart_error_to_error(
    config: &Config,
    err: axum::extract::multipart::MultipartError,
) -> AppError {
    let status = err.status();
    AppError::new(
        status,
        format_multipart_error(config, status, err.body_text()),
    )
}

fn format_multipart_error(config: &Config, status: StatusCode, body_text: String) -> String {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        format!(
            "upload size exceeds limit (max {})",
            human_size(config.upload_size_limit)
        )
    } else {
        body_text
    }
}

fn build_upload_temp_path(path: &Path) -> Result<PathBuf, AppError> {
    for _ in 0..16 {
        let token = generate_csrf_token()
            .map_err(|err| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        let candidate = path.join(format!(".simple-http-upload-{token}.part"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(AppError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to allocate temporary upload path",
    ))
}

fn cleanup_pending_uploads(files: &[PendingUpload]) {
    for pending in files {
        let _ = fs::remove_file(&pending.temp_path);
    }
}

async fn list_directory(
    config: &Config,
    request: &RequestMeta,
    query: &DirectoryQuery,
    fs_path: &Path,
    path_prefix: &[String],
    head_only: bool,
) -> Result<Response, AppError> {
    let mut entries = Vec::new();
    let read_dir = fs::read_dir(fs_path).map_err(AppError::from_io)?;
    for entry_result in read_dir {
        let entry = entry_result.map_err(AppError::from_io)?;
        entries.push(DirectoryEntry {
            filename: entry.file_name().to_string_lossy().into_owned(),
            metadata: entry.metadata().map_err(AppError::from_io)?,
        });
    }

    let breadcrumb = if !path_prefix.is_empty() {
        let mut remaining = path_prefix.to_vec();
        let mut links = vec![escape_html(remaining.pop().unwrap_or_default().as_str())];
        while !remaining.is_empty() {
            let label = remaining.pop().unwrap_or_default();
            let mut link_prefix = remaining.clone();
            link_prefix.push(label.clone());
            links.push(format!(
                "<a href=\"{}{}\"><strong>{}</strong></a>",
                config.base_url,
                encode_link_path(&link_prefix),
                escape_html(&label)
            ));
        }
        links.push(root_link(&config.base_url));
        links.reverse();
        links.join(" / ")
    } else {
        root_link(&config.base_url)
    };

    let sort_links = if config.sort {
        let order = query
            .order
            .clone()
            .unwrap_or_else(|| DEFAULT_ORDER.to_owned());
        let field = query.sort.clone().unwrap_or_else(|| "name".to_owned());

        if !SORT_FIELDS.contains(&field.as_str()) {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                format!("Unknown sort field: {field}"),
            ));
        }

        if order != ORDER_ASC && order != ORDER_DESC {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                format!("Unknown sort order: {order}"),
            ));
        }

        let reverse = order == ORDER_DESC;
        entries.sort_by(|left, right| {
            let ordering = match field.as_str() {
                "name" => left.filename.cmp(&right.filename),
                "modified" => left
                    .metadata
                    .modified()
                    .unwrap_or(UNIX_EPOCH)
                    .cmp(&right.metadata.modified().unwrap_or(UNIX_EPOCH)),
                "size" => {
                    if left.metadata.is_dir() == right.metadata.is_dir()
                        || left.metadata.is_file() == right.metadata.is_file()
                    {
                        left.metadata.len().cmp(&right.metadata.len())
                    } else if left.metadata.is_dir() {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                }
                _ => Ordering::Equal,
            };

            if reverse {
                ordering.reverse()
            } else {
                ordering
            }
        });

        let mut next_orders = BTreeMap::new();
        for sort_field in SORT_FIELDS {
            if *sort_field == field && order == ORDER_DESC {
                next_orders.insert(*sort_field, ORDER_ASC);
            }
        }

        let mut current_link = path_prefix.to_vec();
        current_link.push(String::new());

        format!(
            "\n<tr>\n  <th><a href=\"{}{}?sort=name&order={}\">Name</a></th>\n  <th><a href=\"{}{}?sort=modified&order={}\">Last modified</a></th>\n  <th><a href=\"{}{}?sort=size&order={}\">Size</a></th>\n</tr>\n<tr><td style=\"border-top:1px dashed #BBB;\" colspan=\"5\"></td></tr>\n",
            config.base_url,
            encode_link_path(&current_link),
            next_orders.get("name").copied().unwrap_or(DEFAULT_ORDER),
            config.base_url,
            encode_link_path(&current_link),
            next_orders
                .get("modified")
                .copied()
                .unwrap_or(DEFAULT_ORDER),
            config.base_url,
            encode_link_path(&current_link),
            next_orders.get("size").copied().unwrap_or(DEFAULT_ORDER),
        )
    } else {
        String::new()
    };

    let mut rows = Vec::new();

    if !path_prefix.is_empty() {
        let mut link = path_prefix.to_vec();
        link.pop();
        if !link.is_empty() {
            link.push(String::new());
        }
        rows.push(format!(
            "\n<tr>\n  <td><a href=\"{}{}\"><strong>[Up]</strong></a></td>\n  <td></td>\n  <td></td>\n</tr>\n",
            config.base_url,
            encode_link_path(&link),
        ));
    } else {
        rows.push("<tr><td>&nbsp;</td></tr>".to_owned());
    }

    for entry in entries {
        if config.index && (entry.filename == "index.html" || entry.filename == "index.htm") {
            return send_file(
                config,
                request,
                &fs_path.join(&entry.filename),
                None,
                head_only,
            )
            .await;
        }

        let mut link = path_prefix.to_vec();
        link.push(entry.filename.clone());
        if entry.metadata.is_dir() {
            link.push(String::new());
        }

        let label = if entry.metadata.is_dir() {
            format!("{}/", entry.filename)
        } else {
            entry.filename.clone()
        };

        rows.push(format!(
            "\n<tr>\n  <td><a {} href=\"{}{}\">{}</a></td>\n  <td style=\"color:#888;\">[{}]</td>\n  <td><bold>{}</bold></td>\n</tr>\n",
            if entry.metadata.is_dir() {
                "style=\"font-weight: bold;\""
            } else {
                ""
            },
            config.base_url,
            encode_link_path(&link),
            escape_html(&label),
            format_local_time(entry.metadata.modified().unwrap_or(UNIX_EPOCH)),
            if entry.metadata.is_dir() {
                "-".to_owned()
            } else {
                human_size(entry.metadata.len())
            },
        ));
    }

    let upload_form = config
        .upload
        .as_ref()
        .map(|upload| {
            format!(
                "\n<form style=\"margin-top:1em; margin-bottom:1em;\" action=\"{}{}\" method=\"POST\" enctype=\"multipart/form-data\">\n  <input type=\"file\" name=\"files\" accept=\"*\" multiple />\n  <input type=\"hidden\" name=\"csrf\" value=\"{}\"/>\n  <input type=\"submit\" value=\"Upload\" />\n</form>\n",
                config.base_url,
                encode_link_path(path_prefix),
                escape_html(&upload.csrf_token),
            )
        })
        .unwrap_or_default();

    let html = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no\"/>\n  <style> a {{ text-decoration:none; }} </style>\n</head>\n<body>\n  {upload_form}\n  <div>{breadcrumb}</div>\n  <hr />\n  <table>\n    {sort_links}\n    {rows}\n  </table>\n</body>\n</html>\n",
        upload_form = upload_form,
        breadcrumb = breadcrumb,
        sort_links = sort_links,
        rows = rows.join("\n"),
    );

    let encoding = if !config.compress.is_empty() {
        preferred_encoding(&request.headers)
    } else {
        None
    };

    let body = if let Some(encoding) = encoding {
        compress_bytes(html.as_bytes(), encoding).map_err(AppError::from_io)?
    } else {
        html.into_bytes()
    };

    Ok(build_response(
        StatusCode::OK,
        "text/html; charset=utf-8",
        body,
        head_only,
        encoding,
    ))
}

async fn send_file(
    config: &Config,
    request: &RequestMeta,
    path: &Path,
    status_override: Option<StatusCode>,
    head_only: bool,
) -> Result<Response, AppError> {
    let metadata = fs::metadata(path).map_err(AppError::from_io)?;
    let modified = truncate_to_second(metadata.modified().unwrap_or(UNIX_EPOCH));
    let etag = build_etag(metadata.len(), modified);
    let mime = mime_guess::from_path(path).first_or_octet_stream();

    if config.cache
        && let Some(header_value) = request.headers.get(header::IF_MODIFIED_SINCE)
        && let Ok(value) = header_value.to_str()
        && let Ok(date) = httpdate::parse_http_date(value)
        && modified <= date
    {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        return Ok(response);
    }

    let method = &request.method;
    if *method != Method::GET && *method != Method::HEAD {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(response);
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = status_override.unwrap_or(StatusCode::OK);
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, header_value(mime.essence_str()));

    if config.range {
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }

    if config.coop {
        response.headers_mut().insert(
            header::HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        );
    }

    if config.coep {
        response.headers_mut().insert(
            header::HeaderName::from_static("cross-origin-embedder-policy"),
            HeaderValue::from_static("require-corp"),
        );
    }

    if config.cache {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=604800"),
        );
        response.headers_mut().insert(
            header::LAST_MODIFIED,
            header_value(&fmt_http_date(modified)),
        );
        response
            .headers_mut()
            .insert(header::ETAG, header_value(&etag.header_value()));
    }

    if head_only {
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            header_value(&metadata.len().to_string()),
        );
        return Ok(response);
    }

    let mut requested_range = None;
    if config.range {
        let if_match_passes = if_match_passes(&request.headers, &etag)?;
        if request.headers.contains_key(header::RANGE) && !if_match_passes {
            return Err(AppError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "Etag not matched",
            ));
        }

        if if_range_matches(&request.headers, &etag, modified)? {
            requested_range = parse_range_header(&request.headers, metadata.len())?;
        }
    }

    let partial_range = requested_range.map(|(offset, length)| (offset, offset + length - 1));
    if let Some((start, end)) = partial_range {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            header_value(&format!("bytes {start}-{end}/{}", metadata.len())),
        );
    }

    let compression = if requested_range.is_none()
        && metadata.len() > 256
        && path_matches_compression(path, &config.compress)
    {
        preferred_encoding(&request.headers)
    } else {
        None
    };

    if let Some(encoding) = compression {
        let file = fs::File::open(path).map_err(AppError::from_io)?;
        response.headers_mut().insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(match encoding {
                CompressionEncoding::Gzip => "gzip",
                CompressionEncoding::Deflate => "deflate",
            }),
        );
        *response.body_mut() = Body::new(spawn_compressed_body(file, encoding));
        return Ok(response);
    }

    let mut file = fs::File::open(path).map_err(AppError::from_io)?;
    let body_len = if let Some((offset, length)) = requested_range {
        file.seek(SeekFrom::Start(offset))
            .map_err(AppError::from_io)?;
        length
    } else {
        metadata.len()
    };

    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, header_value(&body_len.to_string()));
    *response.body_mut() = Body::new(spawn_file_body(file, body_len));

    Ok(response)
}

fn spawn_file_body(mut file: fs::File, body_len: u64) -> ChannelBody {
    let (sender, receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);

    thread::spawn(move || {
        let mut remaining = body_len;
        let mut buffer = vec![0u8; FILE_CHUNK_SIZE];

        while remaining > 0 {
            let limit = remaining.min(FILE_CHUNK_SIZE as u64) as usize;
            match file.read(&mut buffer[..limit]) {
                Ok(0) => break,
                Ok(read) => {
                    remaining -= read as u64;
                    if sender
                        .blocking_send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    let _ = sender.blocking_send(Err(err));
                    break;
                }
            }
        }
    });

    ChannelBody::new(receiver, Some(body_len))
}

fn spawn_compressed_body(file: fs::File, encoding: CompressionEncoding) -> ChannelBody {
    let (sender, receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
    let error_sender = sender.clone();

    thread::spawn(move || {
        let result = compress_file_to_channel(file, sender, encoding);
        if let Err(err) = result {
            let _ = error_sender.blocking_send(Err(err));
        }
    });

    ChannelBody::new(receiver, None)
}

fn compress_file_to_channel(
    file: fs::File,
    sender: mpsc::Sender<io::Result<Bytes>>,
    encoding: CompressionEncoding,
) -> io::Result<()> {
    let mut reader = BufReader::new(file);
    let writer = ChannelWriter::new(sender);

    match encoding {
        CompressionEncoding::Gzip => {
            let mut encoder = GzEncoder::new(writer, Compression::default());
            io::copy(&mut reader, &mut encoder)?;
            encoder.finish()?.finish()?;
        }
        CompressionEncoding::Deflate => {
            let mut encoder = DeflateEncoder::new(writer, Compression::default());
            io::copy(&mut reader, &mut encoder)?;
            encoder.finish()?.finish()?;
        }
    }

    Ok(())
}

fn preferred_encoding(headers: &HeaderMap) -> Option<CompressionEncoding> {
    let value = headers.get(header::ACCEPT_ENCODING)?.to_str().ok()?;
    for part in value.split(',') {
        let encoding = part.split(';').next().unwrap_or_default().trim();
        if encoding.eq_ignore_ascii_case("gzip") {
            return Some(CompressionEncoding::Gzip);
        }
        if encoding.eq_ignore_ascii_case("deflate") {
            return Some(CompressionEncoding::Deflate);
        }
    }
    None
}

fn compress_bytes(data: &[u8], encoding: CompressionEncoding) -> io::Result<Vec<u8>> {
    match encoding {
        CompressionEncoding::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            encoder.finish()
        }
        CompressionEncoding::Deflate => {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            encoder.finish()
        }
    }
}

fn parse_range_header(headers: &HeaderMap, file_len: u64) -> Result<Option<(u64, u64)>, AppError> {
    let Some(value) = headers.get(header::RANGE) else {
        return Ok(None);
    };

    let value = value
        .to_str()
        .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;

    let Some(range_set) = value.strip_prefix("bytes=") else {
        return Err(AppError::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "Invalid range type",
        ));
    };

    let first = range_set
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Empty range set"))?;

    let (start, end) = first
        .split_once('-')
        .ok_or_else(|| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Invalid range type"))?;

    if !start.is_empty() && !end.is_empty() {
        let start = start
            .parse::<u64>()
            .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;
        let mut end = end
            .parse::<u64>()
            .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;

        if start >= file_len || start > end {
            return Err(AppError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                format!("Invalid range(x={start}, y={end})"),
            ));
        }

        if end >= file_len {
            end = file_len - 1;
        }

        return Ok(Some((start, end - start + 1)));
    }

    if !start.is_empty() {
        let start = start
            .parse::<u64>()
            .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;

        if start >= file_len {
            return Err(AppError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                format!("Range::AllFrom to large (x={start}), Content-Length: {file_len})"),
            ));
        }

        return Ok(Some((start, file_len - start)));
    }

    let mut last = end
        .parse::<u64>()
        .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;
    if last > file_len {
        last = file_len;
    }
    Ok(Some((file_len - last, last)))
}

fn if_match_passes(headers: &HeaderMap, current: &EntityTag) -> Result<bool, AppError> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Ok(true);
    };

    let value = value
        .to_str()
        .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;

    if value.trim() == "*" {
        return Ok(true);
    }

    for item in value.split(',') {
        let parsed = parse_entity_tag(item.trim())?;
        if current.strong_eq(&parsed) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn if_range_matches(
    headers: &HeaderMap,
    current: &EntityTag,
    modified: SystemTime,
) -> Result<bool, AppError> {
    let Some(value) = headers.get(header::IF_RANGE) else {
        return Ok(true);
    };

    let value = value
        .to_str()
        .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;

    if value.starts_with('"') || value.starts_with("W/\"") {
        let parsed = parse_entity_tag(value)?;
        Ok(current.weak_eq(&parsed))
    } else {
        let date = httpdate::parse_http_date(value)
            .map_err(|err| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, err.to_string()))?;
        Ok(modified <= date)
    }
}

fn parse_entity_tag(value: &str) -> Result<EntityTag, AppError> {
    let trimmed = value.trim();
    let (weak, raw_tag) = if let Some(stripped) = trimmed.strip_prefix("W/") {
        (true, stripped)
    } else {
        (false, trimmed)
    };

    let tag = raw_tag
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Invalid entity tag"))?;

    Ok(EntityTag {
        weak,
        tag: tag.to_owned(),
    })
}

fn build_etag(len: u64, modified: SystemTime) -> EntityTag {
    let (secs, nanos) = system_time_parts(modified);
    EntityTag {
        weak: true,
        tag: format!("{len:x}-{secs:x}.{nanos:x}"),
    }
}

fn build_response(
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    head_only: bool,
    encoding: Option<CompressionEncoding>,
) -> Response {
    let len = body.len();
    let mut response = if head_only {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(body))
    };
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, header_value(content_type));
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, header_value(&len.to_string()));

    if let Some(encoding) = encoding {
        response.headers_mut().insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(match encoding {
                CompressionEncoding::Gzip => "gzip",
                CompressionEncoding::Deflate => "deflate",
            }),
        );
    }

    response
}

fn build_relative_path(segments: &[String]) -> PathBuf {
    let mut path = PathBuf::new();
    for segment in segments {
        path.push(segment);
    }
    path
}
