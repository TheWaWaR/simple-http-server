use std::{io, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    extract::{DefaultBodyLimit, connect_info::Connected},
    routing::any,
    serve::{IncomingStream, Listener},
};
use tokio::net::TcpListener;

#[cfg(feature = "tls")]
use std::{pin::Pin, time::Duration};

#[cfg(feature = "tls")]
use openssl::{
    pkcs12::Pkcs12,
    ssl::{Ssl, SslAcceptor, SslMethod},
};

#[cfg(feature = "tls")]
use tokio::net::TcpStream;

#[cfg(feature = "tls")]
use tokio_openssl::SslStream;

use crate::{
    config::{Config, browser_url, open_in_browser},
    handlers::handle_request,
};

#[cfg(feature = "tls")]
pub(crate) struct HttpsListener {
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
}

#[derive(Clone, Copy)]
pub(crate) struct PeerAddr(pub(crate) SocketAddr);

#[cfg(feature = "tls")]
impl HttpsListener {
    fn new(listener: TcpListener, acceptor: Arc<SslAcceptor>) -> Self {
        Self { listener, acceptor }
    }
}

#[cfg(feature = "tls")]
impl Listener for HttpsListener {
    type Io = SslStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    eprintln!("accept error: {err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            match accept_tls(&self.acceptor, stream).await {
                Ok(stream) => return (stream, addr),
                Err(err) => {
                    eprintln!("tls handshake error from {addr}: {err}");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

impl Connected<IncomingStream<'_, TcpListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

#[cfg(feature = "tls")]
impl Connected<IncomingStream<'_, HttpsListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, HttpsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

pub(crate) async fn run_server(config: Arc<Config>) -> io::Result<()> {
    let app = build_router(config.clone());
    let bind_addr = SocketAddr::new(config.ip, config.port);

    #[cfg(feature = "tls")]
    if let Some(cert_path) = &config.cert {
        let listener = TcpListener::bind(bind_addr).await?;
        let acceptor = Arc::new(build_tls_acceptor(
            cert_path,
            config.certpass.as_deref().unwrap_or(""),
        )?);
        let listener = HttpsListener::new(listener, acceptor);
        return serve_with_optional_open(listener, app, config).await;
    }

    #[cfg(not(feature = "tls"))]
    if config.cert.is_some() {
        return Err(io::Error::other(
            "TLS support is not enabled during compilation of simple-http-server",
        ));
    }

    let listener = TcpListener::bind(bind_addr).await?;
    serve_with_optional_open(listener, app, config).await
}

fn build_router(config: Arc<Config>) -> Router {
    let body_limit = usize::try_from(config.upload_size_limit).unwrap_or(usize::MAX);

    Router::new()
        .route("/", any(handle_request))
        .route("/{*path}", any(handle_request))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(config)
}

async fn serve_with_optional_open<L>(
    listener: L,
    app: Router,
    config: Arc<Config>,
) -> io::Result<()>
where
    L: Listener + Send + 'static,
    L::Addr: Send + std::fmt::Debug,
    L::Io: Send + 'static,
    for<'a> PeerAddr: Connected<IncomingStream<'a, L>>,
{
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PeerAddr>(),
        )
        .await
    });

    maybe_open_browser(config).await;

    match server.await {
        Ok(result) => result,
        Err(err) => Err(io::Error::other(err)),
    }
}

async fn maybe_open_browser(config: Arc<Config>) {
    if !config.open {
        return;
    }

    let url = browser_url(&config);
    let browser_url = url.clone();
    let silent = config.silent;
    let result = tokio::task::spawn_blocking(move || open_in_browser(&browser_url)).await;

    match result {
        Ok(Ok(())) => {
            if !silent {
                println!("Opening {url} in default browser");
            }
        }
        Ok(Err(err)) => {
            if !silent {
                eprintln!("Unable to open in default browser {err}");
            }
        }
        Err(err) => {
            if !silent {
                eprintln!("Unable to open in default browser {err}");
            }
        }
    }
}

#[cfg(feature = "tls")]
fn build_tls_acceptor(cert_path: &std::path::Path, password: &str) -> io::Result<SslAcceptor> {
    let der = std::fs::read(cert_path)?;
    let pkcs12 = Pkcs12::from_der(&der).map_err(io::Error::other)?;
    let parsed = pkcs12.parse2(password).map_err(io::Error::other)?;
    let certificate = parsed
        .cert
        .ok_or_else(|| io::Error::other("certificate missing in pkcs#12 file"))?;
    let private_key = parsed
        .pkey
        .ok_or_else(|| io::Error::other("private key missing in pkcs#12 file"))?;

    let mut builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).map_err(io::Error::other)?;
    builder
        .set_certificate(&certificate)
        .map_err(io::Error::other)?;
    builder
        .set_private_key(&private_key)
        .map_err(io::Error::other)?;
    builder.check_private_key().map_err(io::Error::other)?;

    if let Some(chain) = parsed.ca {
        for cert in chain {
            builder
                .add_extra_chain_cert(cert)
                .map_err(io::Error::other)?;
        }
    }

    Ok(builder.build())
}

#[cfg(feature = "tls")]
async fn accept_tls(acceptor: &SslAcceptor, stream: TcpStream) -> io::Result<SslStream<TcpStream>> {
    let ssl = Ssl::new(acceptor.context()).map_err(io::Error::other)?;
    let mut stream = SslStream::new(ssl, stream).map_err(io::Error::other)?;
    Pin::new(&mut stream)
        .accept()
        .await
        .map_err(io::Error::other)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::Read,
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
    };

    use axum::{
        Router,
        body::Body,
        extract::connect_info::MockConnectInfo,
        http::{Method, Request, StatusCode, header},
    };
    use flate2::read::GzDecoder;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::config::{AuthConfig, Config, UploadConfig};

    use super::{PeerAddr, build_router};

    #[test]
    fn serves_directory_listing() {
        run_async_test(async {
            let root = make_temp_dir();
            fs::write(root.join("hello.txt"), "hello").unwrap();

            let response = send(
                test_app(test_config(root.clone())),
                Request::builder().uri("/").body(Body::empty()).unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response_text(response).await;
            assert!(body.contains("hello.txt"));
            assert!(body.contains("href=\"/hello.txt\""));

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn sorts_directory_listing_from_query_params() {
        run_async_test(async {
            let root = make_temp_dir();
            fs::write(root.join("a.txt"), "a").unwrap();
            fs::write(root.join("b.txt"), "b").unwrap();

            let response = send(
                test_app(test_config(root.clone())),
                Request::builder()
                    .uri("/?sort=name&order=asc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response_text(response).await;
            assert!(body.find("a.txt").unwrap() < body.find("b.txt").unwrap());

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn serves_try_file_for_missing_paths() {
        run_async_test(async {
            let root = make_temp_dir();
            let try_file = root.join("404.html");
            fs::write(&try_file, "fallback page").unwrap();

            let mut config = test_config(root.clone());
            config.try_file_404 = Some(try_file);

            let response = send(
                test_app(config),
                Request::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(response_text(response).await, "fallback page");

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn enforces_basic_auth() {
        run_async_test(async {
            let root = make_temp_dir();
            fs::write(root.join("secret.txt"), "classified").unwrap();

            let mut config = test_config(root.clone());
            config.auth = Some(AuthConfig {
                username: "user".to_owned(),
                password: "pass".to_owned(),
            });

            let unauthorized = send(
                test_app(config.clone()),
                Request::builder()
                    .uri("/secret.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                unauthorized
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "Basic realm=\"main\""
            );

            let authorized = send(
                test_app(config),
                Request::builder()
                    .uri("/secret.txt")
                    .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(authorized.status(), StatusCode::OK);
            assert_eq!(response_text(authorized).await, "classified");

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn serves_byte_ranges() {
        run_async_test(async {
            let root = make_temp_dir();
            fs::write(root.join("hello.txt"), "abcdef").unwrap();

            let response = send(
                test_app(test_config(root.clone())),
                Request::builder()
                    .uri("/hello.txt")
                    .header(header::RANGE, "bytes=2-4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "bytes 2-4/6"
            );
            assert_eq!(response_text(response).await, "cde");

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn returns_not_modified_when_if_modified_since_matches() {
        run_async_test(async {
            let root = make_temp_dir();
            fs::write(root.join("hello.txt"), "hello").unwrap();

            let initial = send(
                test_app(test_config(root.clone())),
                Request::builder()
                    .uri("/hello.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            let last_modified = initial
                .headers()
                .get(header::LAST_MODIFIED)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            assert_eq!(initial.status(), StatusCode::OK);

            let cached = send(
                test_app(test_config(root.clone())),
                Request::builder()
                    .uri("/hello.txt")
                    .header(header::IF_MODIFIED_SINCE, last_modified)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);
            assert!(response_bytes(cached).await.is_empty());

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn responds_to_cors_preflight() {
        run_async_test(async {
            let root = make_temp_dir();
            let mut config = test_config(root.clone());
            config.cors = true;

            let response = send(
                test_app(config),
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "*"
            );

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn uploads_files_with_valid_csrf() {
        run_async_test(async {
            let root = make_temp_dir();
            let token = "csrf-token".to_owned();
            let mut config = test_config(root.clone());
            config.upload = Some(UploadConfig {
                csrf_token: token.clone(),
            });

            let boundary = "X-BOUNDARY";
            let body = build_upload_body(boundary, &token, "hello.txt", "uploaded body");

            let response = send(
                test_app(config),
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::FOUND);
            assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
            assert_eq!(
                fs::read_to_string(root.join("hello.txt")).unwrap(),
                "uploaded body"
            );

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn rejects_invalid_multipart_boundary_as_bad_request() {
        run_async_test(async {
            let root = make_temp_dir();
            let token = "csrf-token".to_owned();
            let mut config = test_config(root.clone());
            config.upload = Some(UploadConfig { csrf_token: token });

            let response = send(
                test_app(config),
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header(header::CONTENT_TYPE, "multipart/form-data")
                    .body(Body::from("broken"))
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(
                response_text(response)
                    .await
                    .contains("Invalid `boundary` for `multipart/form-data` request")
            );

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn rejects_oversized_upload_as_payload_too_large_without_partial_files() {
        run_async_test(async {
            let root = make_temp_dir();
            let token = "csrf-token".to_owned();
            let mut config = test_config(root.clone());
            config.upload = Some(UploadConfig {
                csrf_token: token.clone(),
            });
            config.upload_size_limit = 128;

            let response = send(
                test_app(config),
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header(
                        header::CONTENT_TYPE,
                        "multipart/form-data; boundary=X-BOUNDARY",
                    )
                    .body(Body::from(build_upload_body(
                        "X-BOUNDARY",
                        &token,
                        "hello.txt",
                        &"x".repeat(512),
                    )))
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert!(
                response_text(response)
                    .await
                    .contains("upload size exceeds limit (max 128 B)")
            );
            assert!(!root.join("hello.txt").exists());
            assert_eq!(
                fs::read_dir(&root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".simple-http-upload-"))
                    .count(),
                0
            );

            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn compresses_matching_files_with_gzip() {
        run_async_test(async {
            let root = make_temp_dir();
            let contents = "console.log('hello');".repeat(32);
            fs::write(root.join("app.js"), &contents).unwrap();

            let mut config = test_config(root.clone());
            config.compress = vec![".js".to_owned()];

            let response = send(
                test_app(config),
                Request::builder()
                    .uri("/app.js")
                    .header(header::ACCEPT_ENCODING, "gzip, deflate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_ENCODING)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "gzip"
            );

            let compressed = response_bytes(response).await;
            let mut decoder = GzDecoder::new(&compressed[..]);
            let mut decoded = String::new();
            decoder.read_to_string(&mut decoded).unwrap();
            assert_eq!(decoded, contents);

            fs::remove_dir_all(root).unwrap();
        });
    }

    fn test_app(config: Config) -> Router {
        build_router(std::sync::Arc::new(config))
            .layer(MockConnectInfo(PeerAddr(([127, 0, 0, 1], 12345).into())))
    }

    fn build_upload_body(boundary: &str, token: &str, filename: &str, contents: &str) -> String {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{token}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n{contents}\r\n--{boundary}--\r\n"
        )
    }

    fn test_config(root: PathBuf) -> Config {
        Config {
            root,
            index: false,
            upload: None,
            redirect_to: None,
            sort: true,
            cache: true,
            range: true,
            cert: None,
            certpass: None,
            cors: false,
            coop: false,
            coep: false,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8000,
            upload_size_limit: 8_000_000,
            auth: None,
            compress: Vec::new(),
            threads: 1,
            try_file_404: None,
            silent: true,
            open: false,
            base_url: "/".to_owned(),
        }
    }

    async fn send(app: Router, request: Request<Body>) -> axum::response::Response {
        app.oneshot(request).await.unwrap()
    }

    async fn response_text(response: axum::response::Response) -> String {
        String::from_utf8(response_bytes(response).await.to_vec()).unwrap()
    }

    async fn response_bytes(response: axum::response::Response) -> axum::body::Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    fn run_async_test(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test);
    }

    fn make_temp_dir() -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "axum-server-test-{}-{}",
            std::process::id(),
            crate::util::generate_csrf_token().unwrap()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
