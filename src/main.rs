#[macro_use]
extern crate clap;
extern crate pretty_bytes;
extern crate time;
extern crate chrono;
extern crate filetime;
extern crate ansi_term;
extern crate url;
extern crate iron;
extern crate multipart;

use std::env;
use std::fmt;
use std::str::FromStr;
use std::io::Write;
use std::net::IpAddr;
use std::fs::{self, File};
use std::path::{PathBuf, Path};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use iron::headers;
use iron::status;
use iron::method;
use iron::modifiers::Redirect;
use iron::{Iron, Request, Response, IronResult, IronError, Set, Chain, Handler,
           BeforeMiddleware, AfterMiddleware};
use multipart::server::{Multipart, SaveResult};
use pretty_bytes::converter::convert;
use chrono::{DateTime, Local, TimeZone};
use ansi_term::Colour::{Red, Green, Yellow, Blue};
use url::percent_encoding::{percent_decode, utf8_percent_encode, PATH_SEGMENT_ENCODE_SET};

const ROOT_LINK: &'static str = "<a href=\"/\"><strong>[Root]</strong></a>";

fn main() {
    let matches = clap::App::new("Simple HTTP Server")
        .version(crate_version!())
        .arg(clap::Arg::with_name("root")
             .index(1)
             .validator(|s| {
                 match File::open(s) {
                     Ok(f) => {
                         if f.metadata().unwrap().is_dir() { Ok(()) } else {
                             Err("Not directory".to_owned())
                         }
                     },
                     Err(e) => Err(e.description().to_string())
                 }
             })
             .help("Root directory"))
        .arg(clap::Arg::with_name("index")
             .short("i")
             .long("index")
             .help("Enable automatic render index page [index.html, index.htm]"))
        .arg(clap::Arg::with_name("upload")
             .short("u")
             .long("upload")
             .help("Enable upload files (multiple select)"))
        .arg(clap::Arg::with_name("nocache")
             .long("nocache")
             .help("Disable http cache"))
        .arg(clap::Arg::with_name("ip")
             .long("ip")
             .takes_value(true)
             .default_value("0.0.0.0")
             .validator(|s| {
                 match IpAddr::from_str(&s) {
                     Ok(_) => Ok(()),
                     Err(e) => Err(e.description().to_string())
                 }
             })
             .help("IP address to bind"))
        .arg(clap::Arg::with_name("port")
             .short("p")
             .long("port")
             .takes_value(true)
             .default_value("8000")
             .validator(|s| {
                 match s.parse::<u16>() {
                     Ok(_) => Ok(()),
                     Err(e) => Err(e.description().to_string())
                 }
             })
             .help("Port number"))
        .arg(clap::Arg::with_name("auth")
             .short("a")
             .long("auth")
             .takes_value(true)
             .validator(|s| {
                 let parts = s.splitn(2, ':').collect::<Vec<&str>>();
                 if parts.len() < 2 || parts.len() >= 2 && parts[1].len() < 1 {
                     Err("no password found".to_owned())
                 } else if parts[0].len() < 1 {
                     Err("no username found".to_owned())
                 } else {
                     Ok(())
                 }
             })
             .help("HTTP Basic Auth (username:password)"))
        .arg(clap::Arg::with_name("threads")
             .short("t")
             .long("threads")
             .takes_value(true)
             .default_value("3")
             .validator(|s| {
                 match s.parse::<u8>() {
                     Ok(v) => {
                         if v > 0 { Ok(()) } else {
                             Err("Not positive number".to_owned())
                         }
                     }
                     Err(e) => Err(e.description().to_string())
                 }
             })
             .help("How many worker threads"))
        .get_matches();

    let root = matches
        .value_of("root")
        .map(|s| PathBuf::from(s))
        .unwrap_or(env::current_dir().unwrap());
    let index = matches.is_present("index");
    let upload = matches.is_present("upload");
    let cache = !matches.is_present("nocache");
    let ip = matches.value_of("ip").unwrap();
    let port = matches
        .value_of("port")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let auth = matches.value_of("auth");
    let threads = matches
        .value_of("threads")
        .unwrap()
        .parse::<u8>()
        .unwrap();

    let addr = format!("{}:{}", ip, port);
    println!("  Index: {}, Upload: {}, Cache: {}, Threads: {}, Auth: {}",
             Blue.paint(index.to_string()),
             Blue.paint(upload.to_string()),
             Blue.paint(cache.to_string()),
             Blue.paint(threads.to_string()),
             Blue.paint(auth.unwrap_or("disabled").to_string()));
    println!("   Root: {}", Blue.paint(root.to_str().unwrap()));
    println!("Address: {}", Blue.paint(format!("http://{}", addr)));
    println!("======== [{}] ========", Blue.paint(now_string()));

    let mut chain = Chain::new(MainHandler{root, index, upload, cache});
    if let Some(auth) = auth {
        chain.link_before(AuthChecker::new(auth));
    }
    chain.link_after(RequestLogger);
    let mut server = Iron::new(chain);
    server.threads = threads as usize;
    if let Err(e) = server.http(&addr) {
        writeln!(std::io::stderr(), "{}: Can not bind on {}, {}",
                 Red.bold().paint("ERROR"), addr, e).unwrap();
        std::process::exit(1);
    };
}

struct MainHandler {
    root: PathBuf,
    index: bool,
    upload: bool,
    cache: bool
}

struct AuthChecker { username: String, password: String }
struct RequestLogger;

#[derive(Debug)]
struct AuthError;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt("authentication error", f)
    }
}

impl Error for AuthError {
    fn description(&self) -> &str {
        "authentication error"
    }
}

fn encode_link_path(path: &Vec<String>) -> String {
    path.iter().map(|s| {
        utf8_percent_encode(s, PATH_SEGMENT_ENCODE_SET).to_string()
    }).collect::<Vec<String>>().join("/")
}

fn error_resp(s: status::Status, msg: &str)  -> IronResult<Response> {
    let mut resp = Response::with((s, format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body>
  {root_link}
  <hr />
  <div>[<strong style=color:red;>ERROR {code}</strong>]: {msg}</div>
</body>
</html>
"#,
        root_link=ROOT_LINK,
        code=s.to_u16(),
        msg=msg
    )));
    resp.headers.set(headers::ContentType::html());
    Ok(resp)
}

impl MainHandler {

    fn save_files(&self, req: &mut Request, path: &PathBuf) -> Result<(), (status::Status, String)> {
        match Multipart::from_request(req) {
            Ok(mut multipart) => {
                // Fetching all data and processing it.
                // save().temp() reads the request fully, parsing all fields and saving all files
                // in a new temporary directory under the OS temporary directory.
                match multipart.save().temp() {
                    SaveResult::Full(entries) => {
                        for (_, files) in entries.files {
                            for file in files {
                                let mut target_path = path.clone();
                                target_path.push(file.filename.clone().unwrap());
                                if let Err(errno) = fs::copy(file.path, target_path) {
                                    return Err((status::InternalServerError, format!("Copy file failed: {}", errno)));
                                } else {
                                    println!("  >> File saved: {}", file.filename.clone().unwrap());
                                }
                            }
                        }
                        Ok(())
                    },
                    SaveResult::Partial(_entries, reason) => {
                        Err((status::InternalServerError, reason.unwrap_err().description().to_owned()))
                    }
                    SaveResult::Error(error) => Err((status::InternalServerError, error.description().to_owned())),
                }
            }
            Err(_) => Err((status::BadRequest ,"The request is not multipart".to_owned()))
        }
    }

    fn send_file<P: AsRef<Path>>(&self, req: &Request, path: P) -> IronResult<Response> {
        use iron::headers::{IfModifiedSince, CacheControl, LastModified, CacheDirective, HttpDate};
        use iron::headers::{ContentLength, ContentType, ETag, EntityTag};
        use iron::method::Method;
        use iron::mime::{Mime, TopLevel, SubLevel};
        use iron::modifiers::Header;
        use filetime::FileTime;

        let path = path.as_ref();
        let metadata = fs::metadata(path);
        let metadata = try!(metadata.map_err(|e| IronError::new(e, status::InternalServerError)));
        let mut response = if req.method == Method::Head {
            let has_ct = req.headers.get::<ContentType>();
            let cont_type = match has_ct {
                None => ContentType(Mime(TopLevel::Text, SubLevel::Plain, vec![])),
                Some(t) => t.clone()
            };
            Response::with((status::Ok, Header(cont_type), Header(ContentLength(metadata.len()))))
        } else {
            Response::with((status::Ok, path))
        };

        if self.cache {
            static SECONDS: u32 = 7 * 24 * 3600; // max-age: 7.days()
            let time = FileTime::from_last_modification_time(&metadata);
            let modified = time::Timespec::new(time.seconds() as i64, 0);

            if let Some(IfModifiedSince(HttpDate(if_modified_since))) = req.headers.get::<IfModifiedSince>().cloned() {
                if modified <= if_modified_since.to_timespec() {
                    return Ok(Response::with(status::NotModified))
                }
            };

            let cache = vec![CacheDirective::Public, CacheDirective::MaxAge(SECONDS)];
            response.headers.set(CacheControl(cache));
            response.headers.set(LastModified(HttpDate(time::at(modified))));
            response.headers.set(ETag(EntityTag::weak(format!("{0:x}-{1:x}.{2:x}", metadata.len(), modified.sec, modified.nsec))));
        }
        Ok(response)
    }
}

impl Handler for MainHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let mut fs_path = self.root.clone();
        let path_prefix = req.url.path()
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(|s| {
                percent_decode(s.as_bytes())
                    .decode_utf8().unwrap()
                    .to_string()
            })
            .collect::<Vec<String>>();
        for part in path_prefix.iter() {
            fs_path.push(part);
        }

        if self.upload && req.method == method::Post {
            if let Err((s, msg)) = self.save_files(req, &fs_path) {
                return error_resp(s, &msg);
            } else {
                return Ok(Response::with((status::Found, Redirect(req.url.clone()))))
            }
        }

        match File::open(&fs_path) {
            Ok(f) => {
                let mut resp = Response::with(status::Ok);
                let metadata = f.metadata().unwrap();
                if metadata.is_dir() {
                    let mut rows = Vec::new();

                    // Breadcrumb navigation
                    let breadcrumb = if path_prefix.len() > 0 {
                        let mut breadcrumb = path_prefix.clone();
                        let mut bread_links: Vec<String> = Vec::new();
                        bread_links.push(breadcrumb.pop().unwrap().to_owned());
                        while breadcrumb.len() > 0 {
                            bread_links.push(format!(
                                r#"<a href="/{link}/"><strong>{label}</strong></a>"#,
                                link=encode_link_path(&breadcrumb), label=breadcrumb.pop().unwrap().to_owned(),
                            ));
                        }
                        bread_links.push(ROOT_LINK.to_owned());
                        bread_links.reverse();
                        bread_links.join(" / ")
                    } else { ROOT_LINK.to_owned() };

                    // Goto parent directory link
                    if path_prefix.len() > 0 {
                        let mut link = path_prefix.clone();
                        link.pop();
                        if link.len() > 0 {
                            link.push("".to_owned());
                        }
                        rows.push(format!(
                            r#"
<tr>
  <td><a href="/{link}"><strong>[Up]</strong></a></td>
  <td></td>
  <td></td>
</tr>
"#,
                            link=encode_link_path(&link)
                        ));
                    } else {
                        rows.push(r#"<tr><td>&nbsp;</td></tr>"#.to_owned());
                    }

                    // Directory entries
                    for entry in fs::read_dir(&fs_path).unwrap() {
                        let entry = entry.unwrap();
                        let entry_meta = entry.metadata().unwrap();
                        let file_name = entry.file_name().into_string().unwrap();

                        if self.index {
                            for fname in vec!["index.html", "index.htm"] {
                                if file_name == fname {
                                    // Automatic render index page
                                    fs_path.push(file_name);
                                    return self.send_file(req, &fs_path);
                                }
                            }
                        }
                        // * Entry.modified
                        let file_modified = system_time_to_date_time(entry_meta.modified().unwrap())
                            .format("%Y-%m-%d %H:%M:%S").to_string();
                        // * Entry.filesize
                        let file_size = if entry_meta.is_dir() {
                            "-".to_owned()
                        } else {
                            convert(entry_meta.len() as f64)
                        };
                        // * Entry.linkstyle
                        let link_style = if entry_meta.is_dir() {
                            "style=\"font-weight: bold;\"".to_owned()
                        } else {
                            "".to_owned()
                        };
                        // * Entry.link
                        let mut link = path_prefix.clone();
                        link.push(file_name.clone());
                        if entry_meta.is_dir() {
                            link.push("".to_owned());
                        }
                        // * Entry.label
                        let file_name_label = if entry_meta.is_dir() {
                            format!("{}/", &file_name)
                        } else { file_name.clone() };

                        // Render one directory entry
                        rows.push(format!(
                            r#"
<tr>
  <td><a {linkstyle} href="/{link}">{label}</a></td>
  <td style="color:#888;">[{modified}]</td>
  <td><bold>{filesize}</bold></td>
</tr>
"#,
                            linkstyle=link_style,
                            link=encode_link_path(&link),
                            label=file_name_label,
                            modified=file_modified,
                            filesize=file_size
                        ));
                    }

                    // Optinal upload form
                    let upload_form = if self.upload {
                        format!(
                            r#"
<form style="margin-top:1em; margin-bottom:1em;" action="/{path}" method="POST" enctype="multipart/form-data">
  <input type="file" name="files" accept="*" multiple />
  <input type="submit" value="Upload" />
</form>
"#,
                            path=encode_link_path(&path_prefix))
                    } else { "".to_owned() };

                    // Put all parts together
                    resp.set_mut(format!(
                        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style> a {{ text-decoration:none; }} </style>
</head>
<body>
  {upload_form}
  <div>{breadcrumb}</div>
  <hr />
  <table>{rows}</table>
</body>
</html>
"#,
                        upload_form=upload_form,
                        breadcrumb=breadcrumb,
                        rows=rows.join("\n")));

                    resp.headers.set(headers::ContentType::html());
                    Ok(resp)
                } else {
                    self.send_file(req, &fs_path)
                }
            },
            Err(e) => error_resp(status::NotFound, e.description().to_string().as_str())
        }
    }
}

impl AuthChecker {
    fn new(s: &str) -> AuthChecker {
        let parts = s.splitn(2, ':').collect::<Vec<&str>>();
        AuthChecker {
            username: parts[0].to_owned(),
            password: parts[1].to_owned()
        }
    }
}

impl BeforeMiddleware for AuthChecker {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        match req.headers.get::<headers::Authorization<headers::Basic>>() {
            Some(&headers::Authorization(headers::Basic { ref username, password: Some(ref password) })) => {
                if username == self.username.as_str() && password == self.password.as_str() {
                    Ok(())
                } else {
                    Err(IronError {
                        error: Box::new(AuthError),
                        response: Response::with((status::Unauthorized, "Wrong username or password."))
                    })
                }
            }
            Some(&headers::Authorization(headers::Basic { username: _, password: None })) => {
                Err(IronError {
                    error: Box::new(AuthError),
                    response: Response::with((status::Unauthorized, "No password found."))
                })
            }
            None => {
                let mut resp = Response::with(status::Unauthorized);
                resp.headers.set_raw("WWW-Authenticate", vec![b"Basic realm=\"main\"".to_vec()]);
                Err(IronError {
                    error: Box::new(AuthError),
                    response: resp
                })
            }
        }
    }
}

impl AfterMiddleware for RequestLogger {
    fn after(&self, req: &mut Request, resp: Response) -> IronResult<Response> {
        let status = resp.status.unwrap();
        let status_str = if status.is_success() {
            Green.bold().paint(status.to_u16().to_string())
        } else if status.is_informational() || status.is_redirection() {
            Yellow.bold().paint(status.to_u16().to_string())
        } else {
            Red.bold().paint(status.to_u16().to_string())
        };

        println!(
            // datetime, remote-ip, status-code, method, url-path
            "[{}] - {} - {} - {} {}",
            now_string(),
            req.remote_addr.ip(),
            status_str,
            req.method,
            percent_decode(req.url.as_ref().path().as_bytes())
                .decode_utf8().unwrap().to_string()
        );
        Ok(resp)
    }
}

fn now_string() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn system_time_to_date_time(t: SystemTime) -> DateTime<Local> {
    let (sec, nsec) = match t.duration_since(UNIX_EPOCH) {
        Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
        Err(e) => { // unlikely but should be handled
            let dur = e.duration();
            let (sec, nsec) = (dur.as_secs() as i64, dur.subsec_nanos());
            if nsec == 0 {
                (-sec, 0)
            } else {
                (-sec - 1, 1_000_000_000 - nsec)
            }
        },
    };
    Local.timestamp(sec, nsec)
}
