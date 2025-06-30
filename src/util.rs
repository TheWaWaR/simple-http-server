use std::error::Error;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, TimeZone};
use iron::headers;
use iron::status;
use iron::{IronError, Response};
use percent_encoding::{utf8_percent_encode, AsciiSet};

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT_ENCODE_SET: &AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`');
/// https://url.spec.whatwg.org/#path-percent-encode-set
const PATH_ENCODE_SET: &AsciiSet = &FRAGMENT_ENCODE_SET.add(b'#').add(b'?').add(b'{').add(b'}');
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &PATH_ENCODE_SET.add(b'/').add(b'%').add(b'[').add(b']');

pub fn root_link(baseurl: &str) -> String {
    format!(r#"<a href="{baseurl}"><strong>[Root]</strong></a>"#)
}

#[derive(Debug)]
pub struct StringError(pub String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for StringError {
    fn description(&self) -> &str {
        &self.0
    }
}

impl Deref for StringError {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn enable_string(value: bool) -> String {
    (if value { "enabled" } else { "disabled" }).to_owned()
}

pub fn encode_link_path(path: &[String]) -> String {
    path.iter()
        .map(|s| utf8_percent_encode(s, PATH_SEGMENT_ENCODE_SET).to_string())
        .collect::<Vec<String>>()
        .join("/")
}

pub fn error_io2iron(err: io::Error) -> IronError {
    let status = match err.kind() {
        io::ErrorKind::PermissionDenied => status::Forbidden,
        io::ErrorKind::NotFound => status::NotFound,
        _ => status::InternalServerError,
    };
    IronError::new(err, status)
}

pub fn now_string() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn system_time_to_date_time(t: SystemTime) -> DateTime<Local> {
    let (sec, nsec) = match t.duration_since(UNIX_EPOCH) {
        Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
        Err(e) => {
            // unlikely but should be handled
            let dur = e.duration();
            let (sec, nsec) = (dur.as_secs() as i64, dur.subsec_nanos());
            if nsec == 0 {
                (-sec, 0)
            } else {
                (-sec - 1, 1_000_000_000 - nsec)
            }
        }
    };
    Local.timestamp_opt(sec, nsec).unwrap()
}

pub fn error_resp(s: status::Status, msg: &str, baseurl: &str) -> Response {
    let mut resp = Response::with((
        s,
        format!(
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
            root_link = root_link(baseurl),
            code = s.to_u16(),
            msg = msg
        ),
    ));
    resp.headers.set(headers::ContentType::html());
    resp
}
