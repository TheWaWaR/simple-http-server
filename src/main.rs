#[macro_use]
extern crate log;
extern crate env_logger;
extern crate clap;
extern crate iron;
extern crate pretty_bytes;
extern crate chrono;

use std::env;
use std::fs::{self, File};
use std::path::{PathBuf};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::ffi::OsStrExt;

use iron::headers;
use iron::{Iron, Request, Response, Set, status};
use pretty_bytes::converter::convert;
use chrono::{DateTime, UTC, TimeZone};


fn main() {
    env_logger::init().unwrap();

    let matches = clap::App::new("Simple HTTP Server")
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
        .get_matches();
    let root = matches
        .value_of("root")
        .map(|s| PathBuf::from(s))
        .unwrap_or(env::current_dir().unwrap());
    let port = matches
        .value_of("port")
        .unwrap()
        .parse::<u16>()
        .unwrap();

    println!("current dir: {:?}", env::current_dir());
    let addr = format!("0.0.0.0:{}", port);
    println!("Server running on: http://{}", addr);

    Iron::new(move |req: &mut Request| {
        println!("Url: {:?}", req.url.path());
        let mut path = root.clone();
        for part in req.url.path() {
            path.push(part);
        }
        match File::open(&path) {
            Ok(f) => {
                let mut resp = Response::with(status::Ok);
                let metadata = f.metadata().unwrap();
                let path_prefix = req.url.path()
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<&str>>();
                if metadata.is_dir() {
                    resp.headers.set(headers::ContentType::html());
                    let mut files = Vec::new();
                    for entry in fs::read_dir(&path).unwrap() {
                        let entry = entry.unwrap();
                        let entry_meta = entry.metadata().unwrap();
                        let file_name = entry.file_name().into_string().unwrap();
                        let file_modified = system_time_to_date_time(entry_meta.modified().unwrap())
                            .format("%Y-%m-%d %H:%M:%S").to_string();
                        let file_size = convert(entry_meta.len() as f64);
                        let mut link = path_prefix.clone();
                        link.push(&file_name);
                        let link = link.join("/");
                        files.push(format!(
                            "<tr><td><a href=\"/{}\">{}</a></td> <td style=\"color: #999;\">{}</td> <td><bold>{}</bold></td></tr>",
                            link, file_name, file_modified, file_size
                        ));
                    }
                    resp = resp.set(format!("<html><body><table>{}</table></body></html>", files.join("\n")));
                } else {
                    resp.headers.set(headers::ContentDisposition {
                        disposition: headers::DispositionType::Attachment,
                        parameters: vec![headers::DispositionParam::Filename(
                            headers::Charset::Ext("utf-8".to_owned()), // The character set for the bytes of the filename
                            None, // The optional language tag (see `language-tag` crate)
                            path.file_name().unwrap().as_bytes().to_vec() // the actual bytes of the filename
                        )]
                    });
                    resp = resp.set(path);
                    let mime: iron::mime::Mime = "application/octet-stream".parse().unwrap();
                    resp.headers.set(headers::ContentType(mime));
                };
                Ok(resp)
            },
            Err(e) => {
                Ok(Response::with((status::NotFound, e.description().to_string())))
            }
        }
    }).http(addr).unwrap();
}

fn system_time_to_date_time(t: SystemTime) -> DateTime<UTC> {
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
    UTC.timestamp(sec, nsec)
}
