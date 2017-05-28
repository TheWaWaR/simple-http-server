#[macro_use]
extern crate log;
extern crate env_logger;
extern crate clap;
extern crate iron;

use std::env;
use std::fs::{self, File};
use std::path::{PathBuf};
use std::error::Error;
use std::os::unix::ffi::OsStrExt;

use iron::headers;
use iron::{Iron, Request, Response, Set, status};


fn main() {
    env_logger::init().unwrap();

    let default_port = "8000";
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
             .default_value(default_port)
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
    println!("Server running on http://{:?}", addr);

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
                if metadata.is_dir() {
                    resp.headers.set(headers::ContentType::html());
                    let mut files = Vec::new();
                    for entry in fs::read_dir(&path).unwrap() {
                        let entry = entry.unwrap();
                        let file_name = entry.file_name().into_string().unwrap();
                        let link = req.url.path().join("/");
                        files.push(format!(
                            "<li><a href=\"/{}/{}\">{}</a></li>",
                            link, file_name, file_name
                        ));
                    }
                    resp = resp.set(format!("<html><body>{}</body></html>", files.join("\n")));
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
