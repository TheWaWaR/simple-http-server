#[macro_use]
extern crate log;
extern crate env_logger;
extern crate clap;
extern crate iron;
// extern crate mount;
// extern crate router;
// extern crate staticfile;

use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::error::Error;
use std::fmt::{self, Debug};

use iron::{Iron, IronResult, IronError, Request, Response, status};

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for StringError {
    fn description(&self) -> &str { &*self.0 }
}

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
        .unwrap_or("8000")
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
        match File::open(path) {
            Ok(f) => {
                let metadata = f.metadata().unwrap();
                let content = if metadata.is_dir() { "Is directory" } else { "Is normal file" };
                Ok(Response::with((status::Ok, content)))
            },
            Err(e) => {
                Ok(Response::with((status::NotFound, e.description().to_string())))
            }
        }
    }).http(addr).unwrap();
}
