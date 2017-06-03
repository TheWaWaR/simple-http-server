
use std::ops::Deref;

use iron::status;
use iron::{Request, Response, AfterMiddleware, IronError, IronResult};
use termcolor::{Color, ColorSpec};
use url::percent_encoding::{percent_decode};

use color::{Printer, build_spec};
use util::{now_string, error_resp};

lazy_static! {
    static ref C_BOLD_GREEN: Option<ColorSpec> = Some(build_spec(Some(Color::Green), true));
    static ref C_BOLD_YELLOW: Option<ColorSpec> = Some(build_spec(Some(Color::Yellow), true));
    static ref C_BOLD_RED: Option<ColorSpec> = Some(build_spec(Some(Color::Red), true));
}

pub struct RequestLogger { pub printer: Printer }

impl RequestLogger {
    fn log(&self, req: &Request, resp: &Response) {
        if let Some(status) = resp.status {
            let status_color = if status.is_success() {
                C_BOLD_GREEN.deref()
            } else if status.is_informational() || status.is_redirection() {
                C_BOLD_YELLOW.deref()
            } else {
                C_BOLD_RED.deref()
            };
            self.printer.println_out(
                // datetime, remote-ip, status-code, method, url-path
                "[{}] - {} - {} - {} {}",
                &vec![
                    (now_string().as_str(), &None),
                    (req.remote_addr.ip().to_string().as_str(), &None),
                    (status.to_u16().to_string().as_str(), status_color),
                    (req.method.to_string().as_str(), &None),
                    (percent_decode(req.url.as_ref().path().as_bytes())
                     .decode_utf8().unwrap().to_string().as_str(), &None)
                ]).unwrap();
        } else {
            println!("ERROR: StatusCode missing");
        }
    }
}

impl AfterMiddleware for RequestLogger {
    fn after(&self, req: &mut Request, resp: Response) -> IronResult<Response> {
        self.log(req, &resp);
        Ok(resp)
    }

    fn catch(&self, req: &mut Request, err: IronError) -> IronResult<Response> {
        self.log(req, &err.response);
        let mut unauthorized = false;
        if let Some(ref s) = err.response.status {
            if s == &status::Unauthorized {
                unauthorized = true;
            }
        }
        if unauthorized {
            Err(err)
        } else {
            Ok(error_resp(err.response.status.unwrap_or(status::InternalServerError),
                       err.error.description()))
        }
    }
}
