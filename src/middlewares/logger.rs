use std::ops::Deref;
use std::sync::LazyLock;

use iron::status;
use iron::{AfterMiddleware, IronError, IronResult, Request, Response};
use percent_encoding::percent_decode;
use termcolor::{Color, ColorSpec};

use crate::color::{build_spec, Printer};
use crate::util::{error_resp, now_string};

static C_BOLD_GREEN: LazyLock<Option<ColorSpec>> =
    LazyLock::new(|| Some(build_spec(Some(Color::Green), true)));
static C_BOLD_YELLOW: LazyLock<Option<ColorSpec>> =
    LazyLock::new(|| Some(build_spec(Some(Color::Yellow), true)));
static C_BOLD_RED: LazyLock<Option<ColorSpec>> =
    LazyLock::new(|| Some(build_spec(Some(Color::Red), true)));

pub struct RequestLogger {
    pub printer: Printer,
    pub base_url: String,
}

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
            self.printer
                .println_out(
                    // datetime, remote-ip, status-code, method, url-path
                    "[{}] - {} - {} - {} {}",
                    &[
                        (now_string().as_str(), &None),
                        (req.remote_addr.ip().to_string().as_str(), &None),
                        (status.to_u16().to_string().as_str(), status_color),
                        (req.method.to_string().as_str(), &None),
                        (
                            percent_decode(req.url.as_ref().path().as_bytes())
                                .decode_utf8_lossy()
                                .to_string()
                                .as_str(),
                            &None,
                        ),
                    ],
                )
                .unwrap();
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
        if err.response.status == Some(status::Unauthorized) {
            Err(err)
        } else {
            Ok(error_resp(
                err.response.status.unwrap_or(status::InternalServerError),
                err.error.to_string().as_str(),
                &self.base_url,
            ))
        }
    }
}
