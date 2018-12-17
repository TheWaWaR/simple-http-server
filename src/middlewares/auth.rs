use iron::status;
use iron::{BeforeMiddleware, IronError, IronResult, Request, Response};

use util::StringError;

pub struct AuthChecker {
    username: String,
    password: String,
}

impl AuthChecker {
    pub fn new(s: &str) -> AuthChecker {
        let parts = s.splitn(2, ':').collect::<Vec<&str>>();
        AuthChecker {
            username: parts[0].to_owned(),
            password: parts[1].to_owned(),
        }
    }
}

impl BeforeMiddleware for AuthChecker {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        use iron::headers::{Authorization, Basic};

        match req.headers.get::<Authorization<Basic>>() {
            Some(&Authorization(Basic {
                ref username,
                ref password,
            })) => {
                if username == self.username.as_str() && password == &Some(self.password.clone()) {
                    Ok(())
                } else {
                    Err(IronError {
                        error: Box::new(StringError("authorization error".to_owned())),
                        response: Response::with((
                            status::Unauthorized,
                            "Wrong username or password.",
                        )),
                    })
                }
            }
            None => {
                let mut resp = Response::with(status::Unauthorized);
                resp.headers
                    .set_raw("WWW-Authenticate", vec![b"Basic realm=\"main\"".to_vec()]);
                Err(IronError {
                    error: Box::new(StringError("authorization error".to_owned())),
                    response: resp,
                })
            }
        }
    }
}
