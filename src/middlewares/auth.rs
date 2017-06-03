
use iron::status;
use iron::{BeforeMiddleware, Request, Response, IronResult, IronError};

use util::StringError;

pub struct AuthChecker {
    username: String,
    password: String
}

impl AuthChecker {
    pub fn new(s: &str) -> AuthChecker {
        let parts = s.splitn(2, ':').collect::<Vec<&str>>();
        AuthChecker {
            username: parts[0].to_owned(),
            password: parts[1].to_owned()
        }
    }
}

impl BeforeMiddleware for AuthChecker {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        use iron::headers::{Authorization, Basic};

        match req.headers.get::<Authorization<Basic>>() {
            Some(&Authorization(Basic { ref username, password: Some(ref password) })) => {
                if username == self.username.as_str() && password == self.password.as_str() {
                    Ok(())
                } else {
                    Err(IronError {
                        error: Box::new(StringError("authorization error".to_owned())),
                        response: Response::with((status::Unauthorized, "Wrong username or password."))
                    })
                }
            }
            Some(&Authorization(Basic { username: _, password: None })) => {
                Err(IronError {
                    error: Box::new(StringError("authorization error".to_owned())),
                    response: Response::with((status::Unauthorized, "No password found."))
                })
            }
            None => {
                let mut resp = Response::with(status::Unauthorized);
                resp.headers.set_raw("WWW-Authenticate", vec![b"Basic realm=\"main\"".to_vec()]);
                Err(IronError {
                    error: Box::new(StringError("authorization error".to_owned())),
                    response: resp
                })
            }
        }
    }
}
