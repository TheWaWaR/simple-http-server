use std::io;

use flate2::{Compression, write::{DeflateEncoder, GzEncoder}};
use iron::headers::{ContentEncoding, ContentLength, Encoding, TransferEncoding};
use iron::response::WriteBody;
use iron::{AfterMiddleware, IronResult, Request, Response};

// [Reference]: https://github.com/iron/iron/issues/548
struct GzipBody(Box<dyn WriteBody>);
struct DeflateBody(Box<dyn WriteBody>);

impl WriteBody for GzipBody {
    fn write_body(&mut self, w: &mut dyn io::Write) -> io::Result<()> {
        let mut w = GzEncoder::new(w, Compression::default());
        self.0.write_body(&mut w)?;
        w.finish().map(|_| ())
    }
}

impl WriteBody for DeflateBody {
    fn write_body(&mut self, w: &mut dyn io::Write) -> io::Result<()> {
        let mut w = DeflateEncoder::new(w, Compression::default());
        self.0.write_body(&mut w)?;
        w.finish().map(|_| ())
    }
}

pub struct CompressionHandler;

impl AfterMiddleware for CompressionHandler {
    fn after(&self, _: &mut Request, mut resp: Response) -> IronResult<Response> {
        if let Some(&ContentLength(length)) = resp.headers.get::<ContentLength>() {
            if length <= 256 {
                resp.headers.remove::<ContentEncoding>();
                return Ok(resp);
            }
        }

        let mut encoding: Option<Encoding> = None;
        if let Some(&ContentEncoding(ref objs)) = resp.headers.get::<ContentEncoding>() {
            encoding = objs
                .iter()
                .find(|obj| *obj == &Encoding::Deflate || *obj == &Encoding::Gzip)
                .cloned();
        }
        if encoding.is_none() {
            if let Some(&TransferEncoding(ref objs)) = resp.headers.get::<TransferEncoding>() {
                encoding = objs
                    .iter()
                    .find(|obj| *obj == &Encoding::Deflate || *obj == &Encoding::Gzip)
                    .cloned();
            }
        }

        if resp.body.is_some() {
            match encoding {
                Some(Encoding::Gzip) => {
                    // TransferEncoding will be `chunked`
                    resp.headers.remove::<ContentLength>();
                    resp.body = Some(Box::new(GzipBody(resp.body.take().unwrap())));
                }
                Some(Encoding::Deflate) => {
                    // TransferEncoding will be `chunked`
                    resp.headers.remove::<ContentLength>();
                    resp.body = Some(Box::new(DeflateBody(resp.body.take().unwrap())));
                }
                _ => {}
            }
        }
        Ok(resp)
    }
}
