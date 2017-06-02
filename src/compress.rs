
use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder};
use iron::{Response, Request, IronResult, AfterMiddleware};
use iron::headers::{ContentLength, ContentEncoding, TransferEncoding, Encoding};

use util::{error_io2iron};

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
                Some(Encoding::Deflate) => {
                    let mut body = resp.body.take().unwrap();
                    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::Best);
                    try!(body.write_body(&mut encoder).map_err(error_io2iron));
                    let compressed_bytes = try!(encoder.finish().map_err(error_io2iron));
                    resp.headers.set(ContentLength(compressed_bytes.len() as u64));
                    resp.body = Some(Box::new(compressed_bytes));
                    // TODO: give up on header::Range
                    // if let Some(&mut ContentRange(ContentRangeSpec::Bytes{
                    //     range: Some((offset, end)), instance_length: Some(length)
                    // })) = resp.headers.get_mut::<ContentRange>() {
                    // }
                }
                Some(Encoding::Gzip) => {
                    let mut body = resp.body.take().unwrap();
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::Best);
                    try!(body.write_body(&mut encoder).map_err(error_io2iron));
                    let compressed_bytes = try!(encoder.finish().map_err(error_io2iron));
                    resp.headers.set(ContentLength(compressed_bytes.len() as u64));
                    resp.body = Some(Box::new(compressed_bytes));
                }
                _ => {}
            }
        }
        Ok(resp)
    }
}
