//! HTTP 1.1 Request parsing and response building

use crate::Socket;
use std::fmt::{Display, Formatter};
use std::str::from_utf8;

#[derive(Debug, PartialEq, Clone)]
pub enum Method {
    Get,
    Post,
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Get => write!(f, "GET"),
            Method::Post => write!(f, "POST"),
        }
    }
}

pub enum ParseError {
    Incomplete,
    Malformed,
}

#[derive(Debug, PartialEq)]
pub struct Request<'buffer> {
    method: Method,
    uri: &'buffer [u8],
    http_version: &'buffer [u8],
    // TODO: headers
}

impl<'buffer> Display for Request<'buffer> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}\r\n",
            self.method,
            from_utf8(self.uri).unwrap(),
            from_utf8(&self.http_version).unwrap()
        )
    }
}

impl<'buffer> Request<'buffer> {
    pub fn parse<'source>(source: &'source [u8]) -> Result<Request<'buffer>, ParseError>
    where
        'source: 'buffer,
    {
        match parser::request_line(source) {
            Ok((_, req)) => Ok(req),
            Err(nom::Err::Incomplete(_)) => Err(ParseError::Incomplete),
            _ => Err(ParseError::Malformed),
        }
    }
}

pub struct Response<'buffer> {
    status_code: u16,
    reason: &'buffer [u8],
    body: &'buffer [u8],
    // TODO: headers
}

impl<'buffer> Response<'buffer> {
    pub fn new(status_code: u16, reason: &'buffer [u8], body: &'buffer [u8]) -> Response<'buffer> {
        assert!(reason.len() <= 26); // no one needs more than this, right?

        Response {
            status_code,
            reason,
            body,
        }
    }

    pub fn send(self, socket: &Socket) -> Result<(), ()> {
        // Using 3 writes here, not sure if that's optimal.
        // TODO: proper error handling
        let mut status_line_buffer = [32u8; 8 + 1 + 3 + 1 + 26 + 2]; // http version + status code + reason + CR LF

        // HTTP version
        status_line_buffer[0..8].copy_from_slice("HTTP/1.1".as_bytes());

        // status code
        status_line_buffer[9] = b'0' + (self.status_code / 100 % 10) as u8;
        status_line_buffer[10] = b'0' + (self.status_code / 10 % 10) as u8;
        status_line_buffer[11] = b'0' + (self.status_code % 10) as u8;

        // reason
        let reason_end = 13 + self.reason.len();
        status_line_buffer[13..reason_end].copy_from_slice(self.reason);

        // CR LF
        status_line_buffer[reason_end] = b'\r';
        status_line_buffer[reason_end + 1] = b'\n';

        socket.write(&status_line_buffer[0..reason_end + 2])?;
        socket.write("\r\n".as_bytes())?;
        socket.write(self.body)?;

        Ok(())
    }
}

mod parser {
    use crate::http::{Method, Request};
    use nom::branch::alt;
    use nom::bytes::streaming::{is_a, tag};
    use nom::combinator::{map, value};
    use nom::sequence::{separated_pair, terminated};
    use nom::IResult;

    pub fn request_line(input: &[u8]) -> IResult<&[u8], Request> {
        map(
            separated_pair(
                method,
                tag(&[b' ']),
                separated_pair(
                    uri,
                    tag(&[b' ']),
                    terminated(http_version, tag(&[b'\r', b'\n'])),
                ),
            ),
            |(method, (uri, http_version))| Request {
                method,
                uri,
                http_version,
            },
        )(input)
    }

    fn method(input: &[u8]) -> IResult<&[u8], Method> {
        alt((
            // TODO: rest of the HTTP methods
            value(Method::Get, tag("GET".as_bytes())),
            value(Method::Post, tag("POST".as_bytes())),
        ))(input)
    }

    fn uri(input: &[u8]) -> IResult<&[u8], &[u8]> {
        // TODO: proper URI parsing
        is_a("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=")(
            input,
        )
    }

    fn http_version(input: &[u8]) -> IResult<&[u8], &[u8]> {
        // TODO: proper HTTP version parsing
        tag("HTTP/1.1".as_bytes())(input)
    }

    #[cfg(test)]
    mod tests {
        use crate::http::parser::request_line;
        use crate::http::{Method, Request};
        use nom::Finish;

        #[test]
        fn parse_request_line() {
            assert_eq!(
                request_line("GET / HTTP/1.1\r\n".as_bytes()).unwrap(),
                (
                    &[] as &[u8],
                    Request {
                        method: Method::Get,
                        uri: "/".as_bytes(),
                        http_version: "HTTP/1.1".as_bytes()
                    }
                )
            );
        }

        #[test]
        #[should_panic]
        fn faulty_request_line() {
            request_line("GET / HTTP/2.0\r\n".as_bytes()).unwrap();
        }
    }
}
