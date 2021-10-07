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
    http_version: (u8, u8),
    // TODO: headers
}

impl<'buffer> Display for Request<'buffer> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}.{}\r\n",
            self.method,
            from_utf8(self.uri).unwrap(),
            self.http_version.0,
            self.http_version.1,
        )
    }
}

impl<'buffer> Request<'buffer> {
    pub fn parse<'source>(source: &'source [u8]) -> Result<Request<'buffer>, ParseError>
    where
        'source: 'buffer,
    {
        match parser::request(source) {
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
    //! HTTP/1.1 parser, follows [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616)
    //!
    use crate::http::{Method, Request};
    use nom::branch::alt;
    use nom::bytes::streaming::{is_a, is_not, tag, take};
    use nom::combinator::{map, not, opt, recognize, value, verify};
    use nom::multi::{fold_many1, many1_count};
    use nom::sequence::{delimited, pair, separated_pair, terminated, tuple};
    use nom::{FindToken, IResult};

    // I wanted to use type alias like this:
    // type Parser<Output> = impl FnMut(&[u8]) -> IResult<&[u8], Output>;
    // but I didn't get it to work so time for a macro workaround

    macro_rules! parser {
        (
            $(#[$meta:meta])*
            $name:ident -> $return:ty; $body:expr
        ) => {
            $(#[$meta])*
            fn $name<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], $return> {
                $body
            }
        };
    }

    pub fn request(input: &[u8]) -> IResult<&[u8], Request> {
        request_line(input)
    }

    fn request_line(input: &[u8]) -> IResult<&[u8], Request> {
        map(
            separated_pair(
                method,
                tag(&[b' ']),
                separated_pair(
                    uri,
                    tag(&[b' ']),
                    terminated(http_version(), tag(&[b'\r', b'\n'])),
                ),
            ),
            |(method, (uri, http_version))| Request {
                method,
                uri,
                http_version,
            },
        )(input)
    }

    fn ignore<'s, O>(
        parser: impl FnMut(&'s [u8]) -> IResult<&[u8], O>,
    ) -> impl FnMut(&'s [u8]) -> IResult<&[u8], ()> {
        value((), parser)
    }

    // Basic rules

    parser!(
        /// Any 8-bit sequence of data
        octet -> u8;
        map(take(1usize), |slice: &[u8]| slice[0])
    );

    parser!(
        /// Any US-ASCII character (octets 0 - 127)
        char -> u8;
        verify(octet(), |byte| *byte <= 127u8)
    );

    parser!(
        /// Any US-ASCII uppercase letter `A..Z`
        upalpha -> u8;
        verify(octet(), |byte| (b'A'..=b'Z').contains(byte))
    );

    parser!(
        /// Any US-ASCII lowercase letter `a-z`
        loalpha -> u8;
        verify(octet(), |byte| (b'a'..=b'z').contains(byte))
    );

    parser!(
        /// Any US-ASCII letter
        alpha -> u8;
        alt((upalpha(), loalpha()))
    );

    parser!(
        /// Any US-ASCII digit `0-9`
        digit -> u8;
        map(verify(octet(), |byte| (b'0'..=b'9').contains(byte)), |byte| byte - b'0')
    );

    parser!(
        /// Any US-ASCII control character `0..31` or DEL `127`
        ctl -> u8;
        verify(octet(), |byte| (0..=31).contains(byte) || *byte == 127u8)
    );

    parser!(
        /// US-ASCII CR, carriage return `13`
        cr -> ();
        ignore(tag([13]))
    );

    parser!(
        /// US-ASCII LF, linefeed `10`
        lf -> ();
        ignore(tag([10]))
    );

    parser!(
        /// US-ASCII SP, space `32`
        sp -> ();
        ignore(tag([32]))
    );

    parser!(
        /// US-ASCII HT, horizontal-tab `9`
        ht -> ();
        ignore(tag([9]))
    );

    parser!(
        /// US-ASCII double-quote mark `34`
        dq -> ();
        ignore(tag([34]))
    );

    parser!(
        /// End-of-line marker CR + LF
        ///
        /// HTTP/1.1 defines the sequence CR LF as the end-of-line marker for all
        /// protocol elements except the entity-body (see appendix 19.3 for
        /// tolerant applications). The end-of-line marker within an entity-body
        /// is defined by its associated media type, as described in section 3.7.
        crlf -> ();
        ignore(pair(cr(), lf()))
    );

    parser!(
        /// Linear white space
        ///
        /// HTTP/1.1 header field values can be folded onto multiple lines if the
        /// continuation line begins with a space or horizontal tab. All linear
        /// white space, including folding, has the same semantics as SP. A
        /// recipient MAY replace any linear white space with a single SP before
        /// interpreting the field value or forwarding the message downstream.
        lws -> ();
        ignore(tuple((opt(crlf()), many1_count(alt((sp(), ht()))))))
    );

    parser!(
        /// The TEXT rule is only used for descriptive field contents and values
        /// that are not intended to be interpreted by the message parser. Words
        /// of *TEXT MAY contain characters from character sets other than ISO-
        /// [8859-1](https://datatracker.ietf.org/doc/html/rfc2616#ref-22) only when encoded according to the rules of [RFC 2047](https://datatracker.ietf.org/doc/html/rfc2616#ref-14).
        ///
        /// A CRLF is allowed in the definition of TEXT only as part of a header
        /// field continuation. It is expected that the folding LWS will be
        /// replaced with a single SP before interpretation of the TEXT value.
        text -> u8;
        alt((
            value(b' ', lws()),
            map(recognize(not(ctl())), |slice| slice[0])
        ))
    );

    parser!(
        /// Hexadecimal numeric character.
        hex -> u8;
        alt((
            map(verify(octet(), |byte| (b'A'..=b'F').contains(byte)), |byte| byte - b'A' + 10),
            map(verify(octet(), |byte| (b'a'..=b'f').contains(byte)), |byte| byte - b'a' + 10),
            map(verify(octet(), |byte| (b'0'..=b'9').contains(byte)), |byte| byte - b'0'),
        ))
    );

    parser!(
        /// Header field separators
        ///
        /// Many HTTP/1.1 header field values consist of words separated by LWS
        /// or special characters. These special characters MUST be in a quoted
        /// string to be used within a parameter value (as defined in section
        /// 3.6).
        separators -> u8;
        verify(octet(), |byte| [b'(', b')', b'<', b'>', b'@', b',', b';', b':', b'\\', b'"', b'/', b'[', b']', b'?', b'=', b'{', b'}', b' ', b'\t'].contains(byte))
    );

    parser!(
        /// Header field tokens.
        ///
        /// Many HTTP/1.1 header field values consist of words separated by LWS
        /// or special characters. These special characters MUST be in a quoted
        /// string to be used within a parameter value (as defined in section
        /// 3.6).
        token -> &[u8];
        // TODO: is there a better way?
        recognize(many1_count(not(
            alt((ctl(), separators()))
        )))
    );

    parser!(
        /// Comments can be included in some HTTP header fields by surrounding
        /// the comment text with parentheses. Comments are only allowed in
        /// fields containing "comment" as part of their field value definition.
        /// In all other fields, parentheses are considered part of the field
        /// value.
        comment -> &[u8];
        delimited(
            tag("(".as_bytes()),
            recognize(many1_count(alt((
                ctext(),
                quoted_pair()
            )))),
            tag(")".as_bytes())
        )
    );

    parser!(
        /// Comment text
        ctext -> u8;
        verify(text(), |byte| *byte != b'(' && *byte != b')')
    );

    parser!(
        /// Quoted character
        /// The backslash character ("\") MAY be used as a single-character
        /// quoting mechanism only within quoted-string and comment constructs.
        quoted_pair -> u8;
        map(pair(tag("\\".as_bytes()), char()), |(_, byte)| byte)
    );

    // Protocol Parameters

    parser!(
        /// http version
        http_version -> (u8, u8);
        map(tuple((
            tag("HTTP/".as_bytes()),
            fold_many1(digit(), || 0, |acc, d| acc * 10 + d),
            tag(".".as_bytes()),
            fold_many1(digit(), || 0, |acc, d| acc * 10 + d),
        )), |(_, major, _, minor)| (major, minor))
    );

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

    #[cfg(test)]
    mod tests {
        use crate::http::parser::{hex, request_line};
        use crate::http::{Method, Request};
        use nom::Finish;

        #[test]
        fn parse_hex() {
            assert_eq!(hex()(&[b'A']), Ok((&[] as &[u8], 10)));
            assert_eq!(hex()(&[b'b']), Ok((&[] as &[u8], 11)));
            assert_eq!(hex()(&[b'3']), Ok((&[] as &[u8], 3)));
            assert_eq!(hex()(&[b'f']), Ok((&[] as &[u8], 15)));
        }

        #[test]
        fn parse_request_line() {
            assert_eq!(
                request_line("GET / HTTP/1.1\r\n".as_bytes()).unwrap(),
                (
                    &[] as &[u8],
                    Request {
                        method: Method::Get,
                        uri: "/".as_bytes(),
                        http_version: (1, 1)
                    }
                )
            );
        }
    }
}
