//! HTTP 1.1 Request parsing and response building

use crate::Socket;
use nom::combinator::ParserIterator;
use nom::IResult;
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

pub struct Date {
    weekday: u64,
    day: u64,
    month: u64,
    year: u64,
    time: (u64, u64, u64),
}

pub enum DateOrDelta {
    Date(Date),
    Delta(u64),
}

pub enum TransferCoding<'a> {
    Chunked,
    Extension(&'a [u8], TransfemParams<'a>),
}

pub struct TransfemParams<'a> {
    param_slice: &'a [u8],
}

impl<'a> TransfemParams<'a> {
    pub fn iter(
        &self,
    ) -> ParserIterator<
        &'a [u8],
        nom::error::Error<&'a [u8]>,
        impl FnMut(&'a [u8]) -> IResult<&'a [u8], (&'a [u8], &'a [u8])>,
    > {
        parser::params_iter(self.param_slice)
    }
}

mod parser {
    //! HTTP/1.1 parser, follows [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616)
    //!
    use crate::http::{Date, Method, Request, TransfemParams, TransferCoding};
    use nom::branch::alt;
    use nom::bytes::streaming::{is_a, is_not, tag, take};
    use nom::combinator::{iterator, map, not, opt, recognize, value, verify, ParserIterator};
    use nom::multi::{fold_many1, fold_many_m_n, many0_count, many1_count};
    use nom::sequence::{delimited, pair, preceded, separated_pair, terminated, tuple};
    use nom::{IResult, Parser};

    /// HTTP/1.1 Request parser
    pub fn request(input: &[u8]) -> IResult<&[u8], Request> {
        request_line(input)
    }

    /// Build an iterator over transfer coding parameters for given input
    pub fn params_iter<'a>(
        input: &'a [u8],
    ) -> ParserIterator<
        &'a [u8],
        nom::error::Error<&'a [u8]>,
        impl FnMut(&'a [u8]) -> IResult<&'a [u8], (&'a [u8], &'a [u8])>,
    > {
        iterator(
            input,
            preceded(
                nom::bytes::complete::tag(";".as_bytes()),
                complete::parameter(),
            ),
        )
    }

    // macro because I don't feel like manually typing lifetimes
    macro_rules! parser {
        (
            $(
                $(#[$meta:meta])*
                $name:ident -> $return:ty; $body:expr
            )+
        ) => {
            $(
                $(#[$meta])*
                fn $name<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], $return> {
                    $body
                }
            )+

            mod complete {
                    use super::{ignore, integer_fixed};
                    use crate::http::{Date, Method, Request, TransfemParams, TransferCoding};
                    use nom::branch::alt;
                    use nom::bytes::complete::{is_a, is_not, tag, take};
                    use nom::combinator::{iterator, map, not, opt, recognize, value, verify, ParserIterator};
                    use nom::multi::{fold_many1, fold_many_m_n, many0_count, many1_count};
                    use nom::sequence::{delimited, pair, preceded, separated_pair, terminated, tuple};
                    use nom::IResult;

                    $(
                    pub(super) fn $name<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], $return> {
                        $body
                    }
                )+
            }
        };
    }

    fn ignore<'s, O>(
        parser: impl FnMut(&'s [u8]) -> IResult<&[u8], O>,
    ) -> impl FnMut(&'s [u8]) -> IResult<&[u8], ()> {
        value((), parser)
    }

    /// Captures a fixed-digit integer and converts it to u64
    fn integer_fixed<'s>(count: usize) -> impl Parser<&'s [u8], u64, nom::error::Error<&'s [u8]>> {
        fold_many_m_n(count, count, digit(), || 0u64, |acc, d| acc * 10 + d as u64)
    }

    // Basic rules

    parser!(
        /// Any 8-bit sequence of data
        octet -> u8;
        map(take(1usize), |slice: &[u8]| slice[0])

        /// Any US-ASCII character (octets 0 - 127)
        char -> u8;
        verify(octet(), |byte| *byte <= 127u8)

        /// Any US-ASCII uppercase letter `A..Z`
        upalpha -> u8;
        verify(octet(), |byte| (b'A'..=b'Z').contains(byte))

        /// Any US-ASCII lowercase letter `a-z`
        loalpha -> u8;
        verify(octet(), |byte| (b'a'..=b'z').contains(byte))

        /// Any US-ASCII letter
        alpha -> u8;
        alt((upalpha(), loalpha()))

        /// Any US-ASCII digit `0-9`
        digit -> u8;
        map(verify(octet(), |byte| (b'0'..=b'9').contains(byte)), |byte| byte - b'0')

        /// Any US-ASCII control character `0..31` or DEL `127`
        ctl -> u8;
        verify(octet(), |byte| (0..=31).contains(byte) || *byte == 127u8)

        /// US-ASCII CR, carriage return `13`
        cr -> ();
        ignore(tag([13]))

        /// US-ASCII LF, linefeed `10`
        lf -> ();
        ignore(tag([10]))

        /// US-ASCII SP, space `32`
        sp -> ();
        ignore(tag([32]))

        /// US-ASCII HT, horizontal-tab `9`
        ht -> ();
        ignore(tag([9]))

        /// US-ASCII double-quote mark `34`
        dq -> ();
        ignore(tag([34]))

        /// End-of-line marker CR + LF
        ///
        /// HTTP/1.1 defines the sequence CR LF as the end-of-line marker for all
        /// protocol elements except the entity-body (see appendix 19.3 for
        /// tolerant applications). The end-of-line marker within an entity-body
        /// is defined by its associated media type, as described in section 3.7.
        crlf -> ();
        ignore(pair(cr(), lf()))

        /// Linear white space
        ///
        /// HTTP/1.1 header field values can be folded onto multiple lines if the
        /// continuation line begins with a space or horizontal tab. All linear
        /// white space, including folding, has the same semantics as SP. A
        /// recipient MAY replace any linear white space with a single SP before
        /// interpreting the field value or forwarding the message downstream.
        lws -> ();
        ignore(tuple((opt(crlf()), many1_count(alt((sp(), ht()))))))

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
            map(recognize(pair(not(ctl()), take(1usize))), |slice| slice[0])
        ))

        /// Hexadecimal numeric character.
        hex -> u8;
        alt((
            map(verify(octet(), |byte| (b'A'..=b'F').contains(byte)), |byte| byte - b'A' + 10),
            map(verify(octet(), |byte| (b'a'..=b'f').contains(byte)), |byte| byte - b'a' + 10),
            map(verify(octet(), |byte| (b'0'..=b'9').contains(byte)), |byte| byte - b'0'),
        ))

        /// Header field separators
        ///
        /// Many HTTP/1.1 header field values consist of words separated by LWS
        /// or special characters. These special characters MUST be in a quoted
        /// string to be used within a parameter value (as defined in section
        /// 3.6).
        separators -> u8;
        verify(octet(), |byte| [b'(', b')', b'<', b'>', b'@', b',', b';', b':', b'\\', b'"', b'/', b'[', b']', b'?', b'=', b'{', b'}', b' ', b'\t'].contains(byte))

        /// Header field tokens.
        ///
        /// Many HTTP/1.1 header field values consist of words separated by LWS
        /// or special characters. These special characters MUST be in a quoted
        /// string to be used within a parameter value (as defined in section
        /// 3.6).
        token -> &[u8];
        // TODO: is there a better way?
        recognize(
            many1_count(
                pair(
                    not(
                        alt((
                            ctl(),
                            separators()
                        ))
                    ),
                    take(1usize)
                )
            )
        )

        /// Comments can be included in some HTTP header fields by surrounding
        /// the comment text with parentheses. Comments are only allowed in
        /// fields containing "comment" as part of their field value definition.
        /// In all other fields, parentheses are considered part of the field
        /// value.
        comment -> &[u8];
        delimited(
            tag("(".as_bytes()),
            alt((
                recognize(many1_count(alt((
                    ctext(),
                    quoted_pair()
                )))),
                |input| comment()(input)
            )),
            tag(")".as_bytes())
        )

        /// Comment text
        ctext -> u8;
        verify(text(), |byte| *byte != b'(' && *byte != b')')

        /// Quoted character
        /// The backslash character ("\") MAY be used as a single-character
        /// quoting mechanism only within quoted-string and comment constructs.
        quoted_pair -> u8;
        preceded(tag(r"\".as_bytes()), char())

        // Protocol Parameters

        /// http version
        http_version -> (u8, u8);
        map(tuple((
            tag("HTTP/".as_bytes()),
            fold_many1(digit(), || 0, |acc, d| acc * 10 + d),
            tag(".".as_bytes()),
            fold_many1(digit(), || 0, |acc, d| acc * 10 + d),
        )), |(_, major, _, minor)| (major, minor))

        /// http date
        http_date -> Date;
        alt((
            rfc1132_date(),
            rfc850_date(),
            asctime_date()
        ))

        /// [RFC 1123](https://datatracker.ietf.org/doc/html/rfc1123#page-55) Date
        rfc1132_date -> Date;
        map(
            tuple((
                wkday(),
                tag(",".as_bytes()),
                sp(),
                date1(),
                sp(),
                time(),
                sp(),
                tag("GMT".as_bytes())
            )),
            |(weekday, _, _, (day, month, year), _, time, _, _)| Date {
                weekday,
                day,
                month,
                year,
                time
            }
        )

        /// [RFC 850](https://datatracker.ietf.org/doc/html/rfc850) Date
        rfc850_date -> Date;
        map(
            tuple((
                weekday(),
                tag(",".as_bytes()),
                sp(),
                date2(),
                sp(),
                time(),
                sp(),
                tag("GMT".as_bytes())
            )),
            |(weekday, _, _, (day, month, year), _, time, _, _)| Date {
                weekday,
                day,
                month,
                year,
                time
            }
        )

        /// `asctime()` Date
        asctime_date -> Date;
        map(
            tuple((
                wkday(), sp(), date3(), sp(), time(), sp(), integer_fixed(4)
            )),
            |(weekday, _, (month, day), _, time, _, year)| Date {
                weekday,
                day,
                month,
                year,
                time,
            }
        )

        /// day month year (e.g., 02 Jun 1982)
        date1 -> (u64, u64, u64);
        tuple((
            terminated(integer_fixed(2), sp()),
            terminated(month(), sp()),
            integer_fixed(4),
        ))

        /// day-month-year (e.g., 02-Jun-82)
        date2 -> (u64, u64, u64);
        tuple((
            terminated(integer_fixed(2), tag("-".as_bytes())),
            terminated(month(), tag("-".as_bytes())),
            integer_fixed(2)
        ))

        /// month day (e.g., Jun 2)
        date3 -> (u64, u64);
        tuple((terminated(month(), sp()), alt((integer_fixed(2), preceded(sp(), integer_fixed(1))))))

        /// Time
        ///
        /// 00:00:00 - 23:59:59
        time -> (u64, u64, u64);
        tuple((
            terminated(integer_fixed(2), tag(":".as_bytes())),
            terminated(integer_fixed(2), tag(":".as_bytes())),
            integer_fixed(2)
        ))

        /// Short day of week
        wkday -> u64;
        alt((
            value(0, tag("Mon".as_bytes())),
            value(1, tag("Tue".as_bytes())),
            value(2, tag("Wed".as_bytes())),
            value(3, tag("Thu".as_bytes())),
            value(4, tag("Fri".as_bytes())),
            value(5, tag("Sat".as_bytes())),
            value(6, tag("Sun".as_bytes())),
        ))

        /// Long day of week
        weekday -> u64;
        alt((
            value(0, tag("Monday".as_bytes())),
            value(1, tag("Tuesday".as_bytes())),
            value(2, tag("Wednesday".as_bytes())),
            value(3, tag("Thursday".as_bytes())),
            value(4, tag("Friday".as_bytes())),
            value(5, tag("Saturday".as_bytes())),
            value(6, tag("Sunday".as_bytes())),
        ))

        /// Short month name
        month -> u64;
        alt((
            value(0, tag("Jan".as_bytes())),
            value(1, tag("Feb".as_bytes())),
            value(2, tag("Mar".as_bytes())),
            value(3, tag("Apr".as_bytes())),
            value(4, tag("May".as_bytes())),
            value(5, tag("Jun".as_bytes())),
            value(6, tag("Jul".as_bytes())),
            value(7, tag("Aug".as_bytes())),
            value(8, tag("Sep".as_bytes())),
            value(9, tag("Oct".as_bytes())),
            value(10, tag("Nov".as_bytes())),
            value(11, tag("Dec".as_bytes()))
        ))

        /// Delta seconds
        delta_seconds -> u64;
        fold_many1(digit(), || 0u64, |acc, d| acc * 10 + d as u64)

        /// Character encoding / Character set
        charset -> &[u8];
        token()

        /// Content codings
        content_coding -> &[u8];
        token()

        /// Transfer codings
        ///
        /// Returns the transfer coding, a iterator over parameters
        transfer_coding -> TransferCoding<'a>;
        alt((
            map(tag("chunked".as_bytes()), |_| TransferCoding::Chunked),
            map(
                pair(
                    token(),
                    recognize(many0_count(preceded(tag(";".as_bytes()), parameter())))
                ),
                |(extension, param_slice)| TransferCoding::Extension(
                    extension,
                    TransfemParams { param_slice }
                )
            )
        ))

        /// Transfer extension parameter
        parameter -> (&[u8], &[u8]);
        // TODO: Quoted string as alt value here
        separated_pair(token(), tag("=".as_bytes()), token())
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

    #[cfg(test)]
    mod tests {
        use crate::http::parser::{comment, hex, request_line, transfer_coding};
        use crate::http::{Method, Request, TransferCoding};
        use nom::Finish;

        fn eof(input: &str) -> (&[u8], &[u8]) {
            (&[], input.as_bytes())
        }

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

        #[test]
        fn parse_comment() {
            assert_eq!(
                comment()("(normal comment)".as_bytes()).unwrap(),
                eof("normal comment")
            );
        }

        //#[test]
        fn parse_comment_with_quote() {
            assert_eq!(
                comment()(r"(comment with quoted \()".as_bytes()).unwrap(),
                eof(r"comment with quoted \(")
            );
        }

        //#[test]
        fn parse_comment_with_comment() {
            assert_eq!(
                comment()(r"(comment with recursive (comment))".as_bytes()).unwrap(),
                eof(r"comment")
            );
        }

        #[test]
        fn parse_transfer_coding_params() {
            let mut buffer = Vec::new();
            let (tail, params) =
                transfer_coding()("chonked;boi=chonky;others=chonky_too\n".as_bytes()).unwrap();

            assert_eq!(tail, &[10]);

            match params {
                TransferCoding::Extension(coding, params) => {
                    assert_eq!(coding, "chonked".as_bytes());
                    let mut iter = params.iter();
                    for (k, v) in &mut iter {
                        dbg!((k, v));
                        buffer.push((k, v));
                    }

                    iter.finish().unwrap();

                    assert_eq!(
                        buffer.as_slice(),
                        &[
                            ("boi".as_bytes(), "chonky".as_bytes()),
                            ("others".as_bytes(), "chonky_too".as_bytes())
                        ]
                    );
                }
                _ => panic!("parsing failed"),
            }
        }
    }
}
