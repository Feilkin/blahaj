//! IPv4 address handling

use std::convert::TryFrom;
use std::fmt::{Display, Formatter};

pub const AF_INET: u64 = 2;

/// IPv4 Address struct
#[derive(Debug)]
#[repr(C)]
pub struct AddressV4 {
    /// This will always be AF_INET
    family: u16,
    port: u16,
    address: u32,
    // this is padding?
    _zero: [u8; 8],
}

impl Display for AddressV4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}:{}",
            self.address >> 24,
            self.address >> 16 & 0xFF,
            self.address >> 8 & 0xFF,
            self.address & 0xFF,
            self.port
        )
    }
}

impl TryFrom<&str> for AddressV4 {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        AddressV4::parse(value)
    }
}

impl AddressV4 {
    /// Parses a IPv4 address in dot-decimal notation
    pub fn parse(address: &str) -> Result<AddressV4, ()> {
        // TODO: error handling
        let (address, port) = parser::address_and_port(address).map_err(|_| ())?;

        Ok(AddressV4::from_raw(address, port))
    }

    pub fn empty() -> AddressV4 {
        AddressV4::from_raw(0, 0)
    }

    pub fn from_raw(address: u32, port: u16) -> AddressV4 {
        AddressV4 {
            family: AF_INET as u16,
            port,
            address,
            _zero: [0; 8],
        }
    }
}

mod parser {
    use nom::bytes::complete::tag;
    use nom::character::complete::digit1;
    use nom::combinator::{all_consuming, map, map_res};
    use nom::lib::std::str::FromStr;
    use nom::sequence::{separated_pair, terminated, tuple};
    use nom::{error::Error, Finish, IResult};

    pub fn address_and_port(input: &str) -> Result<(u32, u16), Error<&str>> {
        let (_, address_and_port) =
            all_consuming(separated_pair(address, tag(":"), port))(input).finish()?;
        Ok(address_and_port)
    }

    fn address(input: &str) -> IResult<&str, u32> {
        map(
            tuple((
                terminated(octet, tag(".")),
                terminated(octet, tag(".")),
                terminated(octet, tag(".")),
                octet,
            )),
            |(a, b, c, d)| u32::from_ne_bytes([a, b, c, d]),
        )(input)
    }

    fn port(input: &str) -> IResult<&str, u16> {
        map_res(digit1, |digit| {
            u16::from_str(digit).and_then(|bytes| Ok(bytes.to_be()))
        })(input)
    }

    fn octet(input: &str) -> IResult<&str, u8> {
        map_res(digit1, |digit| u8::from_str(digit))(input)
    }

    #[cfg(test)]
    mod tests {
        use crate::ip::parser::address_and_port;

        #[test]
        fn parse_address_and_port() {
            assert_eq!(address_and_port("127.0.0.1:8080"), Ok((0x0100007F, 36895)));
        }
    }
}
