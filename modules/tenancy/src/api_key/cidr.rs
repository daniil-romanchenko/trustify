//! Network ranges in CIDR notation, like `10.0.0.0/8` or `2001:db8::/32`.

use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
    str::FromStr,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid network range '{0}', expected CIDR notation like '10.0.0.0/8'")]
pub struct CidrError(String);

/// A network range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Check if the range contains the address.
    ///
    /// IPv4 addresses mapped into IPv6 are handled as IPv4 addresses.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = mask_u32(self.prefix);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = mask_u128(self.prefix);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

fn mask_u32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask_u128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || CidrError(s.to_string());

        let (network, prefix) = match s.split_once('/') {
            Some((network, prefix)) => (network, Some(prefix)),
            None => (s, None),
        };

        let network: IpAddr = network.parse().map_err(|_| err())?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().map_err(|_| err())?,
            None => max,
        };
        if prefix > max {
            return Err(err());
        }

        Ok(Self { network, prefix })
    }
}

impl Display for Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("10.0.0.0/8", "10.1.2.3", true)]
    #[case("10.0.0.0/8", "11.0.0.1", false)]
    #[case("192.168.1.10", "192.168.1.10", true)]
    #[case("192.168.1.10", "192.168.1.11", false)]
    #[case("0.0.0.0/0", "203.0.113.7", true)]
    #[case("10.0.0.0/8", "::ffff:10.0.0.1", true)]
    #[case("2001:db8::/32", "2001:db8::1", true)]
    #[case("2001:db8::/32", "2001:db9::1", false)]
    #[case("::/0", "10.0.0.1", false)]
    fn contains(#[case] cidr: &str, #[case] address: &str, #[case] expected: bool) {
        let cidr: Cidr = cidr.parse().expect("valid CIDR");
        let address: IpAddr = address.parse().expect("valid address");
        assert_eq!(cidr.contains(address), expected);
    }

    #[rstest]
    #[case("10.0.0.0/33")]
    #[case("10.0.0/8")]
    #[case("2001:db8::/129")]
    #[case("foo")]
    #[case("10.0.0.0/")]
    fn invalid(#[case] cidr: &str) {
        assert!(cidr.parse::<Cidr>().is_err());
    }
}
