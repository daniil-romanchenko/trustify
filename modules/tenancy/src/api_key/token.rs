//! The format of API key tokens.
//!
//! A token has the form `tfy_<key id>_<secret>_<checksum>`. The key ID is public, and used to
//! look up the key. Only an HMAC of the secret is stored. The checksum allows detecting mistyped
//! or truncated tokens without a lookup, and makes the tokens easy to detect for secret scanners.

use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};

/// The prefix of every token.
pub const PREFIX: &str = "tfy_";

const KEY_ID_BYTES: usize = 10;
const SECRET_BYTES: usize = 32;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("not an API key")]
    NotAnApiKey,
    #[error("malformed API key")]
    Malformed,
    #[error("API key checksum mismatch")]
    Checksum,
    #[error("unable to generate random data")]
    Random,
}

/// A parsed, or newly generated, token.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub key_id: String,
    pub secret: String,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("key_id", &self.key_id)
            .field("secret", &"***")
            .finish()
    }
}

impl Token {
    /// Generate a new random token.
    pub fn generate() -> Result<Self, TokenError> {
        let rng = SystemRandom::new();

        let mut key_id = [0u8; KEY_ID_BYTES];
        let mut secret = [0u8; SECRET_BYTES];
        rng.fill(&mut key_id).map_err(|_| TokenError::Random)?;
        rng.fill(&mut secret).map_err(|_| TokenError::Random)?;

        Ok(Self {
            key_id: base32(&key_id),
            secret: base32(&secret),
        })
    }

    /// Parse a token, validating its checksum.
    pub fn parse(token: &str) -> Result<Self, TokenError> {
        let rest = token.strip_prefix(PREFIX).ok_or(TokenError::NotAnApiKey)?;

        let mut parts = rest.split('_');
        let (Some(key_id), Some(secret), Some(checksum), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TokenError::Malformed);
        };

        let valid = |value: &str, bytes: usize| {
            value.len() == encoded_len(bytes) && value.bytes().all(|b| ALPHABET.contains(&b))
        };
        if !valid(key_id, KEY_ID_BYTES) || !valid(secret, SECRET_BYTES) || !valid(checksum, 4) {
            return Err(TokenError::Malformed);
        }

        let result = Self {
            key_id: key_id.to_string(),
            secret: secret.to_string(),
        };

        if result.checksum() != checksum {
            return Err(TokenError::Checksum);
        }

        Ok(result)
    }

    /// The full token, as handed out to the user.
    pub fn expose(&self) -> String {
        format!("{}_{}", self.unchecked(), self.checksum())
    }

    fn unchecked(&self) -> String {
        format!("{PREFIX}{}_{}", self.key_id, self.secret)
    }

    fn checksum(&self) -> String {
        base32(&crc32(self.unchecked().as_bytes()).to_be_bytes())
    }
}

/// The server side secret, used to derive the stored HMAC from the secret part of a token.
#[derive(Clone)]
pub struct Pepper(hmac::Key);

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pepper(***)")
    }
}

impl Pepper {
    pub fn new(value: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, value))
    }

    /// Create the HMAC of a token's secret.
    pub fn sign(&self, token: &Token) -> Vec<u8> {
        hmac::sign(&self.0, token.secret.as_bytes())
            .as_ref()
            .to_vec()
    }

    /// Verify, in constant time, that the stored HMAC matches the token's secret.
    pub fn verify(&self, token: &Token, secret_hmac: &[u8]) -> bool {
        hmac::verify(&self.0, token.secret.as_bytes(), secret_hmac).is_ok()
    }
}

const fn encoded_len(bytes: usize) -> usize {
    (bytes * 8).div_ceil(5)
}

/// Lower-case RFC 4648 base32, without padding.
fn base32(data: &[u8]) -> String {
    let mut result = String::with_capacity(encoded_len(data.len()));
    let mut buffer: u32 = 0;
    let mut bits = 0;

    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        result.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }

    result
}

/// CRC-32 (IEEE 802.3).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn base32_vectors() {
        // RFC 4648 test vectors, lower-cased and without padding
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"fo"), "mzxq");
        assert_eq!(base32(b"foo"), "mzxw6");
        assert_eq!(base32(b"foob"), "mzxw6yq");
        assert_eq!(base32(b"fooba"), "mzxw6ytb");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn crc32_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn roundtrip() -> anyhow::Result<()> {
        let token = Token::generate()?;
        let exposed = token.expose();

        assert!(exposed.starts_with("tfy_"));
        assert_eq!(exposed.len(), 4 + 16 + 1 + 52 + 1 + 7);
        assert_eq!(Token::parse(&exposed)?, token);
        assert!(!format!("{token:?}").contains(&token.secret));

        Ok(())
    }

    #[test]
    fn invalid() -> anyhow::Result<()> {
        let token = Token::generate()?.expose();

        assert_eq!(Token::parse("Bearer foo"), Err(TokenError::NotAnApiKey));
        assert_eq!(Token::parse("tfy_abc"), Err(TokenError::Malformed));
        assert_eq!(
            Token::parse(&token[..token.len() - 1]),
            Err(TokenError::Malformed)
        );
        assert_eq!(
            Token::parse(&format!("{token}_extra")),
            Err(TokenError::Malformed)
        );

        // flip one character of the secret
        let mut tampered = token.into_bytes();
        tampered[30] = if tampered[30] == b'a' { b'b' } else { b'a' };
        assert_eq!(
            Token::parse(&String::from_utf8(tampered)?),
            Err(TokenError::Checksum)
        );

        Ok(())
    }

    #[test]
    fn pepper() -> anyhow::Result<()> {
        let token = Token::generate()?;
        let other = Token::generate()?;
        let pepper = Pepper::new(b"0123456789abcdef0123456789abcdef");

        let signed = pepper.sign(&token);
        assert!(pepper.verify(&token, &signed));
        assert!(!pepper.verify(&other, &signed));
        assert!(!Pepper::new(b"another pepper, of enough length").verify(&token, &signed));

        Ok(())
    }
}
