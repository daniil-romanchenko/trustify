//! Handling of e-mail addresses, which identify users.

/// Maximum length of an e-mail address, according to RFC 5321.
const MAX_EMAIL_LENGTH: usize = 320;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EmailError {
    #[error("invalid e-mail address '{0}'")]
    Invalid(String),
}

/// Normalize an e-mail address into the form it is stored as.
///
/// This trims surrounding whitespace and lower-cases the address. It performs a basic syntax
/// check, but does not try to fully validate the address. Addresses are expected to come from an
/// identity provider which already validated them.
pub fn normalize_email(email: &str) -> Result<String, EmailError> {
    let email = email.trim().to_lowercase();

    let valid = email.len() <= MAX_EMAIL_LENGTH
        && !email.contains(char::is_whitespace)
        && match email.split_once('@') {
            Some((local, domain)) => {
                !local.is_empty()
                    && !domain.is_empty()
                    && !domain.contains('@')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
            }
            None => false,
        };

    if valid {
        Ok(email)
    } else {
        Err(EmailError::Invalid(email))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("alice@acme.com", Some("alice@acme.com"))]
    #[case("  Alice@ACME.com ", Some("alice@acme.com"))]
    #[case("alice@localhost", Some("alice@localhost"))]
    #[case("alice", None)]
    #[case("@acme.com", None)]
    #[case("alice@", None)]
    #[case("alice@@acme.com", None)]
    #[case("al ice@acme.com", None)]
    #[case("alice@.acme.com", None)]
    fn normalize(#[case] input: &str, #[case] expected: Option<&str>) {
        assert_eq!(normalize_email(input).ok().as_deref(), expected);
    }
}
