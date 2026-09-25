//! OpenID Connect tools

use super::user::UserDetails;
use openid::{CompactJson, biscuit::SingleOrMultiple};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// An OIDC access token, containing the claims that we need.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessTokenClaims {
    #[serde(default)]
    pub azp: Option<String>,
    pub sub: String,
    pub iss: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<SingleOrMultiple<String>>,

    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub auth_time: Option<i64>,

    #[serde(flatten)]
    pub extended_claims: Value,
}

impl CompactJson for AccessTokenClaims {}

/// A validated access token, including post-processing according to our configuration.
#[derive(Clone, Debug)]
pub struct ValidatedAccessToken {
    pub access_token: AccessTokenClaims,
    pub permissions: Vec<String>,
}

impl AccessTokenClaims {
    /// Get the verified e-mail address from the `email` claim.
    ///
    /// The address is only returned if the `email_verified` claim is `true`.
    pub fn verified_email(&self) -> Option<&str> {
        let verified = self
            .extended_claims
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if verified {
            self.extended_claims.get("email").and_then(Value::as_str)
        } else {
            None
        }
    }
}

impl From<ValidatedAccessToken> for UserDetails {
    fn from(token: ValidatedAccessToken) -> Self {
        let email = token.access_token.verified_email().map(ToString::to_string);
        Self {
            id: token.access_token.sub,
            permissions: token.permissions,
            issuer: Some(token.access_token.iss.to_string()),
            email,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    fn claims(extended: Value) -> AccessTokenClaims {
        let mut value = json!({
            "sub": "user-1",
            "iss": "https://sso.example.com/realms/acme",
            "exp": 0,
            "iat": 0,
        });
        if let (Some(value), Some(extended)) = (value.as_object_mut(), extended.as_object()) {
            value.extend(extended.clone());
        }
        serde_json::from_value(value).expect("must be valid claims")
    }

    #[test]
    fn verified_email() {
        let details: UserDetails = ValidatedAccessToken {
            access_token: claims(json!({"email": "a@acme.com", "email_verified": true})),
            permissions: vec![],
        }
        .into();
        assert_eq!(details.email.as_deref(), Some("a@acme.com"));
        assert_eq!(
            details.issuer.as_deref(),
            Some("https://sso.example.com/realms/acme")
        );
    }

    #[test]
    fn unverified_email() {
        for extended in [
            json!({"email": "a@acme.com"}),
            json!({"email": "a@acme.com", "email_verified": false}),
            json!({"email": "a@acme.com", "email_verified": "true"}),
            json!({"email_verified": true}),
        ] {
            let claims = claims(extended.clone());
            assert_eq!(claims.verified_email(), None, "{extended}");
        }
    }
}
