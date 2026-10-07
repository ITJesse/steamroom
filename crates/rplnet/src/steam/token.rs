//! Reading the expiry of a Steam refresh token.
//!
//! Steam's tokens are JWTs. Only the `exp` claim of the payload is read; the
//! signature is Steam's business and is not checked here.

use base64::Engine;

/// Expiry of a Steam refresh token, in seconds since 1970, or `None` when the
/// token is not a JWT with an `exp` claim.
#[uniffi::export]
pub fn rplnet_token_expiry(token: String) -> Option<i64> {
    expiry(&token)
}

pub(crate) fn expiry(token: &str) -> Option<i64> {
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("exp")?.as_i64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let encode = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
        format!(
            "{}.{}.signature",
            encode(r#"{"typ":"JWT","alg":"EdDSA"}"#),
            encode(payload)
        )
    }

    #[test]
    fn reads_exp() {
        let token = jwt(r#"{"iss":"steam","sub":"76561197960287930","exp":1806192000}"#);
        assert_eq!(rplnet_token_expiry(token), Some(1806192000));
    }

    #[test]
    fn padded_payload_is_accepted() {
        let token = jwt(r#"{"exp":12}"#);
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        parts[1].push_str("==");
        assert_eq!(expiry(&parts.join(".")), Some(12));
    }

    #[test]
    fn anything_else_has_no_expiry() {
        assert_eq!(expiry(""), None);
        assert_eq!(expiry("not-a-jwt"), None);
        assert_eq!(expiry(&jwt(r#"{"sub":"1"}"#)), None);
        assert_eq!(expiry(&jwt(r#"{"exp":"soon"}"#)), None);
        assert_eq!(expiry(&format!("{}.extra", jwt(r#"{"exp":1}"#))), None);
        assert_eq!(expiry("a.!!!.c"), None);
    }
}
