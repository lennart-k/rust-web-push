use http::uri::Uri;
use jsonwebtoken::{Header, encode};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{error::WebPushError, vapid::VapidKey};

/// A struct representing a VAPID signature. Should be generated using the
/// [VapidSignatureBuilder](struct.VapidSignatureBuilder.html).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VapidSignature {
    /// The signed JWT, base64-encoded
    pub auth_t: String,
    /// The public key bytes
    pub auth_k: Vec<u8>,
}

/// JWT claims object. Custom claims are implemented as a map.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Claims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(flatten)]
    pub custom: BTreeMap<String, Value>,
}

impl Claims {
    pub fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self {
            exp: Some(now + 43200),
            nbf: Some(now),
            iat: Some(now),
            ..Default::default()
        }
    }
}

pub struct VapidSigner {}

impl VapidSigner {
    /// Create a signature with a given key. Sets the default audience from the
    /// endpoint host and sets the expiry in twelve hours. Values can be
    /// overwritten by adding the `aud` and `exp` claims.
    pub fn sign(key: VapidKey, endpoint: &Uri, mut claims: Claims) -> Result<VapidSignature, WebPushError> {
        if claims.aud.is_none() {
            //Add audience if not provided.
            let audience = format!("{}://{}", endpoint.scheme_str().unwrap(), endpoint.host().unwrap());
            claims.aud = Some(audience);
        }

        // Add sub if not provided as some browsers (like firefox) require it even though the API doesn't say its needed >:[
        if claims.sub.is_none() {
            claims.sub = Some("mailto:example@example.com".to_string());
        }

        log::trace!("Using jwt: {:?}", claims);

        let auth_k = key.public_key();

        //Generate JWT signature
        let encoding_key = key.encoding_key()?;

        let header = Header::new(jsonwebtoken::Algorithm::ES256);
        let auth_t = encode(&header, &claims, &encoding_key).map_err(|_| WebPushError::InvalidClaims)?;

        Ok(VapidSignature { auth_t, auth_k })
    }
}

#[cfg(test)]
mod tests {}
