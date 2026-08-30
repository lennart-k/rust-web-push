use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use jsonwebtoken::EncodingKey;
use p256::{SecretKey, ecdsa::SigningKey, pkcs8::EncodePrivateKey};

use crate::WebPushError;

/// The P256 curve key pair used for VAPID ECDHSA.
#[derive(Clone)]
pub struct VapidKey(pub SecretKey);

impl VapidKey {
    pub fn new(ec_key: SecretKey) -> VapidKey {
        VapidKey(ec_key)
    }

    /// Gets the uncompressed public key bytes derived from this private key.
    pub fn public_key(&self) -> Vec<u8> {
        SigningKey::from(&self.0).verifying_key().to_sec1_bytes().to_vec()
    }

    /// Builds a jsonwebtoken `EncodingKey` from the private key.
    pub(crate) fn encoding_key(&self) -> Result<EncodingKey, WebPushError> {
        let der = self.0.to_pkcs8_der().map_err(|_| WebPushError::InvalidCryptoKeys)?;
        Ok(EncodingKey::from_ec_der(der.as_bytes()))
    }

    /// Builds a jsonwebtoken `DecodingKey` from the private key.
    #[cfg(test)]
    pub(crate) fn decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, WebPushError> {
        use p256::pkcs8::EncodePublicKey;

        let der = self
            .0
            .public_key()
            .to_public_key_der()
            .map_err(|_| WebPushError::InvalidCryptoKeys)?;
        Ok(jsonwebtoken::DecodingKey::from_ec_der(der.as_bytes()))
    }

    /// Creates a new VapidKey from a DER-formatted private key.
    pub fn from_der(input: &[u8]) -> Result<Self, WebPushError> {
        Ok(Self(
            SecretKey::from_sec1_der(input).map_err(|_| WebPushError::InvalidCryptoKeys)?,
        ))
    }

    pub fn from_base64(encoded: &str) -> Result<Self, WebPushError> {
        Ok(Self(
            SecretKey::from_slice(
                &Base64UrlSafeNoPadding::decode_to_vec(encoded, None).map_err(|_| WebPushError::InvalidCryptoKeys)?,
            )
            .map_err(|_| WebPushError::InvalidCryptoKeys)?,
        ))
    }

    /// Reads the pem file as either format sec1 or pkcs8, then returns the decoded private key.
    pub fn from_pem(input: &str) -> Result<Self, WebPushError> {
        //Parse many PEM in the assumption of extra unneeded sections.
        Ok(Self(
            SecretKey::from_pem(input).map_err(|_| WebPushError::InvalidCryptoKeys)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::vapid::key::VapidKey;

    #[test]
    /// Tests that VapidKey derives the correct public key.
    fn test_public_key_derivation() {
        let pem = include_str!("../../resources/vapid_test_key.pem");
        let key = VapidKey::from_pem(pem).unwrap();

        assert_eq!(
            vec![
                4, 202, 53, 30, 162, 133, 234, 201, 12, 101, 140, 164, 174, 215, 189, 118, 234, 152, 192, 16, 244, 242,
                96, 208, 41, 59, 167, 70, 66, 93, 15, 123, 19, 39, 209, 62, 203, 35, 122, 176, 153, 79, 89, 58, 74, 54,
                26, 126, 203, 98, 158, 75, 170, 0, 52, 113, 126, 171, 124, 55, 237, 176, 165, 111, 181
            ],
            key.public_key()
        );
    }

    #[test]
    /// Tests that VapidKey clones properly.
    fn test_key_clones() {
        let pem = include_str!("../../resources/vapid_test_key.pem");
        let key = VapidKey::from_pem(pem).unwrap();
        let key2 = key.clone();

        assert_eq!(key.0.to_bytes(), key2.0.to_bytes())
    }
}
