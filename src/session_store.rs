// SPDX-License-Identifier: MIT

//! Encrypted session store in Cookie
//!
//! This session store is not mandatry for OpenID connect protocol itself,
//! but most of server side authentication use Cookie to store session information.
//! So I include this implementation here as optional feature.
//!
//! Session cookie encryption is very similar to
//! [cookie::PrivateJar](https://docs.rs/cookie/latest/cookie/struct.PrivateJar.html),
//! except for the following points:
//!
//! - Supports encryption key rotation
//! - Uses AES-GCM-SIV mode to mitigate the risk of nonce collision
//! - Uses MessagePack for efficient binary encoding

// payload_ver + key_id
const PREFIX_SIZE: usize = 2;
// nonce size
const NONCE_SIZE: usize = 12;
// authentication tag size
const AUTH_TAG_SIZE: usize = 16;
// minimum (payload len = 0)
const MINIMUM_ENCRYPTED_SIZE: usize = PREFIX_SIZE + NONCE_SIZE + AUTH_TAG_SIZE;
// minimum cookie size (base64 size)
const MINIMUM_COOKIE_VALUE_SIZE: usize = MINIMUM_ENCRYPTED_SIZE * 3 / 4;

static NONCE_COUNTER: std::sync::OnceLock<Option<[std::sync::atomic::AtomicU32; 3]>> =
    std::sync::OnceLock::new();

/// Session store encryption key.
#[derive(Clone)]
pub struct SessionStoreKey {
    // (AES-GCM-SIV key, key_id)
    keys: Vec<(aes_gcm_siv::Aes256GcmSiv, u8)>,
}

/// Error in key initialization
#[derive(Debug)]
pub enum KeyError {
    /// getrandom failed.
    GetRandomError,
    /// `secret` in `new()` or `add_key()` is shorter than 40 characters.
    SecretTooShort,
    /// `key_id` specified in `add_key()` is duplicated.
    DuplicatedKeyId,
}

/// Error in cookie encode
#[derive(Debug)]
pub enum EncodeError {
    /// Payload is larger than AES-GCM-SIV limit ( >=2^36 ), normally does not occur
    PayloadTooLarge,
    MessagePackEncodeError(rmp_serde::encode::Error),
}

/// Error in cookie decode
#[derive(Debug)]
pub enum DecodeError {
    /// Cookie value is too short for decryption
    CookieTooShort,
    /// No matching `key_id` in `SessionStoreKey`
    NoKey,
    Base64DecodeError(base64::DecodeError),
    DecryptionError(aes_gcm_siv::Error),
    MessagePackDecodeError(rmp_serde::decode::Error),
}

impl SessionStoreKey {
    /// New session store key.
    ///
    /// - `key_id` is for key rotation.  
    ///   if you don't mind key rotation, set `key_id`=0
    /// - `secret` should random generated string, at least 40 characters or more.
    pub fn new(key_id: u8, secret: &str) -> Result<Self, KeyError> {
        use std::sync::atomic::AtomicU32;

        let nonce = NONCE_COUNTER.get_or_init(|| {
            // Initial nonce from random.
            // Even we use SIV mode, we should avoid duplicated nonce.
            // For multi-instance servers,
            // sequential counter with random initial value
            // may be the best we can do in stateless.
            let r0 = AtomicU32::new(getrandom::u32().ok()?);
            let r1 = AtomicU32::new(getrandom::u32().ok()?);
            let r2 = AtomicU32::new(getrandom::u32().ok()?);
            Some([r0, r1, r2])
        });
        if nonce.is_none() {
            return Err(KeyError::GetRandomError);
        }

        if secret.len() < 40 {
            return Err(KeyError::SecretTooShort);
        }

        // Generate AES secret key from SHA256 hash
        let aes_key = Self::derive_key(secret)?;
        Ok(Self {
            keys: vec![(aes_key, key_id)],
        })
    }

    /// Add alternate decryption key for secret key rotation.
    ///
    /// - `key_id` must be unique.
    /// - `secret` should random generated string, at least 40 characters or more
    ///
    /// When performing key rotation, follow the steps below.
    ///
    /// First, deploy new secret as alternate key to all server instances.
    /// ```ignore
    /// let store_key = SessionStoreKey::new(0, old_secret)?.add_key(1, new_secret)?;
    /// ```
    ///
    /// Then, switch to new secret. Be sure to match (`key_id`, `secret`) pairs.
    /// ```ignore
    /// let store_key = SessionStoreKey::new(1, new_secret)?.add_key(0, old_secret)?;
    /// ```
    ///
    /// After all session Cookies expire, you can remove `old_secret`
    /// ```ignore
    /// let store_key = SessionStoreKey::new(1, new_secret)?;
    /// ```
    ///
    /// For convenience, you may use first char of secret as key_id as you like.
    /// ```ignore
    /// let store_key = SessionStoreKey::new(secret.as_bytes()[0], secret)?;
    /// ```
    pub fn add_key(self, key_id: u8, secret: &str) -> Result<Self, KeyError> {
        // check key_id uniqueness
        if self.decrypt_key_by_id(key_id).is_some() {
            return Err(KeyError::DuplicatedKeyId);
        }

        let mut updated_self = self;
        updated_self.keys.push((Self::derive_key(secret)?, key_id));
        Ok(updated_self)
    }

    /// Encrypt payload in Cookie
    ///
    /// ```ignore
    /// #[derive(serde::Serialize)]
    /// struct UserSession {
    ///     user_id: i32,
    ///     user_name: String,
    /// }
    /// let session = UserSession{
    ///     user_id: 1,
    ///     user_name: "Alice".to_string(),
    /// };
    /// let set_cookie = key.encrypt("__Host-session", &session, 0)?
    ///     .http_only(true)
    ///     .path("/")
    ///     .secure(true)
    ///     .same_site(cookie::SameSite::Lax)
    ///     .build();
    /// ```
    pub fn encrypt<'a, T>(
        &self,
        name: &'a str,
        payload: &T,
        payload_ver: u8,
    ) -> Result<cookie::CookieBuilder<'a>, EncodeError>
    where
        T: serde::Serialize,
    {
        use aes_gcm_siv::{AeadInPlace, Nonce};
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Generate nonce
        // message = [payload_ver || key_id || nonce || MessagePack(payload) || tag]
        let mut message = Vec::with_capacity(3000);
        message.push(payload_ver);
        message.push(self.encrypt_key_id());
        message.extend_from_slice(&self.nonce());
        let mut serializer = rmp_serde::Serializer::new(&mut message)
            // Serialize Vec<u8> as binary, not array of u8
            .with_bytes(rmp_serde::config::BytesMode::ForceAll)
            // Serialize struct key name for better compatibility
            .with_struct_map();
        payload
            .serialize(&mut serializer)
            .map_err(|e| EncodeError::MessagePackEncodeError(e))?;

        // Encryption
        let (header_nonce, msg_pack) = message.split_at_mut(PREFIX_SIZE + NONCE_SIZE);
        let tag = self
            .encrypt_key()
            .encrypt_in_place_detached(
                Nonce::from_slice(&header_nonce[PREFIX_SIZE..]),
                name.as_bytes(),
                msg_pack,
            )
            // Returns Err when message.len()>=2^36
            .map_err(|_| EncodeError::PayloadTooLarge)?;

        // Base64 URL encode [payload_ver || key_id || nonce || AES-GCM-SIV(message) || tag]
        message.extend_from_slice(tag.as_slice());
        let cookie_value = URL_SAFE_NO_PAD.encode(&message);

        let builder = cookie::Cookie::build((name, cookie_value))
            .http_only(true)
            .secure(true);

        Ok(builder)
    }

    /// Decrypt cookie
    ///
    /// ```ignore
    /// #[derive(serde::Deserialize)]
    /// struct UserSession {
    ///     user_id: i32,
    ///     user_name: String,
    /// }
    /// let session = key.decrypt::<UserSession>(&cookie, 0)?;
    /// ```
    pub fn decrypt<T>(&self, cookie: &cookie::Cookie) -> Result<T, DecodeError>
    where
        T: serde::de::DeserializeOwned,
    {
        use aes_gcm_siv::{AeadInPlace, Nonce, Tag};
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let (name, value) = cookie.name_value();
        if value.len() < MINIMUM_COOKIE_VALUE_SIZE {
            return Err(DecodeError::CookieTooShort);
        }
        // Decode base64
        let mut encrypted = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|e| DecodeError::Base64DecodeError(e))?;
        // Check key_id
        let key_id = encrypted[1];

        // Decrypt
        let (header_nonce, msg_pack) = encrypted.split_at_mut(PREFIX_SIZE + NONCE_SIZE);
        let (msg_pack, tag) = msg_pack.split_at_mut(msg_pack.len() - AUTH_TAG_SIZE);
        let key = self.decrypt_key_by_id(key_id).ok_or(DecodeError::NoKey)?;
        key.decrypt_in_place_detached(
            Nonce::from_slice(&header_nonce[PREFIX_SIZE..]),
            name.as_bytes(),
            msg_pack,
            Tag::from_slice(&tag),
        )
        .map_err(|e| DecodeError::DecryptionError(e))?;

        // Decode payload as MessagePack
        let payload = rmp_serde::from_slice::<T>(&msg_pack)
            .map_err(|e| DecodeError::MessagePackDecodeError(e))?;

        Ok(payload)
    }

    /// Payload version specified in encrypt()
    ///
    /// When you have the breaking change in payload type,
    /// check this payload_ver() and decode each types.
    ///
    /// ```ignore
    /// match payload_ver(&cookie) {
    ///     Some(0) => {
    ///         let payload = key.decyrpt::<PreviousPayloadType>(&cookie)?;
    ///         do_previous_work(&payload)
    ///     },
    ///     Some(1) => {
    ///         let payload = key.decyrpt::<NewPayloadType>(&cookie)?;
    ///         do_new_work(&payload)
    ///     },
    ///     _ => {
    ///         Err(BAD_REQUEST)?
    ///     },
    /// }
    /// ```
    pub fn payload_ver(cookie: &cookie::Cookie) -> Option<u8> {
        let value = cookie.value();

        if let Some(leading_4char) = value.get(0..4) {
            // Base64 decode
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            if let Ok(leading_3bytes) = URL_SAFE_NO_PAD.decode(leading_4char) {
                // First byte is the payload version
                Some(leading_3bytes[0])
            } else {
                // Invalid Base64 encoding
                None
            }
        } else {
            // Invalid - too short or non-ascii chars
            None
        }
    }

    /// Generate nonce (increment)
    fn nonce(&self) -> [u8; 12] {
        use std::sync::atomic::Ordering::Relaxed;
        use std::u32::MAX;

        // NONCE_COUNTER is initialized in Self::new(),
        // it safe to call unwrap() here.
        let nonce_counter = NONCE_COUNTER.get().unwrap().as_ref().unwrap();

        // 96bit increment
        let u0 = nonce_counter[0].fetch_add(1, Relaxed);
        let carry = if u0 == MAX { 1 } else { 0 };
        let u1 = nonce_counter[1].fetch_add(carry, Relaxed);
        let carry = if u1 == MAX { 1 } else { 0 };
        let u2 = nonce_counter[2].fetch_add(carry, Relaxed);

        // Serialize as 96bit little endian uint
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&u0.to_le_bytes());
        nonce[4..8].copy_from_slice(&u1.to_le_bytes());
        nonce[8..12].copy_from_slice(&u2.to_le_bytes());

        nonce
    }

    /// encrypt key_id
    fn encrypt_key_id(&self) -> u8 {
        self.keys[0].1
    }

    /// encrypt key
    fn encrypt_key<'a>(&'a self) -> &'a aes_gcm_siv::Aes256GcmSiv {
        &self.keys[0].0
    }

    /// decrypt key by key_id
    fn decrypt_key_by_id<'a>(&'a self, key_id: u8) -> Option<&'a aes_gcm_siv::Aes256GcmSiv> {
        let (key, _kid) = self.keys.iter().find(|(_key, kid)| *kid == key_id)?;
        Some(key)
    }

    /// derive key by hash function
    fn derive_key(secret: &str) -> Result<aes_gcm_siv::Aes256GcmSiv, KeyError> {
        use aes_gcm_siv::KeyInit;
        use sha2::Digest;

        // Check if secret has enough entropy
        if secret.len() < 40 {
            return Err(KeyError::SecretTooShort);
        }

        // Generate AES secret key from SHA256 hash
        let key = sha2::Sha256::digest(secret.as_bytes());
        // Aes256GcmSiv instance
        //   new_from_slice() always requires 32byte(256bit) slice, and SHA-256 generate 32byte, unwrap() is always safe.
        let aes_key = aes_gcm_siv::Aes256GcmSiv::new_from_slice(&key).unwrap();

        Ok(aes_key)
    }
}

impl From<getrandom::Error> for KeyError {
    fn from(_e: getrandom::Error) -> Self {
        KeyError::GetRandomError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    struct Session {
        user_id: i32,
        name: String,
    }

    #[test]
    fn key_generation() {
        // single key
        SessionStoreKey::new(0, "0123456789012345678901234567890123456789").unwrap();

        // additional key
        SessionStoreKey::new(0, "0123456789012345678901234567890123456789")
            .unwrap()
            .add_key(1, "1234567890123456789012345678901234567890")
            .unwrap();
    }

    #[test]
    fn too_short_secret() {
        // 39 char
        if let Err(KeyError::SecretTooShort) =
            SessionStoreKey::new(0, "012345678901234567890123456789012345678")
        {
            // ok
        } else {
            panic!("Result != SecretTooShort");
        }
    }

    #[test]
    fn duplicated_key_id() {
        // same key_id
        let duplicated = SessionStoreKey::new(1, "0123456789012345678901234567890123456789")
            .unwrap()
            .add_key(1, "1234567890123456789012345678901234567890");

        if let Err(KeyError::DuplicatedKeyId) = duplicated {
            // ok
        } else {
            panic!("Result != DuplicatedKeyId");
        }
    }

    #[test]
    fn encrypt_decrypt() {
        let alice = Session {
            user_id: 1,
            name: "Alice".to_string(),
        };

        // Encrypt
        let key = SessionStoreKey::new(0, "0123456789012345678901234567890123456789").unwrap();
        let cookie = key.encrypt("session", &alice, 5).unwrap().build();
        // check payload ver
        assert_eq!(SessionStoreKey::payload_ver(&cookie), Some(5));
        // Check decrypted session is same as plain
        let decrypted_session = key.decrypt::<Session>(&cookie).unwrap();
        assert_eq!(decrypted_session, alice);

        // Decrypt as alternate key
        let key = SessionStoreKey::new(1, "1234567890123456789012345678901234567890")
            .unwrap()
            .add_key(0, "0123456789012345678901234567890123456789")
            .unwrap();
        let alt_decrypted = key.decrypt::<Session>(&cookie).unwrap();
        assert_eq!(alt_decrypted, alice);
    }
}
