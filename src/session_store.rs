//! Encrypted session store in Cookie
//!
//! This is very similar to [cookie::PrivateJar](https://docs.rs/cookie/latest/cookie/struct.PrivateJar.html),
//! except for the following points:
//!
//! - Supports encryption key rotation
//! - Uses AES-GCM-SIV mode to mitigate the risk of nonce collision
//! - Uses MessagePack for efficient binary encoding

/// Encrypt, message authentication key
pub struct SessionStoreKey {
    aes_gcm_siv: aes_gcm_siv::Aes256GcmSiv,
    nonce_counter: [std::sync::atomic::AtomicU32; 3],
    key_id: u8,
}

/// Error in cookie encode, decode
#[derive(Debug)]
pub enum Error {
    PayloadTooLarge,
    MessagePackEncodeError(rmp_serde::encode::Error),
}

impl SessionStoreKey {
    /// Encrypt payload in Cookie
    pub fn encrypt<'a, T>(
        &self,
        name: &'a str,
        payload: &T,
        payload_ver: u8,
    ) -> Result<cookie::CookieBuilder<'a>, Error>
    where
        T: serde::Serialize,
    {
        use aes_gcm_siv::{AeadInPlace, Nonce};
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Generate nonce
        // message = [payload_ver || key_id || nonce || MessagePack(payload) || tag]
        let mut message = Vec::with_capacity(3000);
        message.push(payload_ver);
        message.push(self.key_id);
        message.extend_from_slice(&self.nonce());
        let mut serializer = rmp_serde::Serializer::new(&mut message)
            // Serialize Vec<u8> as binary, not array of u8
            .with_bytes(rmp_serde::config::BytesMode::ForceAll)
            // Serialize struct key name for better compatibility
            .with_struct_map();
        payload
            .serialize(&mut serializer)
            .map_err(|e| Error::MessagePackEncodeError(e))?;

        // Encryption
        let (header_nonce, msg_pack) = message.split_at_mut(2 + 12);
        let tag = self
            .aes_gcm_siv
            .encrypt_in_place_detached(
                Nonce::from_slice(&header_nonce[2..]),
                name.as_bytes(),
                msg_pack,
            )
            // Returns Err when message.len()>=2^36
            .map_err(|_| Error::PayloadTooLarge)?;

        // Base64 URL encode [payload_ver || key_id || nonce || AES-GCM-SIV(message) || tag]
        message.extend_from_slice(tag.as_slice());
        let cookie_value = URL_SAFE_NO_PAD.encode(&message);

        let builder = cookie::Cookie::build((name, cookie_value))
            .http_only(true)
            .secure(true);

        Ok(builder)
    }

    pub fn decrypt<T>(&self, _cookie: &cookie::Cookie) -> Result<T, ()>
    where
        T: serde::de::DeserializeOwned,
    {
        todo!()
    }

    /// Generate nonce (increment)
    fn nonce(&self) -> [u8; 12] {
        use std::sync::atomic::Ordering::Relaxed;
        use std::u32::MAX;

        // 96bit increment
        let u0 = self.nonce_counter[0].fetch_add(1, Relaxed);
        let carry = if u0 == MAX { 1 } else { 0 };
        let u1 = self.nonce_counter[1].fetch_add(carry, Relaxed);
        let carry = if u1 == MAX { 1 } else { 0 };
        let u2 = self.nonce_counter[2].fetch_add(carry, Relaxed);

        // Serialize as 96bit little endian uint
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&u0.to_le_bytes());
        nonce[4..8].copy_from_slice(&u1.to_le_bytes());
        nonce[8..12].copy_from_slice(&u2.to_le_bytes());

        nonce
    }
}
