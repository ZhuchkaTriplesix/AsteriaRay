use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha1::Sha1;
use sha2::Sha256;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspCipher {
    Aes128Cbc,
    Aes256Cbc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspAuth {
    HmacSha1_96,
    HmacSha256_128,
}

pub struct EspContext {
    pub spi_out: u32,
    pub spi_in: u32,
    pub seq_out: u32,
    pub cipher: EspCipher,
    pub auth: EspAuth,
    pub enc_key_out: Vec<u8>,
    pub enc_key_in: Vec<u8>,
    pub auth_key_out: Vec<u8>,
    pub auth_key_in: Vec<u8>,
}

impl EspContext {
    pub fn new(
        spi_out: u32,
        spi_in: u32,
        cipher: EspCipher,
        auth: EspAuth,
        enc_key_out: Vec<u8>,
        enc_key_in: Vec<u8>,
        auth_key_out: Vec<u8>,
        auth_key_in: Vec<u8>,
    ) -> Self {
        Self {
            spi_out,
            spi_in,
            seq_out: 1,
            cipher,
            auth,
            enc_key_out,
            enc_key_in,
            auth_key_out,
            auth_key_in,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], next_header: u8) -> Vec<u8> {
        let block_size = 16; // AES block size
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        // Padding: payload + pad + pad_len(1) + next_header(1) must be multiple of block_size
        let total_unpadded = plaintext.len() + 2;
        let pad_len = (block_size - (total_unpadded % block_size)) % block_size;

        let mut to_encrypt = Vec::with_capacity(plaintext.len() + pad_len + 2);
        to_encrypt.extend_from_slice(plaintext);
        for i in 1..=pad_len {
            to_encrypt.push(i as u8);
        }
        to_encrypt.push(pad_len as u8);
        to_encrypt.push(next_header);

        let mut ciphertext = to_encrypt.clone();
        match self.cipher {
            EspCipher::Aes128Cbc => {
                let enc = Aes128CbcEnc::new_from_slices(&self.enc_key_out, &iv)
                    .expect("valid key and iv");
                enc.encrypt_padded_mut::<NoPadding>(&mut ciphertext, to_encrypt.len())
                    .expect("correct block multiple");
            }
            EspCipher::Aes256Cbc => {
                let enc = Aes256CbcEnc::new_from_slices(&self.enc_key_out, &iv)
                    .expect("valid key and iv");
                enc.encrypt_padded_mut::<NoPadding>(&mut ciphertext, to_encrypt.len())
                    .expect("correct block multiple");
            }
        }

        let mut packet = Vec::with_capacity(8 + 16 + ciphertext.len() + 16);
        packet.extend_from_slice(&self.spi_out.to_be_bytes());
        packet.extend_from_slice(&self.seq_out.to_be_bytes());
        packet.extend_from_slice(&iv);
        packet.extend_from_slice(&ciphertext);

        self.seq_out = self.seq_out.wrapping_add(1);

        // Compute ICV over [SPI | Seq | IV | Ciphertext]
        let icv = self.compute_icv(&self.auth_key_out, &packet);
        packet.extend_from_slice(&icv);
        packet
    }

    pub fn decrypt(&self, packet: &[u8]) -> Result<(Vec<u8>, u8), &'static str> {
        if packet.len() < 8 + 16 + 2 {
            return Err("ESP packet too short");
        }
        let icv_len = match self.auth {
            EspAuth::HmacSha1_96 => 12,
            EspAuth::HmacSha256_128 => 16,
        };

        if packet.len() < 8 + 16 + icv_len + 16 {
            return Err("ESP packet shorter than header + ICV");
        }

        let signed_len = packet.len() - icv_len;
        let signed_data = &packet[..signed_len];
        let received_icv = &packet[signed_len..];

        let expected_icv = self.compute_icv(&self.auth_key_in, signed_data);
        if received_icv != expected_icv.as_slice() {
            return Err("ESP ICV authentication failed");
        }

        let spi = u32::from_be_bytes(packet[0..4].try_into().unwrap());
        if spi != self.spi_in {
            return Err("Unexpected incoming ESP SPI");
        }

        let iv = &packet[8..24];
        let ciphertext = &packet[24..signed_len];
        let mut decrypted = ciphertext.to_vec();

        match self.cipher {
            EspCipher::Aes128Cbc => {
                let dec = Aes128CbcDec::new_from_slices(&self.enc_key_in, iv)
                    .map_err(|_| "invalid key/iv")?;
                dec.decrypt_padded_mut::<NoPadding>(&mut decrypted)
                    .map_err(|_| "AES decryption failed")?;
            }
            EspCipher::Aes256Cbc => {
                let dec = Aes256CbcDec::new_from_slices(&self.enc_key_in, iv)
                    .map_err(|_| "invalid key/iv")?;
                dec.decrypt_padded_mut::<NoPadding>(&mut decrypted)
                    .map_err(|_| "AES decryption failed")?;
            }
        }

        if decrypted.len() < 2 {
            return Err("Decrypted ESP payload too short");
        }

        let next_header = decrypted[decrypted.len() - 1];
        let pad_len = decrypted[decrypted.len() - 2] as usize;

        if decrypted.len() < pad_len + 2 {
            return Err("Invalid ESP pad length");
        }

        let plaintext_len = decrypted.len() - pad_len - 2;
        let plaintext = decrypted[..plaintext_len].to_vec();

        Ok((plaintext, next_header))
    }

    fn compute_icv(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self.auth {
            EspAuth::HmacSha1_96 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("valid hmac key");
                mac.update(data);
                let full = mac.finalize().into_bytes();
                full[..12].to_vec()
            }
            EspAuth::HmacSha256_128 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("valid hmac key");
                mac.update(data);
                let full = mac.finalize().into_bytes();
                full[..16].to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 32];
        let auth_key = vec![0x24u8; 20];

        let mut sender = EspContext::new(
            0x1000,
            0x2000,
            EspCipher::Aes256Cbc,
            EspAuth::HmacSha1_96,
            key.clone(),
            key.clone(),
            auth_key.clone(),
            auth_key.clone(),
        );

        let receiver = EspContext::new(
            0x2000,
            0x1000,
            EspCipher::Aes256Cbc,
            EspAuth::HmacSha1_96,
            key.clone(),
            key.clone(),
            auth_key.clone(),
            auth_key.clone(),
        );

        let payload = b"Hello L2TP inside ESP!";
        let encrypted = sender.encrypt(payload, 17);

        let (decrypted, next_hdr) = receiver.decrypt(&encrypted).expect("decrypt failed");
        assert_eq!(decrypted, payload);
        assert_eq!(next_hdr, 17);
    }
}
