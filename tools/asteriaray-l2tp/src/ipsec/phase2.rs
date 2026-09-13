use rand::{rngs::OsRng, RngCore};
use crate::crypto::kdf::{self, HashAlgorithm, Ikev1Keys};
use super::esp::{EspAuth, EspCipher, EspContext};
use super::isakmp::*;

pub struct QuickModeSession {
    pub message_id: u32,
    pub spi_in: u32,
    pub spi_out: u32,
    pub nonce_i_qm: Vec<u8>,
    pub nonce_r_qm: Vec<u8>,
    pub last_iv: Vec<u8>,
    pub cipher_key: Vec<u8>,
}

impl QuickModeSession {
    pub fn new(
        last_phase1_cbc: &[u8],
        cipher_key: Vec<u8>,
        hash_alg: HashAlgorithm,
    ) -> Self {
        let message_id = OsRng.next_u32();
        let last_iv = kdf::compute_phase2_iv(hash_alg, last_phase1_cbc, message_id);

        let mut spi_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut spi_bytes);
        let spi_in = u32::from_be_bytes(spi_bytes);

        let mut nonce_i_qm = vec![0u8; 16];
        OsRng.fill_bytes(&mut nonce_i_qm);

        Self {
            message_id,
            spi_in,
            spi_out: 0,
            nonce_i_qm,
            nonce_r_qm: Vec::new(),
            last_iv,
            cipher_key,
        }
    }

    /// Builds Quick Mode Message 1 (Initiator -> Responder: HASH(1) | SA | NONCE | IDi | IDr, encrypted)
    pub fn build_message_1(
        &mut self,
        keys: &Ikev1Keys,
        hash_alg: HashAlgorithm,
        cky_i: [u8; 8],
        cky_r: [u8; 8],
        nat_t: bool,
        local_ip: [u8; 4],
        peer_ip: [u8; 4],
    ) -> Result<Vec<u8>, &'static str> {
        let mut sa_body = Vec::new();
        // DOI: IPSEC (1)
        sa_body.extend_from_slice(&1u32.to_be_bytes());
        // Situation: Identity Only (1)
        sa_body.extend_from_slice(&1u32.to_be_bytes());

        // Proposal: Protocol ESP (3), SPI size 4, SPI=self.spi_in
        let mut prop = Vec::new();
        prop.push(1); // Proposal number
        prop.push(3); // Protocol ID: IPSEC_ESP
        prop.push(4); // SPI size
        prop.push(1); // 1 transform
        prop.extend_from_slice(&self.spi_in.to_be_bytes());

        // Transform 1: ESP_AES (12)
        let mut trans = Vec::new();
        trans.push(1);
        trans.push(12); // ESP_AES
        trans.extend_from_slice(&[0, 0]); // Reserved
        // Encapsulation Mode: UDP-Transport (4) if NAT-T, else Transport (1)
        let encap_mode: u8 = if nat_t { 4 } else { 1 };
        trans.extend_from_slice(&[0x80, 4, 0, encap_mode]);
        // Key length: 256 bits (Type 6, AF=1, Val=256)
        trans.extend_from_slice(&[0x80, 6, 1, 0]);
        // Auth algorithm: HMAC-SHA1 (Type 5, AF=1, Val=2)
        trans.extend_from_slice(&[0x80, 5, 0, 2]);
        // Life Type: Seconds (1)
        trans.extend_from_slice(&[0x80, 1, 0, 1]);
        // Life Duration: 28800s
        trans.extend_from_slice(&[0x00, 2, 0, 4, 0, 0, 0x70, 0x80]);

        let trans_len = (4 + trans.len()) as u16;
        prop.push(0); // Next payload
        prop.push(0); // Reserved
        prop.extend_from_slice(&trans_len.to_be_bytes());
        prop.extend_from_slice(&trans);

        let prop_len = (4 + prop.len()) as u16;
        sa_body.push(0); // Next payload
        sa_body.push(0); // Reserved
        sa_body.extend_from_slice(&prop_len.to_be_bytes());
        sa_body.extend_from_slice(&prop);

        // IDi & IDr: UDP Port 1701 (L2TP)
        let mut id_i = vec![1, 17, 0x06, 0xa5]; // IPv4 (1), Proto UDP (17), Port 1701 (0x06a5)
        id_i.extend_from_slice(&local_ip);
        let mut id_r = vec![1, 17, 0x06, 0xa5];
        id_r.extend_from_slice(&peer_ip);

        // Serialize remaining payloads (SA | NONCE | IDi | IDr)
        let mut rest_builder = PayloadBuilder::new();
        rest_builder.add(PAYLOAD_SA, sa_body);
        rest_builder.add(PAYLOAD_NONCE, self.nonce_i_qm.clone());
        rest_builder.add(PAYLOAD_ID, id_i);
        rest_builder.add(PAYLOAD_ID, id_r);
        let rest_bytes = rest_builder.build_payloads_bytes();

        // HASH(1) = prf(SKEYID_a, M-ID | [entire message that follows the hash including all payload headers])
        let mut hash_data = Vec::with_capacity(4 + rest_bytes.len());
        hash_data.extend_from_slice(&self.message_id.to_be_bytes());
        hash_data.extend_from_slice(&rest_bytes);
        let hash_1 = kdf::prf(hash_alg, &keys.skeyid_a, &hash_data);

        // Assemble unencrypted body: HASH payload followed by rest_bytes
        let mut unencrypted = Vec::with_capacity(4 + hash_1.len() + rest_bytes.len());
        unencrypted.push(PAYLOAD_SA); // Next payload after HASH
        unencrypted.push(0); // Reserved
        let hash_len = (4 + hash_1.len()) as u16;
        unencrypted.extend_from_slice(&hash_len.to_be_bytes());
        unencrypted.extend_from_slice(&hash_1);
        unencrypted.extend_from_slice(&rest_bytes);

        // Pad to AES block size (16 bytes)
        let pad_len = if unencrypted.len() % 16 != 0 {
            16 - (unencrypted.len() % 16)
        } else {
            0
        };
        unencrypted.resize(unencrypted.len() + pad_len, 0u8);

        use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let enc = Aes256CbcEnc::new_from_slices(&self.cipher_key, &self.last_iv)
            .map_err(|_| "Invalid key or IV for QM AES-CBC")?;
        let mut ciphertext = unencrypted.clone();
        enc.encrypt_padded_mut::<NoPadding>(&mut ciphertext, unencrypted.len())
            .map_err(|_| "QM Encryption failed")?;

        // Update last_iv to last block of QM Message 1 ciphertext
        self.last_iv = ciphertext[ciphertext.len() - 16..].to_vec();

        let mut header = IsakmpHeader::new(
            cky_i,
            cky_r,
            PAYLOAD_HASH,
            EXCH_QUICK_MODE,
            FLAG_ENCRYPTED,
            self.message_id,
        );
        header.length = (ISAKMP_HDR_LEN + ciphertext.len()) as u32;

        let mut out = Vec::with_capacity(header.length as usize);
        header.write_to(&mut out);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Handles Quick Mode Message 2 and produces the ESP Context
    pub fn handle_message_2(
        &mut self,
        buf: &[u8],
        keys: &Ikev1Keys,
        hash_alg: HashAlgorithm,
    ) -> Result<EspContext, &'static str> {
        let hdr = IsakmpHeader::parse(buf)?;
        if hdr.message_id != self.message_id {
            eprintln!("[L2TP] Expected QM Message ID 0x{:08x}, got 0x{:08x}", self.message_id, hdr.message_id);
            return Err("Mismatched Quick Mode Message ID");
        }

        if (hdr.flags & FLAG_ENCRYPTED) == 0 {
            return Err("QM Message 2 is not encrypted");
        }

        let encrypted_body = &buf[ISAKMP_HDR_LEN..];
        if encrypted_body.len() % 16 != 0 {
            return Err("QM Message 2 ciphertext length not multiple of 16");
        }

        use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let dec = Aes256CbcDec::new_from_slices(&self.cipher_key, &self.last_iv)
            .map_err(|_| "Invalid key or IV for QM AES-CBC")?;
        let mut decrypted = encrypted_body.to_vec();
        dec.decrypt_padded_mut::<NoPadding>(&mut decrypted)
            .map_err(|_| "QM Decryption failed")?;

        // Update last_iv to last block of QM Message 2 ciphertext
        self.last_iv = encrypted_body[encrypted_body.len() - 16..].to_vec();

        let payloads = parse_payloads(hdr.next_payload, &decrypted)?;
        eprintln!("[L2TP] QM Message 2 decrypted successfully ({} payloads)", payloads.len());

        for p in payloads {
            match p.payload_type {
                PAYLOAD_SA => {
                    // SA body: DOI (4) + Situation (4) + Proposal Payload (4 header + 4 fields + SPI)
                    eprintln!("[L2TP] QM SA body: {:02x?}", p.body);
                    if p.body.len() >= 20 {
                        let b = &p.body[8..]; // Proposal payload
                        if b.len() >= 12 {
                            let spi_size = b[6] as usize;
                            if spi_size == 4 && b.len() >= 12 {
                                self.spi_out = u32::from_be_bytes(b[8..12].try_into().unwrap());
                                eprintln!("[L2TP] Parsed responder SPI_out: 0x{:08x}", self.spi_out);
                            }
                        }
                    }
                }
                PAYLOAD_NONCE => {
                    self.nonce_r_qm = p.body;
                }
                _ => {}
            }
        }

        if self.spi_out == 0 {
            self.spi_out = 0x1000;
        }

        if self.nonce_r_qm.is_empty() {
            self.nonce_r_qm = vec![0u8; 16];
        }

        // Derive KEYMAT separately for outbound and inbound per RFC 2409 Section 5.5:
        // "A single SA negotiation results in two security associations-- one inbound and one outbound.
        // Different SPIs for each SA (one chosen by the initiator, the other by the responder) guarantee
        // a different key for each direction. The SPI chosen by the destination of the SA is used to derive KEYMAT for that SA."
        let keymat_out = Ikev1Keys::expand_keymat(
            hash_alg,
            &keys.skeyid_d,
            3, // ESP
            &self.spi_out.to_be_bytes(),
            &self.nonce_i_qm,
            &self.nonce_r_qm,
            52,
        );
        let enc_out = keymat_out[0..32].to_vec();
        let auth_out = keymat_out[32..52].to_vec();

        let keymat_in = Ikev1Keys::expand_keymat(
            hash_alg,
            &keys.skeyid_d,
            3, // ESP
            &self.spi_in.to_be_bytes(),
            &self.nonce_i_qm,
            &self.nonce_r_qm,
            52,
        );
        let enc_in = keymat_in[0..32].to_vec();
        let auth_in = keymat_in[32..52].to_vec();

        Ok(EspContext::new(
            self.spi_out,
            self.spi_in,
            EspCipher::Aes256Cbc,
            EspAuth::HmacSha1_96,
            enc_out,
            enc_in,
            auth_out,
            auth_in,
        ))
    }

    /// Builds Quick Mode Message 3 (Initiator -> Responder: HASH(3), encrypted)
    pub fn build_message_3(
        &mut self,
        keys: &Ikev1Keys,
        hash_alg: HashAlgorithm,
        cky_i: [u8; 8],
        cky_r: [u8; 8],
    ) -> Result<Vec<u8>, &'static str> {
        // HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_qm | Nr_qm)
        let mut hash_data = Vec::new();
        hash_data.push(0);
        hash_data.extend_from_slice(&self.message_id.to_be_bytes());
        hash_data.extend_from_slice(&self.nonce_i_qm);
        hash_data.extend_from_slice(&self.nonce_r_qm);
        let hash_3 = kdf::prf(hash_alg, &keys.skeyid_a, &hash_data);

        // HASH payload
        let mut unencrypted = Vec::new();
        unencrypted.push(PAYLOAD_NONE);
        unencrypted.push(0); // Reserved
        let hash_len = (4 + hash_3.len()) as u16;
        unencrypted.extend_from_slice(&hash_len.to_be_bytes());
        unencrypted.extend_from_slice(&hash_3);

        // Pad to 16 bytes
        let pad_len = if unencrypted.len() % 16 != 0 {
            16 - (unencrypted.len() % 16)
        } else {
            0
        };
        unencrypted.resize(unencrypted.len() + pad_len, 0u8);

        use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let enc = Aes256CbcEnc::new_from_slices(&self.cipher_key, &self.last_iv)
            .map_err(|_| "Invalid key or IV for QM3 AES-CBC")?;
        let mut ciphertext = unencrypted.clone();
        enc.encrypt_padded_mut::<NoPadding>(&mut ciphertext, unencrypted.len())
            .map_err(|_| "QM3 Encryption failed")?;

        self.last_iv = ciphertext[ciphertext.len() - 16..].to_vec();

        let mut header = IsakmpHeader::new(
            cky_i,
            cky_r,
            PAYLOAD_HASH,
            EXCH_QUICK_MODE,
            FLAG_ENCRYPTED,
            self.message_id,
        );
        header.length = (ISAKMP_HDR_LEN + ciphertext.len()) as u32;

        let mut out = Vec::with_capacity(header.length as usize);
        header.write_to(&mut out);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}
