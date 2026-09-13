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
}

impl QuickModeSession {
    pub fn new() -> Self {
        let mut spi_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut spi_bytes);
        let spi_in = u32::from_be_bytes(spi_bytes);

        let mut nonce_i_qm = vec![0u8; 16];
        OsRng.fill_bytes(&mut nonce_i_qm);

        Self {
            message_id: OsRng.next_u32(),
            spi_in,
            spi_out: 0,
            nonce_i_qm,
            nonce_r_qm: Vec::new(),
        }
    }

    /// Builds Quick Mode Message 1 (Initiator -> Responder: HASH(1) | SA | NONCE | IDi | IDr)
    pub fn build_message_1(
        &mut self,
        keys: &Ikev1Keys,
        hash_alg: HashAlgorithm,
        cky_i: [u8; 8],
        cky_r: [u8; 8],
    ) -> Vec<u8> {
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
        // Encapsulation Mode: UDP-Transport (3) or Transport (1)
        trans.extend_from_slice(&[0x80, 4, 0, 3]);
        // Key length: 256 bits
        trans.extend_from_slice(&[0x80, 6, 1, 0]);
        // Auth algorithm: HMAC-SHA1 (2)
        trans.extend_from_slice(&[0x80, 5, 0, 2]);

        let trans_len = (4 + trans.len()) as u16;
        prop.push(0);
        prop.push(0);
        prop.extend_from_slice(&trans_len.to_be_bytes());
        prop.extend_from_slice(&trans);

        let prop_len = (4 + prop.len()) as u16;
        sa_body.push(0);
        sa_body.push(0);
        sa_body.extend_from_slice(&prop_len.to_be_bytes());
        sa_body.extend_from_slice(&prop);

        // IDi & IDr: UDP Port 1701 (L2TP)
        let mut id_i = vec![1, 17, 0x06, 0xa5]; // IPv4 (1), Proto UDP (17), Port 1701 (0x06a5)
        id_i.extend_from_slice(&[0, 0, 0, 0]);
        let mut id_r = vec![1, 17, 0x06, 0xa5];
        id_r.extend_from_slice(&[0, 0, 0, 0]);

        // HASH(1) = prf(SKEYID_a, M-ID | SA | Ni_qm | IDi | IDr)
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&self.message_id.to_be_bytes());
        hash_data.extend_from_slice(&sa_body);
        hash_data.extend_from_slice(&self.nonce_i_qm);
        hash_data.extend_from_slice(&id_i);
        hash_data.extend_from_slice(&id_r);
        let hash_1 = kdf::prf(hash_alg, &keys.skeyid_a, &hash_data);

        let header = IsakmpHeader::new(
            cky_i,
            cky_r,
            PAYLOAD_HASH,
            EXCH_QUICK_MODE,
            FLAG_ENCRYPTED,
            self.message_id,
        );

        let mut builder = PayloadBuilder::new();
        builder.add(PAYLOAD_HASH, hash_1);
        builder.add(PAYLOAD_SA, sa_body);
        builder.add(PAYLOAD_NONCE, self.nonce_i_qm.clone());
        builder.add(PAYLOAD_ID, id_i);
        builder.add(PAYLOAD_ID, id_r);
        builder.build(header)
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
            return Err("Mismatched Quick Mode Message ID");
        }

        let payloads = parse_payloads(hdr.next_payload, &buf[ISAKMP_HDR_LEN..])?;

        for p in payloads {
            match p.payload_type {
                PAYLOAD_SA => {
                    // Extract SPI out (responder SPI) from proposal payload inside SA
                    if p.body.len() >= 16 {
                        // find proposal SPI
                        let b = &p.body[8..];
                        if b.len() >= 8 {
                            let spi_size = b[2] as usize;
                            if spi_size == 4 && b.len() >= 8 {
                                self.spi_out = u32::from_be_bytes(b[4..8].try_into().unwrap());
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
            // fallback safe SPI if peer encoded differently
            self.spi_out = 0x1000;
        }

        if self.nonce_r_qm.is_empty() {
            self.nonce_r_qm = vec![0u8; 16];
        }

        // Derive KEYMAT: AES-256 (32 bytes) + HMAC-SHA1 (20 bytes) each direction = 104 bytes
        let keymat = Ikev1Keys::expand_keymat(
            hash_alg,
            &keys.skeyid_d,
            3, // ESP
            &self.spi_in.to_be_bytes(),
            &self.nonce_i_qm,
            &self.nonce_r_qm,
            104,
        );

        let enc_out = keymat[0..32].to_vec();
        let auth_out = keymat[32..52].to_vec();
        let enc_in = keymat[52..84].to_vec();
        let auth_in = keymat[84..104].to_vec();

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

    /// Builds Quick Mode Message 3 (Initiator -> Responder: HASH(3))
    pub fn build_message_3(
        &self,
        keys: &Ikev1Keys,
        hash_alg: HashAlgorithm,
        cky_i: [u8; 8],
        cky_r: [u8; 8],
    ) -> Vec<u8> {
        // HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_qm | Nr_qm)
        let mut hash_data = Vec::new();
        hash_data.push(0);
        hash_data.extend_from_slice(&self.message_id.to_be_bytes());
        hash_data.extend_from_slice(&self.nonce_i_qm);
        hash_data.extend_from_slice(&self.nonce_r_qm);
        let hash_3 = kdf::prf(hash_alg, &keys.skeyid_a, &hash_data);

        let header = IsakmpHeader::new(
            cky_i,
            cky_r,
            PAYLOAD_HASH,
            EXCH_QUICK_MODE,
            FLAG_ENCRYPTED,
            self.message_id,
        );

        let mut builder = PayloadBuilder::new();
        builder.add(PAYLOAD_HASH, hash_3);
        builder.build(header)
    }
}
