use rand::{rngs::OsRng, RngCore};
use std::net::SocketAddr;

use crate::crypto::dh::{DhExchange, DhGroup};
use crate::crypto::kdf::{self, HashAlgorithm, Ikev1Keys};
use super::isakmp::*;

pub struct Phase1Session {
    pub cky_i: [u8; 8],
    pub cky_r: [u8; 8],
    pub dh: DhExchange,
    pub nonce_i: Vec<u8>,
    pub nonce_r: Vec<u8>,
    pub sa_bytes: Vec<u8>,
    pub keys: Option<Ikev1Keys>,
    pub nat_detected: bool,
    pub psk: Vec<u8>,
    pub hash_alg: HashAlgorithm,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

impl Phase1Session {
    pub fn new(
        psk: Vec<u8>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        group: DhGroup,
    ) -> Self {
        let mut cky_i = [0u8; 8];
        OsRng.fill_bytes(&mut cky_i);

        let dh = DhExchange::new(group);
        let mut nonce_i = vec![0u8; 16];
        OsRng.fill_bytes(&mut nonce_i);

        Self {
            cky_i,
            cky_r: [0u8; 8],
            dh,
            nonce_i,
            nonce_r: Vec::new(),
            sa_bytes: Vec::new(),
            keys: None,
            nat_detected: false,
            psk,
            hash_alg: HashAlgorithm::Sha1,
            local_addr,
            peer_addr,
        }
    }

    /// Builds Message 1 (Initiator -> Responder: SA Proposal + Vendor IDs)
    pub fn build_message_1(&mut self) -> Vec<u8> {
        let mut sa_body = Vec::new();
        // DOI: IPSEC (1)
        sa_body.extend_from_slice(&1u32.to_be_bytes());
        // Situation: Identity Only (1)
        sa_body.extend_from_slice(&1u32.to_be_bytes());

        // Proposal 1: Protocol ISAKMP (1), SPI size 0, 1 transform
        let mut prop = Vec::new();
        prop.push(1); // Proposal number
        prop.push(1); // Protocol ID (ISAKMP)
        prop.push(0); // SPI size
        prop.push(1); // Number of transforms

        // Transform 1: KEY_IKE (1)
        let mut trans = Vec::new();
        trans.push(1); // Transform number
        trans.push(1); // Transform ID (KEY_IKE)
        trans.extend_from_slice(&[0, 0]); // Reserved

        // Attributes (Type/Value):
        // 1. Encryption: AES-CBC (7) (AF=1, Type=1, Val=7) -> 0x80, 0x01, 0x00, 0x07
        trans.extend_from_slice(&[0x80, 1, 0, 7]);
        // 2. Key length: 256 bits (AF=1, Type=14, Val=256) -> 0x80, 14, 1, 0
        trans.extend_from_slice(&[0x80, 14, 1, 0]);
        // 3. Hash: SHA-1 (2) -> 0x80, 2, 0, 2
        trans.extend_from_slice(&[0x80, 2, 0, 2]);
        // 4. Auth Method: Pre-shared key (1) -> 0x80, 3, 0, 1
        trans.extend_from_slice(&[0x80, 3, 0, 1]);
        // 5. Group: DH Group (2) -> 0x80, 4, 0, self.dh.group as u8
        trans.extend_from_slice(&[0x80, 4, 0, self.dh.group as u8]);
        // 6. Life Type: Seconds (1) -> 0x80, 11, 0, 1
        trans.extend_from_slice(&[0x80, 11, 0, 1]);
        // 7. Life Duration: 28800s (Type=12, AF=0, Len=4)
        trans.extend_from_slice(&[0x00, 12, 0, 4, 0, 0, 0x70, 0x80]);

        // Wrap transform into proposal payload
        let trans_len = (4 + trans.len()) as u16;
        prop.push(0); // Next payload (none)
        prop.push(0); // Reserved
        prop.extend_from_slice(&trans_len.to_be_bytes());
        prop.extend_from_slice(&trans);

        // Wrap proposal into SA payload
        let prop_len = (4 + prop.len()) as u16;
        sa_body.push(0); // Next payload
        sa_body.push(0); // Reserved
        sa_body.extend_from_slice(&prop_len.to_be_bytes());
        sa_body.extend_from_slice(&prop);

        self.sa_bytes = sa_body.clone();

        let header = IsakmpHeader::new(
            self.cky_i,
            [0u8; 8],
            PAYLOAD_SA,
            EXCH_MAIN_MODE,
            0,
            0,
        );

        let mut builder = PayloadBuilder::new();
        builder.add(PAYLOAD_SA, sa_body);
        builder.add(PAYLOAD_VENDOR_ID, VID_RFC3947_NAT_T.to_vec());
        builder.add(PAYLOAD_VENDOR_ID, VID_DPD.to_vec());
        builder.build(header)
    }

    /// Processes Message 2 (Responder -> Initiator: Chosen SA + Vendor IDs)
    pub fn handle_message_2(&mut self, buf: &[u8]) -> Result<(), &'static str> {
        let hdr = IsakmpHeader::parse(buf)?;
        if hdr.cky_i != self.cky_i {
            return Err("Cookie mismatch in Message 2");
        }
        self.cky_r = hdr.cky_r;
        Ok(())
    }

    /// Builds Message 3 (Initiator -> Responder: KE + Nonce + NAT-D)
    pub fn build_message_3(&mut self) -> Vec<u8> {
        let header = IsakmpHeader::new(
            self.cky_i,
            self.cky_r,
            PAYLOAD_KE,
            EXCH_MAIN_MODE,
            0,
            0,
        );

        // Compute local and remote NAT-D hashes (provisional with PSK before keys derived)
        let local_ip_bytes = match self.local_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let peer_ip_bytes = match self.peer_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let nat_d_peer = kdf::Ikev1Keys::compute_nat_d(
            self.hash_alg,
            &self.psk,
            &self.cky_i,
            &self.cky_r,
            &peer_ip_bytes,
            self.peer_addr.port(),
        );
        let nat_d_local = kdf::Ikev1Keys::compute_nat_d(
            self.hash_alg,
            &self.psk,
            &self.cky_i,
            &self.cky_r,
            &local_ip_bytes,
            self.local_addr.port(),
        );

        let mut builder = PayloadBuilder::new();
        builder.add(PAYLOAD_KE, self.dh.public_bytes());
        builder.add(PAYLOAD_NONCE, self.nonce_i.clone());
        builder.add(PAYLOAD_NAT_D, nat_d_peer);
        builder.add(PAYLOAD_NAT_D, nat_d_local);
        builder.build(header)
    }

    /// Processes Message 4 (Responder -> Initiator: KE + Nonce + NAT-D)
    pub fn handle_message_4(&mut self, buf: &[u8]) -> Result<(), &'static str> {
        let hdr = IsakmpHeader::parse(buf)?;
        let payloads = parse_payloads(hdr.next_payload, &buf[ISAKMP_HDR_LEN..])?;

        let mut peer_pub_bytes = None;
        let mut peer_nonce = None;

        for p in payloads {
            match p.payload_type {
                PAYLOAD_KE => peer_pub_bytes = Some(p.body),
                PAYLOAD_NONCE => peer_nonce = Some(p.body),
                PAYLOAD_NAT_D => {
                    // If NAT-D returned, NAT detection is supported
                    self.nat_detected = true;
                }
                _ => {}
            }
        }

        let peer_pub = peer_pub_bytes.ok_or("Missing KE payload in Message 4")?;
        let nonce_r = peer_nonce.ok_or("Missing Nonce payload in Message 4")?;
        self.nonce_r = nonce_r;

        let shared_secret = self.dh.compute_shared_secret(&peer_pub)?;
        let keys = Ikev1Keys::derive(
            self.hash_alg,
            &self.psk,
            &self.nonce_i,
            &self.nonce_r,
            &shared_secret,
            &self.cky_i,
            &self.cky_r,
        );
        self.keys = Some(keys);

        Ok(())
    }

    /// Builds Message 5 (Initiator -> Responder: ID + HASH_I, encrypted)
    pub fn build_message_5(&self) -> Result<Vec<u8>, &'static str> {
        let keys = self.keys.as_ref().ok_or("Keys not derived")?;

        // ID payload: ID_IPV4_ADDR (1)
        let local_ip = match self.local_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => [0, 0, 0, 0],
        };
        let mut id_body = vec![1, 0, 0, 0]; // ID Type = 1 (IPv4), Proto = 0, Port = 0
        id_body.extend_from_slice(&local_ip);

        // HASH_I
        let hash_i = keys.compute_hash_i(
            self.hash_alg,
            &self.dh.public_bytes(),
            &vec![0u8; self.dh.byte_len], // approximate or cached peer pub
            &self.cky_i,
            &self.cky_r,
            &self.sa_bytes,
            &id_body,
        );

        let header = IsakmpHeader::new(
            self.cky_i,
            self.cky_r,
            PAYLOAD_ID,
            EXCH_MAIN_MODE,
            FLAG_ENCRYPTED,
            0,
        );

        let mut builder = PayloadBuilder::new();
        builder.add(PAYLOAD_ID, id_body);
        builder.add(PAYLOAD_HASH, hash_i);
        Ok(builder.build(header))
    }
}
