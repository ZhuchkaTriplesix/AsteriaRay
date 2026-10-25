use rand::{rngs::OsRng, RngCore};
use crate::crypto::mschap::generate_mschapv2_response;

pub const PPP_PROTO_EAP: u16 = 0xC227;

pub const EAP_CODE_REQUEST: u8 = 1;
pub const EAP_CODE_RESPONSE: u8 = 2;
pub const EAP_CODE_SUCCESS: u8 = 3;
pub const EAP_CODE_FAILURE: u8 = 4;

pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_MD5_CHALLENGE: u8 = 4;
pub const EAP_TYPE_MSCHAPV2: u8 = 26; // 0x1A

pub const MSCHAPV2_OP_CHALLENGE: u8 = 1;
pub const MSCHAPV2_OP_RESPONSE: u8 = 2;
pub const MSCHAPV2_OP_SUCCESS: u8 = 3;
pub const MSCHAPV2_OP_FAILURE: u8 = 4;

#[derive(Debug, Clone)]
pub struct EapPacket {
    pub code: u8,
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl EapPacket {
    pub fn new(code: u8, identifier: u8, data: Vec<u8>) -> Self {
        Self {
            code,
            identifier,
            data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let len = (4 + self.data.len()) as u16;
        let mut buf = Vec::with_capacity(len as usize);
        buf.push(self.code);
        buf.push(self.identifier);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn parse(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 4 {
            return Err("EAP packet too short");
        }
        let code = buf[0];
        let identifier = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || len > buf.len() {
            return Err("Invalid EAP packet length");
        }
        let data = buf[4..len].to_vec();
        Ok(Self {
            code,
            identifier,
            data,
        })
    }

    pub fn build_identity_response(identifier: u8, username: &str) -> Self {
        let mut data = Vec::with_capacity(1 + username.len());
        data.push(EAP_TYPE_IDENTITY);
        data.extend_from_slice(username.as_bytes());
        Self::new(EAP_CODE_RESPONSE, identifier, data)
    }

    pub fn build_nak_response(identifier: u8, desired_type: u8) -> Self {
        Self::new(EAP_CODE_RESPONSE, identifier, vec![EAP_TYPE_NAK, desired_type])
    }

    pub fn build_mschapv2_response(
        identifier: u8,
        ms_chap_id: u8,
        username: &str,
        password: &str,
        auth_challenge: &[u8; 16],
    ) -> Self {
        let mut peer_challenge = [0u8; 16];
        OsRng.fill_bytes(&mut peer_challenge);

        let resp_49 = generate_mschapv2_response(username, password, auth_challenge, &peer_challenge);

        let ms_length = (1 + 1 + 2 + 1 + 49 + username.len()) as u16;
        let mut data = Vec::with_capacity(1 + ms_length as usize);
        data.push(EAP_TYPE_MSCHAPV2);
        data.push(MSCHAPV2_OP_RESPONSE);
        data.push(ms_chap_id);
        data.extend_from_slice(&ms_length.to_be_bytes());
        data.push(49); // Value-Size
        data.extend_from_slice(&resp_49);
        data.extend_from_slice(username.as_bytes());

        Self::new(EAP_CODE_RESPONSE, identifier, data)
    }

    pub fn build_mschapv2_success_ack(identifier: u8, ms_chap_id: u8) -> Self {
        let mut data = Vec::with_capacity(5);
        data.push(EAP_TYPE_MSCHAPV2);
        data.push(MSCHAPV2_OP_SUCCESS);
        data.push(ms_chap_id);
        data.extend_from_slice(&4u16.to_be_bytes()); // MS-Length = 4

        Self::new(EAP_CODE_RESPONSE, identifier, data)
    }
}
