use crate::crypto::mschap::generate_mschapv2_response;

pub const CHAP_CODE_CHALLENGE: u8 = 1;
pub const CHAP_CODE_RESPONSE: u8 = 2;
pub const CHAP_CODE_SUCCESS: u8 = 3;
pub const CHAP_CODE_FAILURE: u8 = 4;

#[derive(Debug, Clone)]
pub struct ChapPacket {
    pub code: u8,
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl ChapPacket {
    pub fn parse(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 4 {
            return Err("CHAP packet too short");
        }
        let code = buf[0];
        let identifier = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || len > buf.len() {
            return Err("Invalid CHAP packet length");
        }
        let data = buf[4..len].to_vec();
        Ok(Self {
            code,
            identifier,
            data,
        })
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

    pub fn extract_challenge(&self) -> Result<[u8; 16], &'static str> {
        if self.data.is_empty() {
            return Err("Empty CHAP challenge payload");
        }
        let val_size = self.data[0] as usize;
        if val_size != 16 || self.data.len() < 1 + val_size {
            return Err("Invalid challenge value size (expected 16 bytes)");
        }
        let mut chal = [0u8; 16];
        chal.copy_from_slice(&self.data[1..17]);
        Ok(chal)
    }

    pub fn build_mschapv2_response(
        identifier: u8,
        username: &str,
        password: &str,
        auth_challenge: &[u8; 16],
        peer_challenge: &[u8; 16],
    ) -> Self {
        let resp_49 = generate_mschapv2_response(username, password, auth_challenge, peer_challenge);
        let mut data = Vec::with_capacity(1 + 49 + username.len());
        data.push(49); // Value-size
        data.extend_from_slice(&resp_49);
        data.extend_from_slice(username.as_bytes());

        Self {
            code: CHAP_CODE_RESPONSE,
            identifier,
            data,
        }
    }
}
