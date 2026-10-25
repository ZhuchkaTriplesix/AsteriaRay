pub const PPP_PROTO_LCP: u16 = 0xC021;
pub const PPP_PROTO_AUTH_CHAP: u16 = 0xC223;
pub const PPP_PROTO_IPCP: u16 = 0x8021;
pub const PPP_PROTO_IPV4: u16 = 0x0021;

pub const LCP_CODE_CONF_REQ: u8 = 1;
pub const LCP_CODE_CONF_ACK: u8 = 2;
pub const LCP_CODE_CONF_NAK: u8 = 3;
pub const LCP_CODE_CONF_REJ: u8 = 4;
pub const LCP_CODE_TERM_REQ: u8 = 5;
pub const LCP_CODE_TERM_ACK: u8 = 6;
pub const LCP_CODE_ECHO_REQ: u8 = 9;
pub const LCP_CODE_ECHO_REP: u8 = 10;

pub const LCP_OPT_MRU: u8 = 1;
pub const LCP_OPT_AUTH_PROTO: u8 = 3;
pub const LCP_OPT_MAGIC_NUM: u8 = 5;

#[derive(Debug, Clone)]
pub struct LcpPacket {
    pub code: u8,
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl LcpPacket {
    pub fn new(code: u8, identifier: u8, data: Vec<u8>) -> Self {
        Self {
            code,
            identifier,
            data,
        }
    }

    pub fn build_conf_req(identifier: u8, mru: u16, magic_number: u32) -> Self {
        let mut data = Vec::new();
        // MRU option: Type 1, Len 4, Val (u16)
        data.push(LCP_OPT_MRU);
        data.push(4);
        data.extend_from_slice(&mru.to_be_bytes());

        // Magic Number option: Type 5, Len 6, Val (u32)
        data.push(LCP_OPT_MAGIC_NUM);
        data.push(6);
        data.extend_from_slice(&magic_number.to_be_bytes());

        Self::new(LCP_CODE_CONF_REQ, identifier, data)
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
            return Err("LCP packet too short");
        }
        let code = buf[0];
        let identifier = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || len > buf.len() {
            return Err("Invalid LCP packet length");
        }
        let data = buf[4..len].to_vec();
        Ok(Self {
            code,
            identifier,
            data,
        })
    }
}
