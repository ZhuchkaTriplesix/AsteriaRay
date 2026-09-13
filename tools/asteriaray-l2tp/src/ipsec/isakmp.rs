pub const ISAKMP_HDR_LEN: usize = 28;

pub const PAYLOAD_NONE: u8 = 0;
pub const PAYLOAD_SA: u8 = 1;
pub const PAYLOAD_PROPOSAL: u8 = 2;
pub const PAYLOAD_TRANSFORM: u8 = 3;
pub const PAYLOAD_KE: u8 = 4;
pub const PAYLOAD_ID: u8 = 5;
pub const PAYLOAD_HASH: u8 = 8;
pub const PAYLOAD_NONCE: u8 = 10;
pub const PAYLOAD_NOTIFICATION: u8 = 11;
pub const PAYLOAD_DELETE: u8 = 12;
pub const PAYLOAD_VENDOR_ID: u8 = 13;
pub const PAYLOAD_NAT_D: u8 = 130; // RFC 3947 NAT-D
pub const PAYLOAD_NAT_OA: u8 = 131;

pub const EXCH_MAIN_MODE: u8 = 2;
pub const EXCH_INFORMATIONAL: u8 = 5;
pub const EXCH_QUICK_MODE: u8 = 32;

pub const FLAG_ENCRYPTED: u8 = 0x01;

pub const VID_RFC3947_NAT_T: &[u8] = &[
    0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x0d, 0xa1,
    0xd6, 0x5a, 0x34, 0xac, 0x01, 0xb2, 0x2e, 0x3f,
];
pub const VID_DPD: &[u8] = &[
    0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9,
    0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00,
];

#[derive(Debug, Clone)]
pub struct IsakmpHeader {
    pub cky_i: [u8; 8],
    pub cky_r: [u8; 8],
    pub next_payload: u8,
    pub version: u8, // usually 0x10 (v1.0)
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl IsakmpHeader {
    pub fn new(
        cky_i: [u8; 8],
        cky_r: [u8; 8],
        next_payload: u8,
        exchange_type: u8,
        flags: u8,
        message_id: u32,
    ) -> Self {
        Self {
            cky_i,
            cky_r,
            next_payload,
            version: 0x10,
            exchange_type,
            flags,
            message_id,
            length: ISAKMP_HDR_LEN as u32,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < ISAKMP_HDR_LEN {
            return Err("ISAKMP header too short");
        }
        let mut cky_i = [0u8; 8];
        let mut cky_r = [0u8; 8];
        cky_i.copy_from_slice(&buf[0..8]);
        cky_r.copy_from_slice(&buf[8..16]);
        let next_payload = buf[16];
        let version = buf[17];
        let exchange_type = buf[18];
        let flags = buf[19];
        let message_id = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let length = u32::from_be_bytes(buf[24..28].try_into().unwrap());

        Ok(Self {
            cky_i,
            cky_r,
            next_payload,
            version,
            exchange_type,
            flags,
            message_id,
            length,
        })
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.cky_i);
        buf.extend_from_slice(&self.cky_r);
        buf.push(self.next_payload);
        buf.push(self.version);
        buf.push(self.exchange_type);
        buf.push(self.flags);
        buf.extend_from_slice(&self.message_id.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
    }
}

#[derive(Debug, Clone)]
pub struct GenericPayload {
    pub payload_type: u8,
    pub body: Vec<u8>,
}

pub struct PayloadBuilder {
    payloads: Vec<GenericPayload>,
}

impl PayloadBuilder {
    pub fn new() -> Self {
        Self { payloads: Vec::new() }
    }

    pub fn add(&mut self, payload_type: u8, body: Vec<u8>) -> &mut Self {
        self.payloads.push(GenericPayload { payload_type, body });
        self
    }

    pub fn build(self, mut header: IsakmpHeader) -> Vec<u8> {
        if self.payloads.is_empty() {
            header.next_payload = PAYLOAD_NONE;
            let mut out = Vec::with_capacity(ISAKMP_HDR_LEN);
            header.write_to(&mut out);
            return out;
        }

        header.next_payload = self.payloads[0].payload_type;
        let mut body_bytes = Vec::new();

        for (i, p) in self.payloads.iter().enumerate() {
            let next_type = if i + 1 < self.payloads.len() {
                self.payloads[i + 1].payload_type
            } else {
                PAYLOAD_NONE
            };
            let len = (4 + p.body.len()) as u16;
            body_bytes.push(next_type);
            body_bytes.push(0); // reserved
            body_bytes.extend_from_slice(&len.to_be_bytes());
            body_bytes.extend_from_slice(&p.body);
        }

        header.length = (ISAKMP_HDR_LEN + body_bytes.len()) as u32;
        let mut out = Vec::with_capacity(header.length as usize);
        header.write_to(&mut out);
        out.extend_from_slice(&body_bytes);
        out
    }

    pub fn build_payloads_bytes(&self) -> Vec<u8> {
        let mut body_bytes = Vec::new();
        for (i, p) in self.payloads.iter().enumerate() {
            let next_type = if i + 1 < self.payloads.len() {
                self.payloads[i + 1].payload_type
            } else {
                PAYLOAD_NONE
            };
            let len = (4 + p.body.len()) as u16;
            body_bytes.push(next_type);
            body_bytes.push(0); // reserved
            body_bytes.extend_from_slice(&len.to_be_bytes());
            body_bytes.extend_from_slice(&p.body);
        }
        body_bytes
    }
}

pub fn parse_payloads(first_type: u8, mut buf: &[u8]) -> Result<Vec<GenericPayload>, &'static str> {
    let mut current_type = first_type;
    let mut result = Vec::new();

    while current_type != PAYLOAD_NONE {
        if buf.len() < 4 {
            return Err("Truncated payload header");
        }
        let next_type = buf[0];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || len > buf.len() {
            return Err("Invalid payload length");
        }
        let body = buf[4..len].to_vec();
        result.push(GenericPayload {
            payload_type: current_type,
            body,
        });
        buf = &buf[len..];
        current_type = next_type;
    }

    Ok(result)
}
