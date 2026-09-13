pub const MSG_SCCRQ: u16 = 1;
pub const MSG_SCCRP: u16 = 2;
pub const MSG_SCCCN: u16 = 3;
pub const MSG_STOPCCN: u16 = 4;
pub const MSG_HELLO: u16 = 6;
pub const MSG_ICRQ: u16 = 10;
pub const MSG_ICRP: u16 = 11;
pub const MSG_ICCN: u16 = 12;
pub const MSG_CDN: u16 = 14;

pub const AVP_MESSAGE_TYPE: u16 = 0;
pub const AVP_RESULT_CODE: u16 = 1;
pub const AVP_PROTOCOL_VERSION: u16 = 2;
pub const AVP_FRAMING_CAPABILITIES: u16 = 3;
pub const AVP_HOST_NAME: u16 = 7;
pub const AVP_ASSIGNED_TUNNEL_ID: u16 = 9;
pub const AVP_RECEIVE_WINDOW_SIZE: u16 = 10;
pub const AVP_ASSIGNED_SESSION_ID: u16 = 14;
pub const AVP_CALL_SERIAL_NUMBER: u16 = 15;
pub const AVP_FRAMING_TYPE: u16 = 19;
pub const AVP_TX_CONNECT_SPEED: u16 = 24;

#[derive(Debug, Clone)]
pub struct Avp {
    pub mandatory: bool,
    pub vendor_id: u16,
    pub attr_type: u16,
    pub value: Vec<u8>,
}

impl Avp {
    pub fn new(mandatory: bool, attr_type: u16, value: Vec<u8>) -> Self {
        Self {
            mandatory,
            vendor_id: 0,
            attr_type,
            value,
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        let len = (6 + self.value.len()) as u16;
        let mut flags_and_len = len & 0x03FF;
        if self.mandatory {
            flags_and_len |= 0x8000;
        }
        buf.extend_from_slice(&flags_and_len.to_be_bytes());
        buf.extend_from_slice(&self.vendor_id.to_be_bytes());
        buf.extend_from_slice(&self.attr_type.to_be_bytes());
        buf.extend_from_slice(&self.value);
    }
}

#[derive(Debug, Clone)]
pub struct L2tpPacket {
    pub is_control: bool,
    pub tunnel_id: u16,
    pub session_id: u16,
    pub ns: u16,
    pub nr: u16,
    pub avps: Vec<Avp>,
    pub payload: Vec<u8>,
}

impl L2tpPacket {
    pub fn new_control(tunnel_id: u16, session_id: u16, ns: u16, nr: u16) -> Self {
        Self {
            is_control: true,
            tunnel_id,
            session_id,
            ns,
            nr,
            avps: Vec::new(),
            payload: Vec::new(),
        }
    }

    pub fn new_zlb(tunnel_id: u16, session_id: u16, ns: u16, nr: u16) -> Self {
        Self::new_control(tunnel_id, session_id, ns, nr)
    }

    pub fn new_data(tunnel_id: u16, session_id: u16, payload: Vec<u8>) -> Self {
        Self {
            is_control: false,
            tunnel_id,
            session_id,
            ns: 0,
            nr: 0,
            avps: Vec::new(),
            payload,
        }
    }

    pub fn add_avp(&mut self, avp: Avp) -> &mut Self {
        self.avps.push(avp);
        self
    }

    pub fn message_type(&self) -> Option<u16> {
        for avp in &self.avps {
            if avp.attr_type == AVP_MESSAGE_TYPE && avp.value.len() >= 2 {
                return Some(u16::from_be_bytes([avp.value[0], avp.value[1]]));
            }
        }
        None
    }

    pub fn get_assigned_tunnel_id(&self) -> Option<u16> {
        for avp in &self.avps {
            if avp.attr_type == AVP_ASSIGNED_TUNNEL_ID && avp.value.len() >= 2 {
                return Some(u16::from_be_bytes([avp.value[0], avp.value[1]]));
            }
        }
        None
    }

    pub fn get_assigned_session_id(&self) -> Option<u16> {
        for avp in &self.avps {
            if avp.attr_type == AVP_ASSIGNED_SESSION_ID && avp.value.len() >= 2 {
                return Some(u16::from_be_bytes([avp.value[0], avp.value[1]]));
            }
        }
        None
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        if self.is_control {
            let mut avp_bytes = Vec::new();
            for avp in &self.avps {
                avp.write_to(&mut avp_bytes);
            }
            let total_len = (12 + avp_bytes.len()) as u16;
            // Flags: T=1 (0x80), L=1 (0x40), S=1 (0x08), Ver=2 (0x02) -> 0xC802
            buf.extend_from_slice(&0xC802u16.to_be_bytes());
            buf.extend_from_slice(&total_len.to_be_bytes());
            buf.extend_from_slice(&self.tunnel_id.to_be_bytes());
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.ns.to_be_bytes());
            buf.extend_from_slice(&self.nr.to_be_bytes());
            buf.extend_from_slice(&avp_bytes);
        } else {
            // Data packet: T=0, L=0, S=0, Ver=2 -> 0x0002
            buf.extend_from_slice(&0x0002u16.to_be_bytes());
            buf.extend_from_slice(&self.tunnel_id.to_be_bytes());
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.payload);
        }

        buf
    }

    pub fn parse(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 6 {
            return Err("L2TP packet too short");
        }

        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let is_control = (flags & 0x8000) != 0;
        let len_present = (flags & 0x4000) != 0;
        let seq_present = (flags & 0x0800) != 0;
        let offset_present = (flags & 0x0200) != 0;
        let version = (flags & 0x000F) as u8;

        if version != 2 {
            return Err("Unsupported L2TP version (expected v2)");
        }

        let mut pos = 2;
        let mut _total_len = 0;
        if len_present {
            if buf.len() < pos + 2 {
                return Err("Truncated L2TP length");
            }
            _total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
        }

        if buf.len() < pos + 4 {
            return Err("Truncated L2TP tunnel/session ID");
        }
        let tunnel_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let session_id = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        let mut ns = 0;
        let mut nr = 0;
        if seq_present {
            if buf.len() < pos + 4 {
                return Err("Truncated L2TP sequence numbers");
            }
            ns = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            nr = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            pos += 4;
        }

        if offset_present {
            if buf.len() < pos + 2 {
                return Err("Truncated L2TP offset");
            }
            let offset_size = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2 + offset_size;
        }

        let mut avps = Vec::new();
        let payload;

        if is_control {
            let mut rem = &buf[pos..];
            while rem.len() >= 6 {
                let avp_flags_len = u16::from_be_bytes([rem[0], rem[1]]);
                let mandatory = (avp_flags_len & 0x8000) != 0;
                let avp_len = (avp_flags_len & 0x03FF) as usize;

                if avp_len < 6 || avp_len > rem.len() {
                    break;
                }

                let vendor_id = u16::from_be_bytes([rem[2], rem[3]]);
                let attr_type = u16::from_be_bytes([rem[4], rem[5]]);
                let value = rem[6..avp_len].to_vec();

                avps.push(Avp {
                    mandatory,
                    vendor_id,
                    attr_type,
                    value,
                });

                rem = &rem[avp_len..];
            }
            payload = Vec::new();
        } else {
            payload = buf[pos..].to_vec();
        }

        Ok(Self {
            is_control,
            tunnel_id,
            session_id,
            ns,
            nr,
            avps,
            payload,
        })
    }
}
