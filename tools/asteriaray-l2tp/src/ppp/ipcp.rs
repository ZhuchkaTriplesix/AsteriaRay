use std::net::Ipv4Addr;

pub const IPCP_CODE_CONF_REQ: u8 = 1;
pub const IPCP_CODE_CONF_ACK: u8 = 2;
pub const IPCP_CODE_CONF_NAK: u8 = 3;
pub const IPCP_CODE_CONF_REJ: u8 = 4;

pub const IPCP_OPT_IP_ADDR: u8 = 3;
pub const IPCP_OPT_PRIMARY_DNS: u8 = 129;
pub const IPCP_OPT_SECONDARY_DNS: u8 = 131;

#[derive(Debug, Clone)]
pub struct IpcpPacket {
    pub code: u8,
    pub identifier: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct IpcpConfig {
    pub client_ip: Option<Ipv4Addr>,
    pub primary_dns: Option<Ipv4Addr>,
    pub secondary_dns: Option<Ipv4Addr>,
}

impl IpcpPacket {
    pub fn new(code: u8, identifier: u8, data: Vec<u8>) -> Self {
        Self {
            code,
            identifier,
            data,
        }
    }

    pub fn build_conf_req(
        identifier: u8,
        ip: Ipv4Addr,
        dns1: Option<Ipv4Addr>,
        dns2: Option<Ipv4Addr>,
    ) -> Self {
        let mut data = Vec::new();

        // Option 3: IP Address (Type 3, Len 6, 4-byte IP)
        data.push(IPCP_OPT_IP_ADDR);
        data.push(6);
        data.extend_from_slice(&ip.octets());

        // Option 129: Primary DNS
        data.push(IPCP_OPT_PRIMARY_DNS);
        data.push(6);
        data.extend_from_slice(&dns1.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)).octets());

        // Option 131: Secondary DNS
        data.push(IPCP_OPT_SECONDARY_DNS);
        data.push(6);
        data.extend_from_slice(&dns2.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)).octets());

        Self::new(IPCP_CODE_CONF_REQ, identifier, data)
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
            return Err("IPCP packet too short");
        }
        let code = buf[0];
        let identifier = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || len > buf.len() {
            return Err("Invalid IPCP packet length");
        }
        let data = buf[4..len].to_vec();
        Ok(Self {
            code,
            identifier,
            data,
        })
    }

    pub fn parse_options(&self) -> IpcpConfig {
        let mut config = IpcpConfig::default();
        let mut rem = &self.data[..];

        while rem.len() >= 2 {
            let opt_type = rem[0];
            let opt_len = rem[1] as usize;
            if opt_len < 2 || opt_len > rem.len() {
                break;
            }

            let opt_val = &rem[2..opt_len];
            if opt_val.len() == 4 {
                let ip = Ipv4Addr::new(opt_val[0], opt_val[1], opt_val[2], opt_val[3]);
                match opt_type {
                    IPCP_OPT_IP_ADDR => config.client_ip = Some(ip),
                    IPCP_OPT_PRIMARY_DNS => config.primary_dns = Some(ip),
                    IPCP_OPT_SECONDARY_DNS => config.secondary_dns = Some(ip),
                    _ => {}
                }
            }

            rem = &rem[opt_len..];
        }

        config
    }
}
