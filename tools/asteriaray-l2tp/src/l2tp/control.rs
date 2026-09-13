use rand::{rngs::OsRng, RngCore};
use super::packet::*;

pub struct L2tpControlSession {
    pub local_tunnel_id: u16,
    pub remote_tunnel_id: u16,
    pub local_session_id: u16,
    pub remote_session_id: u16,
    pub ns: u16,
    pub nr: u16,
    pub hostname: String,
}

impl L2tpControlSession {
    pub fn new(hostname: String) -> Self {
        let local_tunnel_id = (OsRng.next_u32() % 60000 + 1) as u16;
        let local_session_id = (OsRng.next_u32() % 60000 + 1) as u16;

        Self {
            local_tunnel_id,
            remote_tunnel_id: 0,
            local_session_id,
            remote_session_id: 0,
            ns: 0,
            nr: 0,
            hostname,
        }
    }

    pub fn build_zlb(&self) -> L2tpPacket {
        L2tpPacket::new_zlb(self.remote_tunnel_id, 0, self.ns, self.nr)
    }

    pub fn build_sccrq(&mut self) -> L2tpPacket {
        let mut pkt = L2tpPacket::new_control(0, 0, self.ns, self.nr);

        // AVP 0: Message Type = SCCRQ (1)
        pkt.add_avp(Avp::new(true, AVP_MESSAGE_TYPE, MSG_SCCRQ.to_be_bytes().to_vec()));
        // AVP 2: Protocol Version = 1.0 (0x0100)
        pkt.add_avp(Avp::new(true, AVP_PROTOCOL_VERSION, vec![1, 0]));
        // AVP 3: Framing Capabilities = Sync (1) + Async (2) -> 3
        pkt.add_avp(Avp::new(true, AVP_FRAMING_CAPABILITIES, 3u32.to_be_bytes().to_vec()));
        // AVP 7: Host Name
        pkt.add_avp(Avp::new(true, AVP_HOST_NAME, self.hostname.as_bytes().to_vec()));
        // AVP 9: Assigned Tunnel ID
        pkt.add_avp(Avp::new(true, AVP_ASSIGNED_TUNNEL_ID, self.local_tunnel_id.to_be_bytes().to_vec()));
        // AVP 10: Receive Window Size (8)
        pkt.add_avp(Avp::new(true, AVP_RECEIVE_WINDOW_SIZE, 8u16.to_be_bytes().to_vec()));

        self.ns = self.ns.wrapping_add(1);
        pkt
    }

    pub fn handle_sccrp(&mut self, pkt: &L2tpPacket) -> Result<(), &'static str> {
        self.remote_tunnel_id = pkt
            .get_assigned_tunnel_id()
            .ok_or("Missing Assigned Tunnel ID in SCCRP")?;
        self.nr = pkt.ns.wrapping_add(1);
        Ok(())
    }

    pub fn build_scccn(&mut self) -> L2tpPacket {
        let mut pkt = L2tpPacket::new_control(self.remote_tunnel_id, 0, self.ns, self.nr);
        pkt.add_avp(Avp::new(true, AVP_MESSAGE_TYPE, MSG_SCCCN.to_be_bytes().to_vec()));
        self.ns = self.ns.wrapping_add(1);
        pkt
    }

    pub fn build_icrq(&mut self) -> L2tpPacket {
        let mut pkt = L2tpPacket::new_control(self.remote_tunnel_id, 0, self.ns, self.nr);

        pkt.add_avp(Avp::new(true, AVP_MESSAGE_TYPE, MSG_ICRQ.to_be_bytes().to_vec()));
        pkt.add_avp(Avp::new(true, AVP_ASSIGNED_SESSION_ID, self.local_session_id.to_be_bytes().to_vec()));
        pkt.add_avp(Avp::new(true, AVP_CALL_SERIAL_NUMBER, 1u32.to_be_bytes().to_vec()));

        self.ns = self.ns.wrapping_add(1);
        pkt
    }

    pub fn handle_icrp(&mut self, pkt: &L2tpPacket) -> Result<(), &'static str> {
        self.remote_session_id = pkt
            .get_assigned_session_id()
            .ok_or("Missing Assigned Session ID in ICRP")?;
        self.nr = pkt.ns.wrapping_add(1);
        Ok(())
    }

    pub fn build_iccn(&mut self) -> L2tpPacket {
        let mut pkt = L2tpPacket::new_control(
            self.remote_tunnel_id,
            self.remote_session_id,
            self.ns,
            self.nr,
        );

        pkt.add_avp(Avp::new(true, AVP_MESSAGE_TYPE, MSG_ICCN.to_be_bytes().to_vec()));
        // Tx Connect Speed: 100 Mbps (100000000 bps)
        pkt.add_avp(Avp::new(true, AVP_TX_CONNECT_SPEED, 100_000_000u32.to_be_bytes().to_vec()));
        // Framing Type: Sync (1)
        pkt.add_avp(Avp::new(true, AVP_FRAMING_TYPE, 1u32.to_be_bytes().to_vec()));

        self.ns = self.ns.wrapping_add(1);
        pkt
    }

    pub fn build_stopccn(&mut self) -> L2tpPacket {
        let mut pkt = L2tpPacket::new_control(self.remote_tunnel_id, 0, self.ns, self.nr);
        pkt.add_avp(Avp::new(true, AVP_MESSAGE_TYPE, MSG_STOPCCN.to_be_bytes().to_vec()));
        pkt.add_avp(Avp::new(true, AVP_ASSIGNED_TUNNEL_ID, self.local_tunnel_id.to_be_bytes().to_vec()));
        // Result code: 1 (General Stop), Error: 0
        pkt.add_avp(Avp::new(true, AVP_RESULT_CODE, vec![0, 1, 0, 0]));
        self.ns = self.ns.wrapping_add(1);
        pkt
    }
}
