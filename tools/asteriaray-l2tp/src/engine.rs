use rand::{rngs::OsRng, RngCore};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::interval;

use crate::config::AppConfig;
use crate::crypto::dh::DhGroup;
use crate::crypto::kdf::HashAlgorithm;
use crate::ipsec::esp::EspContext;
use crate::ipsec::phase1::Phase1Session;
use crate::ipsec::phase2::QuickModeSession;
use crate::l2tp::control::L2tpControlSession;
use crate::l2tp::packet::{L2tpPacket, MSG_CDN, MSG_ICRP, MSG_SCCRP};
use crate::ppp::auth::{ChapPacket, CHAP_CODE_CHALLENGE, CHAP_CODE_FAILURE, CHAP_CODE_SUCCESS};
use crate::ppp::eap::{
    EapPacket, PPP_PROTO_EAP, EAP_CODE_FAILURE, EAP_CODE_REQUEST, EAP_CODE_SUCCESS,
    EAP_TYPE_IDENTITY, EAP_TYPE_MSCHAPV2, MSCHAPV2_OP_CHALLENGE, MSCHAPV2_OP_FAILURE,
    MSCHAPV2_OP_SUCCESS,
};
use crate::ppp::ipcp::{IpcpConfig, IpcpPacket, IPCP_CODE_CONF_ACK, IPCP_CODE_CONF_NAK, IPCP_CODE_CONF_REJ, IPCP_CODE_CONF_REQ, IPCP_OPT_PRIMARY_DNS, IPCP_OPT_SECONDARY_DNS};
use crate::ppp::lcp::{LcpPacket, LCP_CODE_CONF_ACK, LCP_CODE_CONF_NAK, LCP_CODE_CONF_REJ, LCP_CODE_CONF_REQ, LCP_CODE_ECHO_REP, LCP_CODE_ECHO_REQ, PPP_PROTO_AUTH_CHAP, PPP_PROTO_IPCP, PPP_PROTO_IPV4, PPP_PROTO_LCP};
use crate::tun::TunDevice;

pub struct VpnEngine {
    config: AppConfig,
    shutdown: Arc<AtomicBool>,
}

impl VpnEngine {
    pub fn new(config: AppConfig, shutdown: Arc<AtomicBool>) -> Self {
        Self { config, shutdown }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let server_ip: Ipv4Addr = match self.config.server.parse() {
            Ok(ip) => ip,
            Err(_) => {
                let resolved = tokio::net::lookup_host(format!("{}:{}", self.config.server, self.config.port))
                    .await?
                    .next()
                    .ok_or("Failed to resolve server hostname")?;
                match resolved.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return Err("IPv6 server addresses not supported yet".into()),
                }
            }
        };

        let mut peer_addr = SocketAddr::new(std::net::IpAddr::V4(server_ip), self.config.port);
        let socket = match UdpSocket::bind("0.0.0.0:500").await {
            Ok(s) => {
                eprintln!("[L2TP] Bound to local port 500");
                s
            }
            Err(e) => {
                eprintln!("[L2TP] Could not bind port 500 ({}), using ephemeral port", e);
                UdpSocket::bind("0.0.0.0:0").await?
            }
        };
        let local_addr = socket.local_addr()?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            let mark: u32 = 0x22b8;
            unsafe {
                let res = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
                if res == 0 {
                    eprintln!("[L2TP] Set SO_MARK 0x{:x} on socket", mark);
                } else {
                    eprintln!("[L2TP] Warning: failed to set SO_MARK: {}", std::io::Error::last_os_error());
                }
            }
        }
        let real_local_ip = {
            let mut detected = None;
            #[cfg(target_os = "linux")]
            {
                if let Ok(out) = std::process::Command::new("ip")
                    .args(["route", "get", &server_ip.to_string(), "mark", "0x22b8"])
                    .output()
                {
                    let s = String::from_utf8_lossy(&out.stdout);
                    if let Some(src_idx) = s.find("src ") {
                        let rem = &s[src_idx + 4..];
                        let ip_str = rem.split_whitespace().next().unwrap_or("");
                        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                            detected = Some(ip);
                        }
                    }
                }
            }
            detected.unwrap_or_else(|| match local_addr.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => Ipv4Addr::new(0, 0, 0, 0),
            })
        };
        let local_addr = SocketAddr::new(std::net::IpAddr::V4(real_local_ip), local_addr.port());
        eprintln!("[L2TP] Local address for IKE: {}", local_addr);

        eprintln!("[L2TP] Initiating IKEv1 Phase 1 to {}", peer_addr);

        // --- IKEv1 Phase 1 (Main Mode) ---
        let mut p1 = Phase1Session::new(
            self.config.psk.as_bytes().to_vec(),
            local_addr,
            peer_addr,
            DhGroup::Group2,
        );

        // Message 1 ->
        let m1 = p1.build_message_1();
        eprintln!("[L2TP] Sending Message 1 ({} bytes): {:02x?}", m1.len(), &m1);
        socket.send_to(&m1, peer_addr).await?;

        // Helper to extract IPv4 packet from PPP/L2TP payload
        fn extract_ipv4_packet(payload: &[u8]) -> Option<&[u8]> {
            let mut data = payload;
            if data.len() >= 2 && data[0] == 0xff && data[1] == 0x03 {
                data = &data[2..];
            }
            if data.len() >= 2 && data[0] == 0x00 && data[1] == 0x21 {
                return Some(&data[2..]);
            }
            if !data.is_empty() && data[0] == 0x21 {
                return Some(&data[1..]);
            }
            if !data.is_empty() && (data[0] >> 4) == 4 {
                return Some(data);
            }
            None
        }

        async fn recv_phase1_msg(
            socket: &UdpSocket,
            buf: &mut [u8],
            peer_ip: std::net::IpAddr,
            expected_cky_i: &[u8; 8],
            timeout_dur: Duration,
        ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
            let start = tokio::time::Instant::now();
            while start.elapsed() < timeout_dur {
                let time_left = timeout_dur - start.elapsed();
                let (len, from) = match tokio::time::timeout(time_left, socket.recv_from(buf)).await {
                    Ok(Ok(res)) => res,
                    _ => return Err("Timeout waiting for Phase 1 message".into()),
                };
                if from.ip() != peer_ip {
                    continue;
                }
                if len < 28 {
                    continue;
                }
                if &buf[0..8] != expected_cky_i {
                    continue;
                }
                return Ok(len);
            }
            Err("Timeout waiting for Phase 1 message".into())
        }

        async fn recv_qm_msg2(
            socket: &UdpSocket,
            buf: &mut [u8],
            peer_ip: std::net::IpAddr,
            expected_msg_id: u32,
            timeout_dur: Duration,
        ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
            let start = tokio::time::Instant::now();
            while start.elapsed() < timeout_dur {
                let time_left = timeout_dur - start.elapsed();
                let (len, from) = match tokio::time::timeout(time_left, socket.recv_from(buf)).await {
                    Ok(Ok(res)) => res,
                    _ => return Err("Timeout waiting for QM response".into()),
                };
                if from.ip() != peer_ip {
                    continue;
                }
                let isakmp_slice = if len > 4 && &buf[..4] == &[0, 0, 0, 0] {
                    &buf[4..len]
                } else {
                    &buf[..len]
                };
                if isakmp_slice.len() < 28 {
                    continue;
                }
                let msg_id = u32::from_be_bytes([isakmp_slice[20], isakmp_slice[21], isakmp_slice[22], isakmp_slice[23]]);
                if msg_id != expected_msg_id {
                    continue;
                }
                return Ok(len);
            }
            Err("Timeout waiting for QM response".into())
        }

        async fn recv_esp(
            socket: &UdpSocket,
            buf: &mut [u8],
            esp_ctx: &EspContext,
            timeout_dur: Duration,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let start = tokio::time::Instant::now();
            while start.elapsed() < timeout_dur {
                let time_left = timeout_dur - start.elapsed();
                let (len, from) = match tokio::time::timeout(time_left, socket.recv_from(buf)).await {
                    Ok(Ok(res)) => res,
                    _ => return Err("Timeout waiting for ESP packet".into()),
                };
                if len <= 4 || &buf[..4] == &[0, 0, 0, 0] {
                    continue;
                }
                let spi = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                if spi != esp_ctx.spi_in {
                    eprintln!("[L2TP] recv_esp from {}: unexpected SPI 0x{:08x}, expected 0x{:08x}", from, spi, esp_ctx.spi_in);
                    continue;
                }
                match esp_ctx.decrypt(&buf[..len]) {
                    Ok((plaintext, _)) => return Ok(plaintext),
                    Err(e) => {
                        eprintln!("[L2TP] recv_esp from {}: decrypt failed: {}", from, e);
                        continue;
                    }
                }
            }
            Err("Timeout waiting for valid ESP packet".into())
        }

        // <- Message 2
        let mut buf = vec![0u8; 4096];
        let len = recv_phase1_msg(&socket, &mut buf, peer_addr.ip(), &p1.cky_i, Duration::from_secs(5)).await?;
        eprintln!("[L2TP] Received Message 2 ({} bytes)", len);
        p1.handle_message_2(&buf[..len])?;

        // Message 3 ->
        let m3 = p1.build_message_3();
        eprintln!("[L2TP] Sending Message 3 ({} bytes): {:02x?}", m3.len(), &m3);
        socket.send_to(&m3, peer_addr).await?;

        // <- Message 4
        let len = recv_phase1_msg(&socket, &mut buf, peer_addr.ip(), &p1.cky_i, Duration::from_secs(5)).await?;
        eprintln!("[L2TP] Received Message 4 ({} bytes)", len);
        p1.handle_message_4(&buf[..len])?;

        // Message 5 ->
        let m5 = p1.build_message_5()?;
        eprintln!("[L2TP] Sending Message 5 ({} bytes)", m5.len());
        socket.send_to(&m5, peer_addr).await?;

        // <- Message 6
        let len = recv_phase1_msg(&socket, &mut buf, peer_addr.ip(), &p1.cky_i, Duration::from_secs(5)).await?;
        p1.handle_message_6(&buf[..len])?;

        eprintln!("[L2TP] IKEv1 Phase 1 established! NAT-T: {}", p1.nat_detected);

        // If NAT detected, migrate peer_addr port to 4500
        if p1.nat_detected {
            peer_addr.set_port(4500);
        }

        // --- IKEv1 Phase 2 (Quick Mode) ---
        let p1_keys = p1.keys.as_ref().ok_or("Missing Phase 1 keys")?;
        let local_ip_bytes = match local_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => [0, 0, 0, 0],
        };
        let peer_ip_bytes = match peer_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => [0, 0, 0, 0],
        };

        let mut qm = QuickModeSession::new(&p1.last_iv, p1.cipher_key.clone(), HashAlgorithm::Sha1);
        let qm_m1 = qm.build_message_1(
            p1_keys,
            HashAlgorithm::Sha1,
            p1.cky_i,
            p1.cky_r,
            p1.nat_detected,
            local_ip_bytes,
            peer_ip_bytes,
        )?;

        let qm_m1_send = if p1.nat_detected {
            let mut prepended = vec![0u8; 4]; // Non-ESP marker
            prepended.extend_from_slice(&qm_m1);
            prepended
        } else {
            qm_m1
        };
        eprintln!("[L2TP] Sending QM Message 1 ({} bytes, NAT-T: {})", qm_m1_send.len(), p1.nat_detected);
        socket.send_to(&qm_m1_send, peer_addr).await?;

        // <- Quick Mode Message 2
        let len = recv_qm_msg2(&socket, &mut buf, peer_addr.ip(), qm.message_id, Duration::from_secs(5)).await?;
        eprintln!("[L2TP] Received QM response ({} bytes)", len);
        let qm_resp_buf = if p1.nat_detected && len > 4 && &buf[..4] == &[0, 0, 0, 0] {
            &buf[4..len]
        } else {
            &buf[..len]
        };

        let mut esp_ctx = qm.handle_message_2(qm_resp_buf, p1_keys, HashAlgorithm::Sha1)?;

        // Quick Mode Message 3 ->
        let qm_m3 = qm.build_message_3(p1_keys, HashAlgorithm::Sha1, p1.cky_i, p1.cky_r)?;
        let qm_m3_send = if p1.nat_detected {
            let mut prepended = vec![0u8; 4];
            prepended.extend_from_slice(&qm_m3);
            prepended
        } else {
            qm_m3
        };
        eprintln!("[L2TP] Sending QM Message 3 ({} bytes)", qm_m3_send.len());
        socket.send_to(&qm_m3_send, peer_addr).await?;

        eprintln!("[L2TP] IKEv1 Phase 2 Quick Mode established! SPI_in={:#x}, SPI_out={:#x}", esp_ctx.spi_in, esp_ctx.spi_out);

        // Helper to send encrypted L2TP packet inside ESP over UDP
        async fn send_l2tp(
            socket: &UdpSocket,
            peer_addr: SocketAddr,
            esp_ctx: &mut EspContext,
            l2tp_pkt: &L2tpPacket,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let l2tp_bytes = l2tp_pkt.to_bytes();
            // Wrap in UDP 1701 header: [src_port(2), dst_port(2), length(2), checksum(2)]
            let udp_len = (8 + l2tp_bytes.len()) as u16;
            let mut udp_packet = Vec::with_capacity(udp_len as usize);
            udp_packet.extend_from_slice(&1701u16.to_be_bytes());
            udp_packet.extend_from_slice(&1701u16.to_be_bytes());
            udp_packet.extend_from_slice(&udp_len.to_be_bytes());
            udp_packet.extend_from_slice(&[0, 0]); // Checksum optional in IPv4 UDP
            udp_packet.extend_from_slice(&l2tp_bytes);

            let esp_packet = esp_ctx.encrypt(&udp_packet, 17); // Next Header = UDP (17)
            socket.send_to(&esp_packet, peer_addr).await?;
            Ok(())
        }

        // --- L2TPv2 Handshake ---
        let mut l2tp = L2tpControlSession::new("AsteriaRay".to_string());

        // 1. SCCRQ ->
        let sccrq = l2tp.build_sccrq();
        send_l2tp(&socket, peer_addr, &mut esp_ctx, &sccrq).await?;

        // 2. <- SCCRP
        let mut sccrp_pkt = None;
        for _ in 0..5 {
            let plaintext = recv_esp(&socket, &mut buf, &esp_ctx, Duration::from_secs(5)).await?;
            if plaintext.len() < 8 {
                continue;
            }
            let pkt = L2tpPacket::parse(&plaintext[8..])?;
            if pkt.message_type() == Some(MSG_SCCRP) {
                sccrp_pkt = Some(pkt);
                break;
            }
        }
        let sccrp = sccrp_pkt.ok_or("Did not receive SCCRP from server")?;
        l2tp.handle_sccrp(&sccrp)?;

        // 3. SCCCN ->
        let scccn = l2tp.build_scccn();
        send_l2tp(&socket, peer_addr, &mut esp_ctx, &scccn).await?;

        // 4. ICRQ ->
        let icrq = l2tp.build_icrq();
        send_l2tp(&socket, peer_addr, &mut esp_ctx, &icrq).await?;

        // 5. <- ICRP
        let mut icrp_pkt = None;
        for _ in 0..5 {
            let plaintext = recv_esp(&socket, &mut buf, &esp_ctx, Duration::from_secs(5)).await?;
            if plaintext.len() < 8 {
                continue;
            }
            let pkt = L2tpPacket::parse(&plaintext[8..])?;
            if pkt.message_type() == Some(MSG_ICRP) {
                icrp_pkt = Some(pkt);
                break;
            } else if pkt.is_control && pkt.avps.is_empty() {
                // Server ZLB ACK for SCCCN, continue waiting for ICRP
                continue;
            }
        }
        let icrp = icrp_pkt.ok_or("Did not receive ICRP from server")?;
        l2tp.handle_icrp(&icrp)?;

        // 6. ICCN ->
        let iccn = l2tp.build_iccn();
        send_l2tp(&socket, peer_addr, &mut esp_ctx, &iccn).await?;

        eprintln!("[L2TP] L2TP tunnel and session established! TunnelID={}, SessionID={}", l2tp.remote_tunnel_id, l2tp.remote_session_id);

        // Helper to send PPP frame inside L2TP Data
        async fn send_ppp(
            socket: &UdpSocket,
            peer_addr: SocketAddr,
            esp_ctx: &mut EspContext,
            l2tp: &L2tpControlSession,
            proto: u16,
            body: &[u8],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut ppp_frame = Vec::with_capacity(4 + body.len());
            ppp_frame.push(0xff);
            ppp_frame.push(0x03);
            ppp_frame.extend_from_slice(&proto.to_be_bytes());
            ppp_frame.extend_from_slice(body);

            let data_pkt = L2tpPacket::new_data(l2tp.remote_tunnel_id, l2tp.remote_session_id, ppp_frame);
            send_l2tp(socket, peer_addr, esp_ctx, &data_pkt).await?;
            Ok(())
        }

        // --- PPP Negotiation (LCP -> Auth (MS-CHAPv2 or EAP-MSCHAPv2) -> IPCP) ---
        // 1. LCP Conf-Req ->
        let client_magic = OsRng.next_u32();
        let mut lcp_req = LcpPacket::build_conf_req(1, self.config.mtu, client_magic);
        eprintln!("[L2TP] Sending initial LCP Conf-Req...");
        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &lcp_req.to_bytes()).await?;

        let mut client_lcp_acked = false;
        let mut _server_lcp_acked = false;
        let mut ipcp_config = IpcpConfig::default();
        let mut client_ipcp_acked = false;
        // DNS options are dropped from our Conf-Req if the server Conf-Rejects them
        let mut req_dns1 = true;
        let mut req_dns2 = true;
        let mut server_ipcp_acked = false;
        let mut server_gateway_ip: Option<Ipv4Addr> = None;
        let mut nak_count: u32 = 0;

        // Read PPP frames until bidirectional IPCP is complete
        for iter in 0..45 {
            let plaintext = match recv_esp(&socket, &mut buf, &esp_ctx, Duration::from_secs(4)).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[L2TP] PPP iter {}: recv_esp error: {}", iter, e);
                    if client_ipcp_acked && server_ipcp_acked {
                        break;
                    }
                    continue;
                }
            };
            if plaintext.len() < 8 {
                continue;
            }
            let raw_l2tp = &plaintext[8..];
            eprintln!("[L2TP RAW RX] len={}, bytes={:02x?}", raw_l2tp.len(), &raw_l2tp[..std::cmp::min(raw_l2tp.len(), 16)]);
            let l2tp_pkt = match L2tpPacket::parse(&plaintext[8..]) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[L2TP] L2TP packet parse error: {}", e);
                    continue;
                }
            };

            // Discard packets belonging to previous or different tunnels
            if l2tp_pkt.tunnel_id != l2tp.local_tunnel_id {
                eprintln!("[L2TP] Ignoring stale packet for old tunnel: got {}, expected {}", l2tp_pkt.tunnel_id, l2tp.local_tunnel_id);
                continue;
            }

            if l2tp_pkt.is_control {
                if l2tp_pkt.message_type() == Some(MSG_CDN) {
                    let mut msg = String::from("L2TP Call Disconnected by server (CDN)");
                    for avp in &l2tp_pkt.avps {
                        if avp.attr_type == 1 {
                            let res_code = if avp.value.len() >= 2 { u16::from_be_bytes([avp.value[0], avp.value[1]]) } else { 0 };
                            let err_code = if avp.value.len() >= 4 { u16::from_be_bytes([avp.value[2], avp.value[3]]) } else { 0 };
                            let desc = if avp.value.len() > 4 { String::from_utf8_lossy(&avp.value[4..]).to_string() } else { String::new() };
                            msg = format!("L2TP Call Disconnected (CDN): res={}, err={}, desc='{}'", res_code, err_code, desc);
                        }
                    }
                    return Err(msg.into());
                }
                if l2tp_pkt.avps.is_empty() {
                    // It is a ZLB ACK - per RFC 2661, never acknowledge a ZLB!
                    continue;
                }
                eprintln!("[L2TP] Received L2TP control message: type={:?}", l2tp_pkt.message_type());
                l2tp.nr = l2tp_pkt.ns.wrapping_add(1);
                let zlb = l2tp.build_zlb();
                let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &zlb).await;
                continue;
            }

            // Extract PPP payload, stripping HDLC framing (0xFF 0x03) if present
            let mut ppp_payload = &l2tp_pkt.payload[..];
            if ppp_payload.len() >= 2 && ppp_payload[0] == 0xff && ppp_payload[1] == 0x03 {
                ppp_payload = &ppp_payload[2..];
            }
            if ppp_payload.len() < 2 {
                continue;
            }
            let proto = u16::from_be_bytes([ppp_payload[0], ppp_payload[1]]);
            let ppp_body = &ppp_payload[2..];
            eprintln!("[L2TP] Received PPP packet: proto=0x{:04x}, len={}", proto, ppp_body.len());

            match proto {
                PPP_PROTO_LCP => {
                    let lcp = match LcpPacket::parse(ppp_body) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    eprintln!("[L2TP] LCP packet: code={}, id={}, data={:02x?}", lcp.code, lcp.identifier, &lcp.data);
                    if lcp.code == LCP_CODE_CONF_REQ {
                        // Check if server proposed an auth protocol
                        let mut needs_nak_mschap = false;
                        let mut nak_options = Vec::new();
                        let mut rem = &lcp.data[..];
                        while rem.len() >= 2 {
                            let opt_type = rem[0];
                            let opt_len = rem[1] as usize;
                            if opt_len < 2 || opt_len > rem.len() {
                                break;
                            }
                            if opt_type == 3 { // Authentication Protocol
                                let auth_proto = if opt_len >= 4 { u16::from_be_bytes([rem[2], rem[3]]) } else { 0 };
                                let auth_alg = if opt_len >= 5 { rem[4] } else { 0 };
                                if auth_proto == 0xc223 && auth_alg == 0x81 {
                                    // MS-CHAPv2 (0xC223/0x81) — accept directly
                                    eprintln!("[L2TP] Server requested MS-CHAPv2 (0xc223), accepting!");
                                } else if auth_proto == 0xc227 {
                                    // EAP (0xC227): Microsoft NPS does NOT support naked EAP-MSCHAPv2
                                    // (it requires PEAP wrapper). NAK and propose MS-CHAPv2 to force
                                    // SoftEther into "Double CHAP" mode (same path as pppd/network-manager-l2tp).
                                    eprintln!("[L2TP] Server requested EAP (0xc227), NAKing → proposing MS-CHAPv2 (0xc223)");
                                    needs_nak_mschap = true;
                                    nak_options.extend_from_slice(&[3, 5, 0xc2, 0x23, 0x81]);
                                } else {
                                    needs_nak_mschap = true;
                                    nak_options.extend_from_slice(&[3, 5, 0xc2, 0x23, 0x81]);
                                }
                            }
                            rem = &rem[opt_len..];
                        }

                        if needs_nak_mschap {
                            nak_count += 1;
                            eprintln!("[L2TP] Server requested unsupported auth. Sending Conf-Nak requesting MS-CHAPv2 (attempt {})...", nak_count);
                            let nak = LcpPacket::new(LCP_CODE_CONF_NAK, lcp.identifier, nak_options);
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &nak.to_bytes()).await?;
                        } else {
                            eprintln!("[L2TP] Acking server LCP Conf-Req (id={})", lcp.identifier);
                            let ack = LcpPacket::new(LCP_CODE_CONF_ACK, lcp.identifier, lcp.data);
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &ack.to_bytes()).await?;
                            _server_lcp_acked = true;
                        }

                        if !client_lcp_acked {
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &lcp_req.to_bytes()).await?;
                        }
                    } else if lcp.code == LCP_CODE_CONF_NAK || lcp.code == LCP_CODE_CONF_REJ {
                        eprintln!("[L2TP] Server rejected or nak'd client LCP options! Re-sending simple Conf-Req...");
                        lcp_req = LcpPacket::new(LCP_CODE_CONF_REQ, lcp.identifier.wrapping_add(1), Vec::new());
                        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &lcp_req.to_bytes()).await?;
                    } else if lcp.code == LCP_CODE_CONF_ACK {
                        eprintln!("[L2TP] Client LCP Conf-Ack received from server!");
                        client_lcp_acked = true;
                    } else if lcp.code == LCP_CODE_ECHO_REQ {
                        let mut rep_data = lcp.data.clone();
                        if rep_data.len() >= 4 {
                            rep_data[0..4].copy_from_slice(&client_magic.to_be_bytes());
                        }
                        let echo_rep = LcpPacket::new(LCP_CODE_ECHO_REP, lcp.identifier, rep_data);
                        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &echo_rep.to_bytes()).await?;
                        if !client_lcp_acked {
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &lcp_req.to_bytes()).await?;
                        }
                    } else if lcp.code == 5 { // LCP Term-Req
                        eprintln!("[L2TP] Server sent LCP Terminate-Request (id={})", lcp.identifier);
                        let term_ack = LcpPacket::new(6, lcp.identifier, Vec::new());
                        let _ = send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &term_ack.to_bytes()).await;
                        return Err("LCP link terminated by server".into());
                    }
                }
                PPP_PROTO_AUTH_CHAP => {
                    let chap = match ChapPacket::parse(ppp_body) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[L2TP] CHAP parse error: {}", e);
                            continue;
                        }
                    };
                    eprintln!("[L2TP CHAP MSG] code={}, id={}, len={}, text='{}'", chap.code, chap.identifier, chap.data.len(), String::from_utf8_lossy(&chap.data));
                    if chap.code == CHAP_CODE_CHALLENGE {
                        if let Ok(chal) = chap.extract_challenge() {
                            let mut peer_chal = [0u8; 16];
                            OsRng.fill_bytes(&mut peer_chal);

                            eprintln!("[L2TP] Server Auth Challenge: {:02x?}", &chal);
                            eprintln!("[L2TP] Generated Peer Challenge: {:02x?}", &peer_chal);

                            let (eap_identity, mschap_logon) = self.config.auth_identities();
                            let resp = ChapPacket::build_mschapv2_response(
                                chap.identifier,
                                // Use mschap_logon (e.g. "DOMAIN\user") so SoftEther forwards
                                // the domain-qualified name to RADIUS/NPS. Using eap_identity
                                // ("user@hub") causes SoftEther to strip the hub suffix
                                // and send bare "user" to NPS, which can't resolve the domain.
                                &mschap_logon,
                                &self.config.password,
                                &chal,
                                &peer_chal,
                            );
                            eprintln!("[L2TP] Sending MS-CHAPv2 Response: id={}, eap_id='{}', logon='{}', len={}", resp.identifier, eap_identity, mschap_logon, resp.data.len());
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_AUTH_CHAP, &resp.to_bytes()).await?;
                        } else {
                            eprintln!("[L2TP] Failed to extract CHAP challenge from packet!");
                        }
                    } else if chap.code == CHAP_CODE_SUCCESS {
                        eprintln!("[L2TP] MS-CHAPv2 authentication successful! Initiating IPCP...");
                        let ipcp_req = IpcpPacket::build_conf_req(1, Ipv4Addr::new(0, 0, 0, 0), None, None);
                        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPCP, &ipcp_req.to_bytes()).await?;
                    } else if chap.code == CHAP_CODE_FAILURE {
                        let msg = String::from_utf8_lossy(&chap.data).to_string();
                        eprintln!("[L2TP] MS-CHAPv2 Authentication FAILURE from server: id={}, msg='{}'", chap.identifier, msg);
                        let stopccn = l2tp.build_stopccn();
                        let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &stopccn).await;
                        return Err(format!("MS-CHAPv2 authentication failed: {}", msg).into());
                    }
                }
                PPP_PROTO_EAP => {
                    let eap = match EapPacket::parse(ppp_body) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[L2TP] EAP packet parse error: {}", e);
                            continue;
                        }
                    };
                    eprintln!("[L2TP] EAP packet: code={}, id={}, len={}", eap.code, eap.identifier, eap.data.len());
                    match eap.code {
                        EAP_CODE_REQUEST => {
                            if eap.data.is_empty() {
                                continue;
                            }
                            let eap_type = eap.data[0];
                            let type_data = &eap.data[1..];
                            eprintln!("[L2TP] EAP Request type={}", eap_type);

                            match eap_type {
                                EAP_TYPE_IDENTITY => {
                                    let (eap_identity, _) = self.config.auth_identities();
                                    eprintln!("[L2TP] Sending EAP Identity Response: '{}'", eap_identity);
                                    let resp = EapPacket::build_identity_response(eap.identifier, &eap_identity);
                                    send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_EAP, &resp.to_bytes()).await?;
                                }
                                EAP_TYPE_MSCHAPV2 => {
                                    if type_data.is_empty() {
                                        continue;
                                    }
                                    let opcode = type_data[0];
                                    let ms_chap_id = if type_data.len() > 1 { type_data[1] } else { 0 };
                                    eprintln!("[L2TP] EAP MS-CHAPv2 opcode={}", opcode);

                                    match opcode {
                                        MSCHAPV2_OP_CHALLENGE => {
                                            if type_data.len() >= 21 {
                                                let mut auth_chal = [0u8; 16];
                                                auth_chal.copy_from_slice(&type_data[5..21]);
                                                eprintln!("[L2TP] Received EAP MS-CHAPv2 challenge: {:02x?}", &auth_chal);
                                                let (eap_identity, mschap_logon) = self.config.auth_identities();
                                                eprintln!("[L2TP] Sending EAP MS-CHAPv2 Response for logon user '{}' (EAP identity: '{}')", mschap_logon, eap_identity);
                                                let resp = EapPacket::build_mschapv2_response(
                                                    eap.identifier,
                                                    ms_chap_id,
                                                    &mschap_logon,
                                                    &self.config.password,
                                                    &auth_chal,
                                                );
                                                send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_EAP, &resp.to_bytes()).await?;
                                            } else {
                                                eprintln!("[L2TP] EAP MS-CHAPv2 challenge too short: len={}", type_data.len());
                                            }
                                        }
                                        MSCHAPV2_OP_SUCCESS => {
                                            eprintln!("[L2TP] Server sent MS-CHAPv2 Success! Acknowledging...");
                                            let ack = EapPacket::build_mschapv2_success_ack(eap.identifier, ms_chap_id);
                                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_EAP, &ack.to_bytes()).await?;
                                        }
                                        MSCHAPV2_OP_FAILURE => {
                                            let msg = String::from_utf8_lossy(&type_data[4..]).to_string();
                                            eprintln!("[L2TP] EAP MS-CHAPv2 failure from server: {}", msg);
                                            return Err(format!("EAP MS-CHAPv2 authentication failed: {}", msg).into());
                                        }
                                        _ => {
                                            eprintln!("[L2TP] Unknown EAP MS-CHAPv2 opcode: {}", opcode);
                                        }
                                    }
                                }
                                _ => {
                                    eprintln!("[L2TP] Unsupported EAP request type: {}, sending Nak proposing MS-CHAPv2", eap_type);
                                    let nak = EapPacket::build_nak_response(eap.identifier, EAP_TYPE_MSCHAPV2);
                                    send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_EAP, &nak.to_bytes()).await?;
                                }
                            }
                        }
                        EAP_CODE_SUCCESS => {
                            eprintln!("[L2TP] EAP authentication successful! Initiating IPCP...");
                            let ipcp_req = IpcpPacket::build_conf_req(1, Ipv4Addr::new(0, 0, 0, 0), None, None);
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPCP, &ipcp_req.to_bytes()).await?;
                        }
                        EAP_CODE_FAILURE => {
                            return Err("EAP authentication failed by server (invalid credentials)".into());
                        }
                        _ => {}
                    }
                }
                PPP_PROTO_IPCP => {
                    let ipcp = match IpcpPacket::parse(ppp_body) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if ipcp.code == IPCP_CODE_CONF_REQ {
                        eprintln!("[L2TP] Received server IPCP Conf-Req (id={})", ipcp.identifier);
                        let opts = ipcp.parse_options();
                        if let Some(gw) = opts.client_ip {
                            server_gateway_ip = Some(gw);
                            eprintln!("[L2TP] Server gateway IP from IPCP: {}", gw);
                        }
                        let ack = IpcpPacket::new(IPCP_CODE_CONF_ACK, ipcp.identifier, ipcp.data);
                        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPCP, &ack.to_bytes()).await?;
                        server_ipcp_acked = true;
                    } else if ipcp.code == IPCP_CODE_CONF_REJ {
                        let rejected = ipcp.option_types();
                        eprintln!("[L2TP] Server Conf-Rejected IPCP options: {:?}, resending without them", rejected);
                        if rejected.contains(&IPCP_OPT_PRIMARY_DNS) {
                            req_dns1 = false;
                        }
                        if rejected.contains(&IPCP_OPT_SECONDARY_DNS) {
                            req_dns2 = false;
                        }
                        let req = IpcpPacket::build_conf_req_opt(
                            ipcp.identifier.wrapping_add(1),
                            ipcp_config.client_ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
                            req_dns1.then(|| ipcp_config.primary_dns.unwrap_or(Ipv4Addr::new(0, 0, 0, 0))),
                            req_dns2.then(|| ipcp_config.secondary_dns.unwrap_or(Ipv4Addr::new(0, 0, 0, 0))),
                        );
                        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPCP, &req.to_bytes()).await?;
                    } else if ipcp.code == IPCP_CODE_CONF_NAK {
                        let opts = ipcp.parse_options();
                        if let Some(ip) = opts.client_ip {
                            ipcp_config.client_ip = Some(ip);
                            ipcp_config.primary_dns = opts.primary_dns.or(ipcp_config.primary_dns);
                            ipcp_config.secondary_dns = opts.secondary_dns.or(ipcp_config.secondary_dns);

                            let req = IpcpPacket::build_conf_req_opt(
                                ipcp.identifier.wrapping_add(1),
                                ip,
                                req_dns1.then(|| ipcp_config.primary_dns.unwrap_or(Ipv4Addr::new(0, 0, 0, 0))),
                                req_dns2.then(|| ipcp_config.secondary_dns.unwrap_or(Ipv4Addr::new(0, 0, 0, 0))),
                            );
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPCP, &req.to_bytes()).await?;
                        }
                    } else if ipcp.code == IPCP_CODE_CONF_ACK {
                        eprintln!("[L2TP] Client IPCP Confirmed! IP={:?}, DNS1={:?}", ipcp_config.client_ip, ipcp_config.primary_dns);
                        client_ipcp_acked = true;
                    }

                    if client_ipcp_acked && server_ipcp_acked {
                        eprintln!("[L2TP] Bidirectional IPCP negotiation complete!");
                        break;
                    }
                }
                _ => {}
            }
        }

        if !client_ipcp_acked || !server_ipcp_acked {
            let stopccn = l2tp.build_stopccn();
            let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &stopccn).await;
            return Err("PPP negotiation timed out: IPCP was not established with server".into());
        }

        let assigned_ip = ipcp_config.client_ip.ok_or("No client IP assigned by IPCP from server")?;
        let gateway_ip = server_gateway_ip.unwrap_or_else(|| {
            let oct = assigned_ip.octets();
            Ipv4Addr::new(oct[0], oct[1], oct[2], 1)
        });

        // Create point-to-point TUN device
        let mut tun = TunDevice::create(&self.config.tun, assigned_ip, gateway_ip, self.config.mtu)?;
        eprintln!("[L2TP] Created TUN device: {} with IP {} peer {}", tun.name, assigned_ip, gateway_ip);

        // Print JSON IPC event to stdout for AsteriaRay Flutter client
        let dns_list: Vec<String> = [ipcp_config.primary_dns, ipcp_config.secondary_dns]
            .into_iter()
            .flatten()
            .map(|ip| ip.to_string())
            .collect();

        let event = serde_json::json!({
            "event": "connected",
            "tun": tun.name,
            "client_ip": assigned_ip.to_string(),
            "server_ip": server_ip.to_string(),
            "dns": dns_list,
        });
        println!("{}", event);

        // --- Data Plane Loop (TUN <--> Socket ESP) ---
        let mut tun_buf = vec![0u8; 4096];
        let mut sock_buf = vec![0u8; 4096];
        let mut keepalive_timer = interval(Duration::from_secs(self.config.hello_interval.max(1)));
        let dead_peer_timeout = Duration::from_secs(self.config.dead_peer_timeout);
        let mut last_rx = tokio::time::Instant::now();
        // The server must ack every HELLO; only silence after several of them means the session is dead.
        let mut hellos_unanswered: u32 = 0;

        let mut tx_packets: u64 = 0;
        let mut tx_bytes: u64 = 0;
        let mut rx_packets: u64 = 0;
        let mut rx_bytes: u64 = 0;

        while !self.shutdown.load(Ordering::Relaxed) {
            tokio::select! {
                // Outgoing packet: TUN -> UDP ESP
                res = tun.dev.read(&mut tun_buf) => {
                    let n = match res {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    let ip_packet = &tun_buf[..n];
                    tx_packets += 1;
                    tx_bytes += n as u64;
                    if tx_packets % 100 == 1 {
                        eprintln!("[L2TP] TUN -> ESP: tx_pkts={}, tx_bytes={}", tx_packets, tx_bytes);
                    }
                    let _ = send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPV4, ip_packet).await;
                }

                // Incoming packet: UDP ESP -> TUN
                res = socket.recv_from(&mut sock_buf) => {
                    let (n, _) = match res {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    if n <= 4 || &sock_buf[..4] == &[0, 0, 0, 0] {
                        continue;
                    }
                    let spi = u32::from_be_bytes([sock_buf[0], sock_buf[1], sock_buf[2], sock_buf[3]]);
                    if spi != esp_ctx.spi_in {
                        continue;
                    }

                    let (plaintext, _) = match esp_ctx.decrypt(&sock_buf[..n]) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if plaintext.len() < 8 {
                        continue;
                    }
                    let l2tp_pkt = match L2tpPacket::parse(&plaintext[8..]) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    last_rx = tokio::time::Instant::now();
                    hellos_unanswered = 0;
                    if l2tp_pkt.is_control {
                        // A ZLB is only an ack: it carries no sequence of its own and needs no reply.
                        if !l2tp_pkt.avps.is_empty() {
                            l2tp.nr = l2tp_pkt.ns.wrapping_add(1);
                            let zlb = l2tp.build_zlb();
                            let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &zlb).await;
                        }
                    } else if let Some(ip_packet) = extract_ipv4_packet(&l2tp_pkt.payload) {
                        rx_packets += 1;
                        rx_bytes += ip_packet.len() as u64;
                        if rx_packets % 100 == 1 {
                            eprintln!("[L2TP] ESP -> TUN: rx_pkts={}, rx_bytes={}", rx_packets, rx_bytes);
                        }
                        let _ = tun.dev.write_all(ip_packet).await;
                    }
                }

                // Keepalive (Hello/ZLB)
                _ = keepalive_timer.tick() => {
                    if !dead_peer_timeout.is_zero()
                        && hellos_unanswered >= 3
                        && last_rx.elapsed() > dead_peer_timeout
                    {
                        eprintln!(
                            "[L2TP] No packets from server for {}s ({} HELLOs unanswered), giving up",
                            last_rx.elapsed().as_secs(),
                            hellos_unanswered
                        );
                        // Best effort: tell the server to drop the session so a reconnect is not blocked by it.
                        let stopccn = l2tp.build_stopccn();
                        let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &stopccn).await;
                        return Err(format!(
                            "peer is dead: nothing received for {}s",
                            self.config.dead_peer_timeout
                        )
                        .into());
                    }
                    hellos_unanswered += 1;
                    let hello = l2tp.build_hello();
                    let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &hello).await;
                }
            }
        }

        eprintln!("[L2TP] Graceful shutdown: sending StopCCN...");
        let stopccn = l2tp.build_stopccn();
        let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &stopccn).await;

        let event = serde_json::json!({
            "event": "disconnected",
            "tun": tun.name,
        });
        println!("{}", event);

        Ok(())
    }
}
