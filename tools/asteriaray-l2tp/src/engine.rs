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
use crate::l2tp::packet::L2tpPacket;
use crate::ppp::auth::{ChapPacket, CHAP_CODE_CHALLENGE, CHAP_CODE_SUCCESS};
use crate::ppp::ipcp::{IpcpConfig, IpcpPacket, IPCP_CODE_CONF_ACK, IPCP_CODE_CONF_NAK};
use crate::ppp::lcp::{LcpPacket, LCP_CODE_CONF_ACK, LCP_CODE_CONF_REQ, PPP_PROTO_AUTH_CHAP, PPP_PROTO_IPCP, PPP_PROTO_IPV4, PPP_PROTO_LCP};
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

        // <- Message 2
        let mut buf = vec![0u8; 4096];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
        eprintln!("[L2TP] Received Message 2 ({} bytes) from {}", len, from);
        p1.handle_message_2(&buf[..len])?;

        // Message 3 ->
        let m3 = p1.build_message_3();
        eprintln!("[L2TP] Sending Message 3 ({} bytes): {:02x?}", m3.len(), &m3);
        socket.send_to(&m3, from).await?;

        // <- Message 4
        let (len, from_m4) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
        eprintln!("[L2TP] Received Message 4 ({} bytes) from {}", len, from_m4);
        p1.handle_message_4(&buf[..len])?;

        // Message 5 ->
        let m5 = p1.build_message_5()?;
        eprintln!("[L2TP] Sending Message 5 ({} bytes)", m5.len());
        socket.send_to(&m5, from_m4).await?;

        // <- Message 6
        let (len, from_m6) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
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
        let (len, from_qm) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
        eprintln!("[L2TP] Received QM response ({} bytes) from {}", len, from_qm);
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
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
        let (plaintext, _) = esp_ctx.decrypt(&buf[..len])?;
        if plaintext.len() < 8 {
            return Err("Truncated L2TP UDP payload".into());
        }
        let sccrp = L2tpPacket::parse(&plaintext[8..])?;
        l2tp.handle_sccrp(&sccrp)?;

        // 3. SCCCN ->
        let scccn = l2tp.build_scccn();
        send_l2tp(&socket, peer_addr, &mut esp_ctx, &scccn).await?;

        // 4. ICRQ ->
        let icrq = l2tp.build_icrq();
        send_l2tp(&socket, peer_addr, &mut esp_ctx, &icrq).await?;

        // 5. <- ICRP
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
        let (plaintext, _) = esp_ctx.decrypt(&buf[..len])?;
        let icrp = L2tpPacket::parse(&plaintext[8..])?;
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
            let mut ppp_frame = Vec::with_capacity(2 + body.len());
            ppp_frame.extend_from_slice(&proto.to_be_bytes());
            ppp_frame.extend_from_slice(body);

            let data_pkt = L2tpPacket::new_data(l2tp.remote_tunnel_id, l2tp.remote_session_id, ppp_frame);
            send_l2tp(socket, peer_addr, esp_ctx, &data_pkt).await?;
            Ok(())
        }

        // --- PPP Negotiation (LCP -> MS-CHAPv2 -> IPCP) ---
        // 1. LCP Conf-Req ->
        let lcp_req = LcpPacket::build_conf_req(1, self.config.mtu, OsRng.next_u32());
        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &lcp_req.to_bytes()).await?;

        let mut ipcp_config = IpcpConfig::default();

        // Read PPP frames until IPCP is complete
        for _ in 0..15 {
            let (len, _) = match tokio::time::timeout(Duration::from_secs(4), socket.recv_from(&mut buf)).await {
                Ok(Ok(res)) => res,
                _ => continue,
            };

            let (plaintext, _) = match esp_ctx.decrypt(&buf[..len]) {
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

            if l2tp_pkt.is_control {
                l2tp.nr = l2tp_pkt.ns.wrapping_add(1);
                let zlb = l2tp.build_zlb();
                let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &zlb).await;
                continue;
            }

            // Data packet with PPP
            if l2tp_pkt.payload.len() < 2 {
                continue;
            }
            let proto = u16::from_be_bytes([l2tp_pkt.payload[0], l2tp_pkt.payload[1]]);
            let ppp_body = &l2tp_pkt.payload[2..];

            match proto {
                PPP_PROTO_LCP => {
                    let lcp = match LcpPacket::parse(ppp_body) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if lcp.code == LCP_CODE_CONF_REQ {
                        // Ack server's LCP parameters
                        let ack = LcpPacket::new(LCP_CODE_CONF_ACK, lcp.identifier, lcp.data);
                        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_LCP, &ack.to_bytes()).await?;
                    }
                }
                PPP_PROTO_AUTH_CHAP => {
                    let chap = match ChapPacket::parse(ppp_body) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if chap.code == CHAP_CODE_CHALLENGE {
                        if let Ok(chal) = chap.extract_challenge() {
                            let mut peer_chal = [0u8; 16];
                            OsRng.fill_bytes(&mut peer_chal);

                            let resp = ChapPacket::build_mschapv2_response(
                                chap.identifier,
                                &self.config.user,
                                &self.config.password,
                                &chal,
                                &peer_chal,
                            );
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_AUTH_CHAP, &resp.to_bytes()).await?;
                        }
                    } else if chap.code == CHAP_CODE_SUCCESS {
                        eprintln!("[L2TP] MS-CHAPv2 authentication successful!");
                        // Request IPCP
                        let ipcp_req = IpcpPacket::build_conf_req(1, Ipv4Addr::new(0, 0, 0, 0), None, None);
                        send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPCP, &ipcp_req.to_bytes()).await?;
                    }
                }
                PPP_PROTO_IPCP => {
                    let ipcp = match IpcpPacket::parse(ppp_body) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if ipcp.code == IPCP_CODE_CONF_NAK {
                        // Server provided our assigned IP and DNS!
                        let opts = ipcp.parse_options();
                        if let Some(ip) = opts.client_ip {
                            ipcp_config.client_ip = Some(ip);
                            ipcp_config.primary_dns = opts.primary_dns;
                            ipcp_config.secondary_dns = opts.secondary_dns;

                            // Send Conf-Req with given IP
                            let req = IpcpPacket::build_conf_req(
                                ipcp.identifier.wrapping_add(1),
                                ip,
                                opts.primary_dns,
                                opts.secondary_dns,
                            );
                            send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPCP, &req.to_bytes()).await?;
                        }
                    } else if ipcp.code == IPCP_CODE_CONF_ACK {
                        eprintln!("[L2TP] IPCP Confirmed! IP={:?}, DNS1={:?}", ipcp_config.client_ip, ipcp_config.primary_dns);
                        break;
                    }
                }
                _ => {}
            }
        }

        let assigned_ip = ipcp_config.client_ip.unwrap_or(Ipv4Addr::new(10, 255, 255, 2));

        // Create TUN device
        let mut tun = TunDevice::create(&self.config.tun, assigned_ip, self.config.mtu)?;
        eprintln!("[L2TP] Created TUN device: {} with IP {}", tun.name, assigned_ip);

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
        let mut keepalive_timer = interval(Duration::from_secs(20));

        while !self.shutdown.load(Ordering::Relaxed) {
            tokio::select! {
                // Outgoing packet: TUN -> UDP ESP
                res = tun.dev.read(&mut tun_buf) => {
                    let n = match res {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    let ip_packet = &tun_buf[..n];
                    let _ = send_ppp(&socket, peer_addr, &mut esp_ctx, &l2tp, PPP_PROTO_IPV4, ip_packet).await;
                }

                // Incoming packet: UDP ESP -> TUN
                res = socket.recv_from(&mut sock_buf) => {
                    let (n, _) = match res {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
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

                    if l2tp_pkt.is_control {
                        l2tp.nr = l2tp_pkt.ns.wrapping_add(1);
                        let zlb = l2tp.build_zlb();
                        let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &zlb).await;
                    } else if l2tp_pkt.payload.len() >= 2 {
                        let proto = u16::from_be_bytes([l2tp_pkt.payload[0], l2tp_pkt.payload[1]]);
                        if proto == PPP_PROTO_IPV4 {
                            let ip_packet = &l2tp_pkt.payload[2..];
                            let _ = tun.dev.write_all(ip_packet).await;
                        }
                    }
                }

                // Keepalive (Hello/ZLB)
                _ = keepalive_timer.tick() => {
                    let zlb = l2tp.build_zlb();
                    let _ = send_l2tp(&socket, peer_addr, &mut esp_ctx, &zlb).await;
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
