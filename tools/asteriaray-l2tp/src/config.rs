use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "AsteriaRay L2TP/IPsec VPN Client Daemon", long_about = None)]
pub struct AppConfig {
    #[arg(short, long, help = "VPN Server hostname or IPv4 address")]
    pub server: String,

    #[arg(short, long, help = "Username")]
    pub user: String,

    #[arg(short, long, help = "Password")]
    pub password: String,

    #[arg(long, help = "IPsec Pre-Shared Key (PSK)")]
    pub psk: String,

    #[arg(long, default_value = "asteria-l2tp0", help = "TUN device name")]
    pub tun: String,

    #[arg(long, default_value_t = 1400, help = "MTU for TUN device")]
    pub mtu: u16,

    #[arg(long, default_value_t = 500, help = "Initial IKE port (default: 500)")]
    pub port: u16,
}
