use std::net::Ipv4Addr;
use std::process::Command;
use tun2::{AsyncDevice, Configuration};

pub struct TunDevice {
    pub name: String,
    pub ip: Ipv4Addr,
    pub dev: AsyncDevice,
}

impl TunDevice {
    pub fn create(name: &str, ip: Ipv4Addr, mtu: u16) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut config = Configuration::default();
        config.tun_name(name);
        config.mtu(mtu);
        config.up();

        let dev = tun2::create_as_async(&config)?;

        // Configure IP address via `ip addr add <ip>/32 dev <name>`
        let _ = Command::new("ip")
            .args(["addr", "add", &format!("{}/32", ip), "dev", name])
            .status();

        let _ = Command::new("ip")
            .args(["link", "set", "dev", name, "up", "mtu", &mtu.to_string()])
            .status();

        Ok(Self {
            name: name.to_string(),
            ip,
            dev,
        })
    }
}
