use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "AsteriaRay L2TP/IPsec VPN Client Daemon", long_about = None)]
pub struct AppConfig {
    #[arg(short, long, help = "VPN Server hostname or IPv4 address")]
    pub server: String,

    #[arg(short, long, default_value = "", help = "Username")]
    pub user: String,

    #[arg(short, long, default_value = "", help = "Password")]
    pub password: String,

    #[arg(long, default_value = "", help = "IPsec Pre-Shared Key (PSK)")]
    pub psk: String,

    #[arg(
        long,
        help = "Read credentials as one JSON line from stdin ({\"user\",\"password\",\"psk\"}) so they stay out of the process list"
    )]
    pub secrets_stdin: bool,

    #[arg(long, default_value = "asteria-l2tp0", help = "TUN device name")]
    pub tun: String,

    #[arg(long, default_value_t = 1400, help = "MTU for TUN device")]
    pub mtu: u16,

    #[arg(
        long,
        default_value = "",
        help = "Optional SoftEther virtual hub; used as EAP identity realm (user@hub)"
    )]
    pub hub: String,

    #[arg(long, default_value_t = 500, help = "Initial IKE port (default: 500)")]
    pub port: u16,

    #[arg(long, default_value_t = 20, help = "Seconds between L2TP HELLO keepalives")]
    pub hello_interval: u64,

    #[arg(
        long,
        default_value_t = 120,
        help = "Exit with an error when no packet arrives from the server for this many seconds (0 disables)"
    )]
    pub dead_peer_timeout: u64,
}

#[derive(serde::Deserialize)]
struct Secrets {
    #[serde(default)]
    user: Option<String>,
    password: String,
    psk: String,
}

impl AppConfig {
    /// Fills credentials from a JSON line when `--secrets-stdin` is set; otherwise checks the argv ones.
    pub fn load_secrets(&mut self, line: Option<&str>) -> Result<(), String> {
        if self.secrets_stdin {
            let line = line.ok_or("--secrets-stdin given but stdin was empty")?;
            let s: Secrets = serde_json::from_str(line.trim()).map_err(|e| format!("invalid secrets JSON: {e}"))?;
            if let Some(user) = s.user {
                self.user = user;
            }
            self.password = s.password;
            self.psk = s.psk;
        }
        if self.user.is_empty() || self.password.is_empty() || self.psk.is_empty() {
            return Err("user, password and psk are required (argv or --secrets-stdin)".into());
        }
        Ok(())
    }

    /// Returns (eap_identity, mschap_logon_name).
    ///
    /// The MS-CHAPv2 logon name is the username exactly as configured (e.g. `DOMAIN\user`),
    /// minus an optional `@hub` / `hub\` qualifier. The EAP identity is `<bare_user>@<hub>`
    /// when a hub is configured, otherwise the logon name unchanged.
    pub fn auth_identities(&self) -> (String, String) {
        let raw_user = self.user.trim();
        let hub = self.hub.trim();

        let logon = if hub.is_empty() {
            raw_user
        } else if let Some(rest) = raw_user.strip_suffix(&format!("@{}", hub)) {
            rest
        } else if let Some(rest) = raw_user.strip_prefix(&format!("{}\\", hub)) {
            rest
        } else {
            raw_user
        };

        let eap_identity = if hub.is_empty() {
            logon.to_string()
        } else {
            let bare_user = logon
                .rsplit('\\')
                .next()
                .unwrap_or(logon)
                .split('@')
                .next()
                .unwrap_or(logon);
            format!("{}@{}", bare_user, hub)
        };

        (eap_identity, logon.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(user: &str, hub: &str) -> AppConfig {
        AppConfig {
            server: "h".into(),
            user: user.into(),
            password: "p".into(),
            psk: "k".into(),
            tun: "t".into(),
            mtu: 1400,
            hub: hub.into(),
            secrets_stdin: false,
            port: 500,
            hello_interval: 20,
            dead_peer_timeout: 120,
        }
    }

    #[test]
    fn no_hub_keeps_user_as_is() {
        assert_eq!(cfg("DOM\\bob", "").auth_identities(), ("DOM\\bob".into(), "DOM\\bob".into()));
    }

    #[test]
    fn hub_builds_eap_identity() {
        assert_eq!(cfg("DOM\\bob@hub1", "hub1").auth_identities(), ("bob@hub1".into(), "DOM\\bob".into()));
        assert_eq!(cfg("bob", "hub1").auth_identities(), ("bob@hub1".into(), "bob".into()));
    }

    #[test]
    fn secrets_from_stdin_json() {
        let mut c = cfg("", "");
        c.secrets_stdin = true;
        c.load_secrets(Some(r#"{"user":"alice","password":"pw","psk":"k"}"#)).unwrap();
        assert_eq!((c.user.as_str(), c.password.as_str(), c.psk.as_str()), ("alice", "pw", "k"));
    }

    #[test]
    fn missing_credentials_are_rejected() {
        let mut c = cfg("", "");
        c.password.clear();
        assert!(c.load_secrets(None).is_err());
    }
}
