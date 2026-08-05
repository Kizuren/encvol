use crate::EncvolError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    Dhcp,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interface: String,
    pub mac_address: Option<String>,
    pub mode: NetworkMode,
    pub addresses: Vec<String>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
}

impl NetworkConfig {
    pub fn validate(&self) -> Result<(), EncvolError> {
        let safe_value = |value: &str| {
            !value.is_empty()
                && !value.contains(['\n', '\r', '[', ']'])
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
                })
        };
        if !safe_value(&self.interface) {
            return Err(EncvolError::Manifest("network interface is invalid".into()));
        }
        if let Some(mac) = &self.mac_address {
            if mac.len() != 17
                || !mac.split(':').all(|part| {
                    part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return Err(EncvolError::Manifest(
                    "network MAC address is invalid".into(),
                ));
            }
        }
        for address in &self.addresses {
            let Some((ip, prefix)) = address.split_once('/') else {
                return Err(EncvolError::Manifest(
                    "network address needs a CIDR prefix".into(),
                ));
            };
            let ip: IpAddr = ip
                .parse()
                .map_err(|_| EncvolError::Manifest("network address is invalid".into()))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| EncvolError::Manifest("network prefix is invalid".into()))?;
            if prefix > if ip.is_ipv4() { 32 } else { 128 } {
                return Err(EncvolError::Manifest("network prefix is invalid".into()));
            }
        }
        for address in self.gateway.iter().chain(self.dns.iter()) {
            address.parse::<IpAddr>().map_err(|_| {
                EncvolError::Manifest("network gateway or DNS value is invalid".into())
            })?;
        }
        if self.mode == NetworkMode::Static && self.addresses.is_empty() {
            return Err(EncvolError::Manifest(
                "static networking requires at least one address".into(),
            ));
        }
        Ok(())
    }

    pub fn to_networkd(&self) -> String {
        let mut s = String::from("[Match]\n");
        if let Some(mac) = &self.mac_address {
            s.push_str(&format!("MACAddress={mac}\n"));
        } else {
            s.push_str(&format!("Name={}\n", self.interface));
        }
        s.push_str("\n[Network]\n");
        match self.mode {
            NetworkMode::Dhcp => s.push_str("DHCP=yes\n"),
            NetworkMode::Static => {
                for a in &self.addresses {
                    s.push_str(&format!("Address={a}\n"));
                }
                if let Some(gateway) = &self.gateway {
                    s.push_str(&format!("Gateway={gateway}\n"));
                }
            }
        }
        for dns in &self.dns {
            s.push_str(&format!("DNS={dns}\n"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn static_network_translates() {
        let c = NetworkConfig {
            interface: "ens3".into(),
            mac_address: None,
            mode: NetworkMode::Static,
            addresses: vec!["192.0.2.5/24".into()],
            gateway: Some("192.0.2.1".into()),
            dns: vec!["1.1.1.1".into()],
        };
        let o = c.to_networkd();
        assert!(o.contains("Address=192.0.2.5/24") && o.contains("Gateway=192.0.2.1"));
        assert!(c.validate().is_ok());
    }
    #[test]
    fn rejects_networkd_injection_and_bad_addresses() {
        let mut c = NetworkConfig {
            interface: "eth0\n[Network]".into(),
            mac_address: None,
            mode: NetworkMode::Dhcp,
            addresses: vec![],
            gateway: None,
            dns: vec![],
        };
        assert!(c.validate().is_err());
        c.interface = "eth0".into();
        c.mode = NetworkMode::Static;
        c.addresses = vec!["not-a-cidr".into()];
        assert!(c.validate().is_err());
    }
}
