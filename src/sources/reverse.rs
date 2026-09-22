use ipnet::{IpNet, Ipv4Net};
use std::net::{IpAddr, Ipv4Addr};

/// Upper bound on the number of hosts a single CIDR sweep may enumerate. A
/// large IPv4 CIDR or any IPv6 CIDR would otherwise allocate an enormous (or
/// overflowing) Vec. main.rs rejects targets above this cap unless
/// --allow-large-sweep is passed; hosts_of also caps its own output as a
/// safety net so it never collects an unbounded range.
pub const MAX_SWEEP_HOSTS: u64 = 65536;

pub fn containing_24(ip: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(ip, 24).unwrap().trunc()
}

/// Count of addresses `hosts()` would yield for `net`, computed WITHOUT
/// enumerating them. Returns None when the count is too large to represent in a
/// u64 (very large IPv6 ranges), which callers treat as "exceeds any cap".
pub fn sweep_host_count(net: &IpNet) -> Option<u64> {
    let (max_prefix, prefix) = match net {
        IpNet::V4(n) => (32u32, n.prefix_len() as u32),
        IpNet::V6(n) => (128u32, n.prefix_len() as u32),
    };
    let host_bits = max_prefix - prefix;
    if host_bits >= 64 {
        return None;
    }
    let total = 1u64.checked_shl(host_bits)?;
    // ipnet's hosts() excludes the network and broadcast addresses for IPv4
    // prefixes of /30 or larger blocks; /31 and /32 yield all addresses.
    let count = match net {
        IpNet::V4(_) if prefix <= 30 => total.saturating_sub(2),
        _ => total,
    };
    Some(count)
}

/// Enumerate the hosts of `net`, capped at MAX_SWEEP_HOSTS. The underlying
/// iterator is lazy, so taking a bounded prefix never materializes a huge
/// range even for an IPv6 CIDR.
pub fn hosts_of(net: &IpNet) -> Vec<IpAddr> {
    net.hosts().take(MAX_SWEEP_HOSTS as usize).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn computes_containing_24() {
        let net = containing_24(Ipv4Addr::new(192, 0, 2, 125));
        assert_eq!(net.to_string(), "192.0.2.0/24");
    }

    #[test]
    fn lists_hosts_in_small_cidr() {
        let net: ipnet::IpNet = "192.0.2.0/30".parse().unwrap();
        let hosts = hosts_of(&net);
        assert_eq!(hosts.len(), 2);
    }
}
