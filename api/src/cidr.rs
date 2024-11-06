use std::{collections::HashSet, net::Ipv4Addr};

use ipnet::Ipv4Net;
use iprange::IpRange;

pub const MIN_COMMON_PREFIX : u8 = 16;
pub const HOST_PREFIX : u8 = 32;

pub fn lowest_common_prefix(net: &Ipv4Net, ip: &Ipv4Addr) -> Option<u8> {
    let mut current = net.prefix_len();
    let base = net.addr();

    // Base case: CIDR matches the IP
    if net.contains(ip) {
        return Some(current);
    }

    let mut query : String;
    let mut tester : Ipv4Net;

    // Try checking each lower CIDR until a match is found
    while current >= MIN_COMMON_PREFIX {
        query = format!("{}/{}", base, current);
        tester = query.parse().unwrap();

        // Current networks matches.
        if tester.contains(ip) {
            break;
        }

        current -= 1;
    }

    if current >= MIN_COMMON_PREFIX {
        Some(current)
    } else {
        None
    }
}


pub fn any_match(cidr: &HashSet<Ipv4Net>, ip: &Ipv4Addr) -> bool {
    for network in cidr {
        if network.contains(ip) {
            return true;
        }
    }

    false
}

pub fn get_exact_match(cidr: &HashSet<Ipv4Net>, ip: &Ipv4Addr) -> Option<Ipv4Net> {
    cidr.clone().into_iter().find(|&network| network.contains(ip))
}

pub fn match_with_merge(cidr: &HashSet<Ipv4Net>, ip: &Ipv4Addr) -> Option<(Ipv4Net, Ipv4Net)> {
    // Iterate each network and attempt to merge the current IP with it.
    for network in cidr.clone() {
        if let Some(prefix) =  lowest_common_prefix(&network, ip) {
            // Found Candidate.
            return Some((network, swap_prefix(&network, prefix)));
        }
    }

    None
}

pub fn try_merge(cidr: &HashSet<Ipv4Net>) -> Option<HashSet<Ipv4Net>> {
    let mut range = as_range(cidr);
    range.simplify();

    let networks : HashSet<Ipv4Net> = range.into_iter().collect();

    if networks.len() < cidr.len() {
        Some(networks)
    } else {
        None
    }
}

fn as_range(cidr: &HashSet<Ipv4Net>) -> IpRange<Ipv4Net> {
    let mut range : IpRange<Ipv4Net> = IpRange::new();

    for addr in cidr.clone() {
        range.add(addr);
    }

    range
}

pub fn encode(net: &Ipv4Net) -> String {
    format!("{}/{}", net.addr(), net.prefix_len())
}

pub fn decode(str: &str) -> Option<Ipv4Net> {
    str.parse().ok()
}

pub fn swap_prefix(net: &Ipv4Net, new_prefix: u8) -> Ipv4Net {
    let new_net = format!("{}/{}", net.addr(), new_prefix);
    decode(&new_net).unwrap()
}

pub fn new_host(addr: &Ipv4Addr) -> Ipv4Net {
    let key = format!("{}/{}", addr, HOST_PREFIX);
    decode(&key).unwrap()
}
