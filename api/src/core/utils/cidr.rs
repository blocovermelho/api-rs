use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use iprange::IpNet;

pub enum PrefixLenMatch {
    Contains(u8),
    Grows { prev: u8, current: u8 },
    NonOverlappingWithinBound { bound: u8 },
}

pub enum NetworkMerge {
    Merged { network: Ipv4Net, bound: u8 },
    Simplified { nets: Vec<Ipv4Net>, bound: u8 },
    NonOverlapping,
}

pub const MIN_COMMON_PREFIX: u8 = 16;

pub fn match_prefix(net: &Ipv4Net, ip: &Ipv4Addr) -> PrefixLenMatch {
    if net.contains(ip) {
        return PrefixLenMatch::Contains(net.prefix_len());
    }

    let mut guess = net.prefix_len() - 1;

    while guess >= MIN_COMMON_PREFIX {
        if net.with_new_prefix(guess).contains(ip) {
            return PrefixLenMatch::Grows { prev: net.prefix_len(), current: guess };
        };
        guess -= 1;
    }

    PrefixLenMatch::NonOverlappingWithinBound { bound: MIN_COMMON_PREFIX }
}

pub fn merge_nets(lhs: &Ipv4Net, rhs: &Ipv4Net) -> NetworkMerge {
    if lhs == rhs {
        return NetworkMerge::Merged { network: *lhs, bound: MIN_COMMON_PREFIX };
    }

    match match_prefix(lhs, &rhs.addr()) {
        PrefixLenMatch::Contains(_) => {
            NetworkMerge::Merged { network: *lhs, bound: MIN_COMMON_PREFIX }
        }
        PrefixLenMatch::Grows { current, .. } => NetworkMerge::Merged {
            network: lhs.with_new_prefix(current),
            bound: MIN_COMMON_PREFIX,
        },
        PrefixLenMatch::NonOverlappingWithinBound { .. } => NetworkMerge::NonOverlapping,
    }
}
