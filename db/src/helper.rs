use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::interface::NetworkProvider;

pub const LOWEST_PREFIX_LEN: u8 = 16;

pub fn check_cidr<T>(lists: Vec<T>, ip: Ipv4Addr) -> CidrAction<T>
where
    T: NetworkProvider,
{
    for entry in lists {
        if entry.get_network().contains(&ip) {
            return CidrAction::Match(entry);
        }

        let mut mask = entry.get_mask();
        while mask >= LOWEST_PREFIX_LEN {
            mask = mask - 1;
            if entry.with_mask(mask).contains(&ip) {
                return CidrAction::MaskUpdate(entry, mask);
            }
        }
    }
    CidrAction::Unmatched(Ipv4Net::new(ip, 32).unwrap())
}

pub enum CidrAction<T>
where
    T: NetworkProvider,
{
    Match(T),
    MaskUpdate(T, u8),
    Unmatched(Ipv4Net),
}
