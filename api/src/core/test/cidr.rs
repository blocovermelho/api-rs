use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use iprange::IpNet;
use quickcheck::Arbitrary;
use quickcheck_macros::quickcheck;

use crate::core::utils::cidr::*;

#[derive(Clone, Debug)]
struct ClusteredIpv4Nets(pub Vec<Ipv4Net>);

impl Arbitrary for ClusteredIpv4Nets {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let len = u8::arbitrary(g);
        let top_octet = u8::arbitrary(g);

        let nets = (0..len)
            .map(|_| {
                let addr =
                    Ipv4Addr::new(top_octet, u8::arbitrary(g), u8::arbitrary(g), u8::arbitrary(g));
                let prefix = u8::arbitrary(g) % 17 + 16;
                Ipv4Net::new(addr, prefix).unwrap()
            })
            .collect();

        Self(nets)
    }
}

#[quickcheck]
fn prop_simplify_respects_bound(cluster: ClusteredIpv4Nets) -> bool {
    let ClusteredIpv4Nets(nets) = cluster;

    let simplified = simplify_nets(&nets);

    let outnets = match simplified {
        NetworkSimplification::Simplified { nets, .. } => nets,
        NetworkSimplification::Identity => nets.to_vec(),
    };

    outnets.iter().all(|n| n.prefix_len() >= MIN_COMMON_PREFIX)
}

#[quickcheck]
fn contains_ip(ip: Ipv4Addr, prefix_len: u8) -> bool {
    let prefix_len = prefix_len % 33;
    let net = Ipv4Net::new(ip, prefix_len).unwrap();
    match_prefix(&net, &ip) == PrefixLenMatch::Contains(prefix_len)
}

#[test]
fn grows_ip() {
    let net = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    let ip = Ipv4Addr::new(192, 168, 2, 42);
    let result = match_prefix(&net, &ip);
    assert_eq!(result, PrefixLenMatch::Grows { prev: 24, current: 22 });
}
#[test]
fn non_overlapping_ip() {
    let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
    let ip = Ipv4Addr::new(192, 168, 1, 42);
    let result = match_prefix(&net, &ip);
    assert_eq!(result, PrefixLenMatch::NonOverlappingWithinBound { bound: MIN_COMMON_PREFIX });
}
