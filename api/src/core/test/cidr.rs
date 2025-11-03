use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
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
