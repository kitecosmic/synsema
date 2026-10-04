//! v0.6.42 — `trust proxy`: el parseo de IPs y CIDRs y la pertenencia (sin crate de redes).

use std::net::IpAddr;
use synsema_stdlib::server::TrustedNet;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn a_single_ip_trusts_only_itself() {
    let n = TrustedNet::parse("127.0.0.1").unwrap();
    assert!(n.contains(ip("127.0.0.1")));
    assert!(!n.contains(ip("127.0.0.2")));
    // Una IPv4 mapeada en IPv6 es la misma dirección.
    assert!(n.contains(ip("::ffff:127.0.0.1")));
}

#[test]
fn cidrs_cover_their_range_in_v4_and_v6() {
    let n = TrustedNet::parse("10.0.0.0/8").unwrap();
    assert!(n.contains(ip("10.200.3.4")));
    assert!(!n.contains(ip("11.0.0.1")));
    let all = TrustedNet::parse("0.0.0.0/0").unwrap();
    assert!(all.contains(ip("8.8.8.8")));
    let v6 = TrustedNet::parse("fd00::/8").unwrap();
    assert!(v6.contains(ip("fd12::1")));
    assert!(!v6.contains(ip("fe80::1")));
    assert!(!v6.contains(ip("10.0.0.1")), "una v4 no está en un rango v6");
    let lo = TrustedNet::parse("[::1]").unwrap();
    assert!(lo.contains(ip("::1")));
}

#[test]
fn garbage_is_rejected_with_the_form_expected() {
    for bad in ["localhost", "10.0.0.0/33", "::1/129", "10.0.0/8", ""] {
        let e = TrustedNet::parse(bad).unwrap_err();
        assert!(e.starts_with("trust proxy:"), "{}: {}", bad, e);
    }
}
