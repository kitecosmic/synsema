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

#[test]
fn a_mapped_ipv4_in_the_list_is_the_ipv4() {
    let n = TrustedNet::parse("::ffff:10.0.0.0/104").unwrap();
    assert!(n.contains(ip("10.1.2.3")));
    assert!(n.contains(ip("::ffff:10.1.2.3")));
    assert!(!n.contains(ip("11.0.0.1")));
}

/// Auditoría B2: el chequeo de `net` y la conexión tienen que ver el mismo host. Un authority con
/// `?`, `#`, `@`, `\`, `%` o espacios no es un host[:puerto].
#[test]
fn proxy_targets_with_more_than_host_and_port_are_refused() {
    use synsema_stdlib::server::parse_proxy_target;
    for bad in [
        "http://a.internal.example?.x.attacker.com:6379",
        "http://a.internal.example#.x.attacker.com",
        "http://user:pass@127.0.0.1:6379",
        "http://a.internal.example\\.attacker.com",
        "http://a%2e.example",
        "http://a .example",
    ] {
        assert!(parse_proxy_target(bad).is_err(), "{}", bad);
    }
    let (addr, authority, base) = parse_proxy_target("http://127.0.0.1:8080/api?x=1").unwrap();
    assert_eq!((addr.as_str(), authority.as_str(), base.as_str()), ("127.0.0.1:8080", "127.0.0.1:8080", "/api?x=1"));
    assert!(parse_proxy_target("http://[::1]:9000").is_ok());
}
