//! Goldens byte a byte de discovery (spec `specs/discovery-openapi.md` §3): el
//! `/openapi.json`, el `/sitemap.xml` y el `/docs` en Markdown que salen del fixture
//! `tests/fixtures/discovery_api.syn` (con `mount` de `discovery_mod.syn`), por el
//! MISMO camino estático que `synsema openapi` (sin ejecutar nada).
//!
//! Regenerar tras un cambio intencional del formato:
//!   SYNSEMA_BLESS=1 cargo test -p synsema-stdlib --test openapi_golden

use std::path::PathBuf;

use synsema_core::parser::parse_source;
use synsema_core::route_meta::{api_routes_static, ResponseKind, StaticProgram};
use synsema_stdlib::discovery::{docs_markdown, openapi_text, sitemap_paths, sitemap_xml, ApiInfo};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden")
}

fn check(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var("SYNSEMA_BLESS").is_ok() {
        std::fs::create_dir_all(golden_dir()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("golden {:?} ilegible ({}); ¿falta bless?", path, e));
    assert_eq!(expected.replace("\r\n", "\n"), actual, "{} cambió respecto del golden", name);
}

fn load() -> (ApiInfo, Vec<synsema_core::route_meta::ApiRoute>) {
    let path = fixtures().join("discovery_api.syn");
    let src = std::fs::read_to_string(&path).unwrap();
    let path_s = path.to_string_lossy().to_string();
    let program = parse_source(&src, &path_s).expect("parse");
    let sp = StaticProgram::load(program, &path_s).expect("modules");
    let (info, routes) = api_routes_static(&sp).expect("static").expect("serve block");
    let api = ApiInfo {
        title: ApiInfo::title_of(info.describe_about.as_deref(), info.intent.as_deref()),
        description: info.intent.clone(),
        version: info.describe_version.clone().unwrap_or_else(|| "0.0.0".into()),
        base_url: Some("https://books.example".into()),
        has_auth: info.has_auth_handler && routes.iter().any(|r| r.requires_auth),
        describe_api: info.describe_api.clone(),
    };
    (api, routes)
}

#[test]
fn openapi_json_golden() {
    let (api, routes) = load();
    check("discovery_openapi.json.golden", &openapi_text(&api, &routes));
}

#[test]
fn sitemap_golden() {
    let (_, routes) = load();
    // Sólo GET sin params, sin auth, sin stream/proxy: `/`, `/health`, `/go`, `/v1/shop`.
    assert_eq!(sitemap_paths(&routes), vec!["/", "/go", "/health", "/v1/shop"]);
    check("discovery_sitemap.xml", &sitemap_xml("https://books.example", &routes));
}

#[test]
fn docs_markdown_golden() {
    let (api, routes) = load();
    check("discovery_docs.md", &docs_markdown(&api, &routes));
}

#[test]
fn static_extraction_facts() {
    let (api, routes) = load();
    assert_eq!(api.title, "Bookshop API");
    assert_eq!(api.version, "1.4.0");
    assert!(api.has_auth);
    let find = |m: &str, p: &str| routes.iter().find(|r| r.method == m && r.path == p).unwrap_or_else(|| panic!("{} {}", m, p));
    let orders = find("POST", "/orders");
    assert!(orders.requires_auth);
    assert_eq!(orders.rate_limit, Some((5, 60.0)));
    assert_eq!(
        orders.meta.expect_shape,
        Some(vec![("book".into(), "text".into()), ("qty".into(), "number".into()), ("gift".into(), "bool".into())])
    );
    // charge() → require net(api.stripe.com) + require llm + fetch (builtin → net sin scope)
    assert_eq!(
        orders.meta.capabilities,
        vec![("llm".to_string(), None), ("net".to_string(), None), ("net".to_string(), Some("api.stripe.com".to_string()))]
    );
    let health = find("GET", "/health");
    assert!(health.rate_unlimited);
    assert_eq!(health.rate_limit, None);
    assert_eq!(health.meta.response_kind, Some(ResponseKind::Html));
    assert_eq!(find("GET", "/").meta.response_kind, Some(ResponseKind::Content));
    assert_eq!(find("GET", "/events").meta.response_kind, Some(ResponseKind::Stream));
    assert_eq!(find("GET", "/go").meta.response_kind, Some(ResponseKind::Redirect));
    assert!(find("GET", "/upstream/*path").proxy);
    // El bloque hereda su rate_limit a las rutas sin uno propio.
    assert_eq!(find("GET", "/books/:id").rate_limit, Some((100, 60.0)));
    // Montadas: prefijo aplicado, expect y capabilities del módulo (load → db).
    let shop_id = find("GET", "/v1/shop/:id");
    assert_eq!(shop_id.meta.capabilities, vec![("db".to_string(), None), ("db".to_string(), Some("./shop.db".to_string()))]);
    assert_eq!(find("POST", "/v1/shop/buy").meta.expect_shape, Some(vec![("item".into(), "text".into())]));
}
