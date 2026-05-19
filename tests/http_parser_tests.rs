use zapret_checker::{
    probe::{
        build_http_request, classify_http_response, parse_http_response_read, parse_http_status,
        probe_outcome_for_http_status,
    },
    types::*,
};

#[test]
fn parses_http_11_200() {
    assert_eq!(parse_http_status(b"HTTP/1.1 200 OK\r\n").unwrap(), 200);
}

#[test]
fn parses_http_10_403() {
    assert_eq!(
        parse_http_status(b"HTTP/1.0 403 Forbidden\r\n").unwrap(),
        403
    );
}

#[test]
fn rejects_invalid_response() {
    assert!(parse_http_status(b"not http").is_err());
}

#[test]
fn maps_http_status_to_probe_outcome() {
    assert_eq!(
        probe_outcome_for_http_status(Some(200)),
        ProbeOutcome::Success
    );
    assert_eq!(
        probe_outcome_for_http_status(Some(403)),
        ProbeOutcome::HttpBlockPage
    );
    assert_eq!(
        probe_outcome_for_http_status(Some(451)),
        ProbeOutcome::HttpBlockPage
    );
}

#[test]
fn parses_target_request_host_mode() {
    let target = parse_target_request(
        Some("example.com".into()),
        None,
        ProbeProtocol::Tls12Http11,
        false,
    )
    .unwrap();
    assert_eq!(target.host, "example.com");
    assert_eq!(target.port, 443);
    assert_eq!(target.path_and_query, "/");
    assert_eq!(target.protocol, ProbeProtocol::Tls12Http11);
}

#[test]
fn parses_target_request_host_mode_with_path() {
    let target = parse_target_request(
        Some("istio.io/latest/logos/autotrader.svg".into()),
        None,
        ProbeProtocol::Tls12Http11,
        false,
    )
    .unwrap();
    assert_eq!(target.host, "istio.io");
    assert_eq!(target.port, 443);
    assert_eq!(target.path_and_query, "/latest/logos/autotrader.svg");
    assert_eq!(target.protocol, ProbeProtocol::Tls12Http11);
}

#[test]
fn parses_target_request_https_url() {
    let target = parse_target_request(
        None,
        Some("https://example.com/a/b?x=1".into()),
        ProbeProtocol::Tls12Http11,
        false,
    )
    .unwrap();
    assert_eq!(target.scheme, TargetScheme::Https);
    assert_eq!(target.host, "example.com");
    assert_eq!(target.port, 443);
    assert_eq!(target.path_and_query, "/a/b?x=1");
    assert_eq!(target.protocol, ProbeProtocol::Tls12Http11);
}

#[test]
fn parses_target_request_http_url() {
    let target = parse_target_request(
        None,
        Some("http://example.com:8080/test".into()),
        ProbeProtocol::Tls12Http11,
        false,
    )
    .unwrap();
    assert_eq!(target.scheme, TargetScheme::Http);
    assert_eq!(target.protocol, ProbeProtocol::HttpPlain);
    assert_eq!(target.port, 8080);
    assert_eq!(target.path_and_query, "/test");
}

#[test]
fn rejects_host_url_conflict() {
    assert!(parse_target_request(
        Some("example.com".into()),
        Some("https://example.com/".into()),
        ProbeProtocol::Tls12Http11,
        false,
    )
    .is_err());
}

#[test]
fn rejects_unsupported_scheme() {
    assert!(parse_target_request(
        None,
        Some("ftp://example.com".into()),
        ProbeProtocol::Tls12Http11,
        false,
    )
    .is_err());
}

#[test]
fn parses_http_response_headers_and_body() {
    let read = parse_http_response_read(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        Some(12),
    );
    assert_eq!(read.status, Some(200));
    assert!(read.headers_complete);
    assert_eq!(read.body_bytes, 5);
}

#[test]
fn body_criteria_requires_body_bytes() {
    let (outcome, class, _message) =
        classify_http_response(Some(200), true, 0, HttpMethod::Get, ReadMode::Body, 1);
    assert_ne!(outcome, ProbeOutcome::Success);
    assert_eq!(class, Some(ProbeErrorClass::BodyTooSmall));
}

#[test]
fn head_headers_only_can_succeed() {
    let (outcome, class, _message) =
        classify_http_response(Some(200), true, 0, HttpMethod::Head, ReadMode::Headers, 1);
    assert_eq!(outcome, ProbeOutcome::Success);
    assert_eq!(class, None);
}

#[test]
fn request_builder_uses_config_user_agent() {
    let task = request_task(443, "ConfigUA/1.0");
    let request = build_http_request(&task);
    assert!(request.contains("User-Agent: ConfigUA/1.0\r\n"));
}

#[test]
fn request_builder_includes_non_standard_host_port() {
    let task = request_task(8443, "ConfigUA/1.0");
    let request = build_http_request(&task);
    assert!(request.contains("Host: example.com:8443\r\n"));
}

fn request_task(port: u16, user_agent: &str) -> ProbeTask {
    ProbeTask {
        strategy_id: "test".into(),
        worker_id: 0,
        strategy_args: vec![],
        target_host: "example.com".into(),
        target_ip: "127.0.0.1".parse().unwrap(),
        target_port: port,
        protocol: ProbeProtocol::Tls12Http11,
        path: "/api".into(),
        request: HttpRequestSpec {
            method: HttpMethod::Get,
            path_and_query: "/api".into(),
            user_agent: user_agent.into(),
            read_mode: ReadMode::Body,
            min_body_bytes: 1,
            max_read_bytes: 65536,
        },
        timeouts: ProbeTimeouts {
            connect_ms: 100,
            tls_ms: 100,
            first_byte_ms: 100,
            total_ms: 100,
        },
    }
}
