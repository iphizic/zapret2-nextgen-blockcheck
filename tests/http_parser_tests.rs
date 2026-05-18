use zapret_checker::{
    probe::{parse_http_status, probe_outcome_for_http_status},
    types::ProbeOutcome,
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
