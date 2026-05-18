use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use zapret_checker::{
    probe::{NativeTcpTlsHttpProbe, ProbeBackend},
    types::*,
};

fn timeouts() -> ProbeTimeouts {
    ProbeTimeouts {
        connect_ms: 500,
        tls_ms: 500,
        first_byte_ms: 500,
        total_ms: 1500,
    }
}

#[tokio::test]
async fn bind_zero_assigns_source_port_and_socket_holds_it_until_connect() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("bind local listener: {e}"),
    };
    let remote = listener.local_addr().unwrap();
    let probe = NativeTcpTlsHttpProbe::new(
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        1024,
        "zapret-checker".into(),
    );
    let prepared = match probe.prepare_socket(IpAddr::V4("127.0.0.1".parse().unwrap())) {
        Ok(prepared) => prepared,
        Err(_) => return,
    };
    let assigned = prepared.assigned_source_port;
    assert_ne!(assigned, 0);

    let accept = tokio::spawn(async move {
        let (_stream, peer) = listener.accept().await.unwrap();
        peer
    });
    let stream = prepared
        .socket
        .connect(SocketAddr::new(remote.ip(), remote.port()))
        .await
        .unwrap();
    let peer = accept.await.unwrap();
    assert_eq!(stream.local_addr().unwrap().port(), assigned);
    assert_eq!(peer.port(), assigned);
}

#[tokio::test]
async fn native_plain_http_probe_reads_status() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("bind local listener: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let probe = NativeTcpTlsHttpProbe::new(
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        1024,
        "zapret-checker".into(),
    );
    if probe.prepare_socket(addr.ip()).is_err() {
        return;
    }
    let task = ProbeTask {
        strategy_id: "plain".into(),
        worker_id: 0,
        strategy_args: vec![],
        target_host: "example.org".into(),
        target_ip: addr.ip(),
        target_port: addr.port(),
        protocol: ProbeProtocol::HttpPlain,
        path: "/".into(),
        timeouts: timeouts(),
    };
    let ctx = ProbeContext {
        qnum: 0,
        cancellation: None,
        baseline: true,
    };
    let result = probe.probe(task, ctx).await;
    assert_eq!(result.outcome, ProbeOutcome::Success);
    assert_eq!(result.http_status, Some(200));
    assert!(result.assigned_source_port.unwrap() > 0);
    assert_eq!(result.qnum, None);
}

#[tokio::test]
async fn native_tls_http_probe_reads_status() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("bind local listener: {e}"),
    };
    let addr = listener.local_addr().unwrap();

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["example.org".into()]).unwrap();
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut buf = [0u8; 512];
        let _ = tls.read(&mut buf).await.unwrap();
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let probe = NativeTcpTlsHttpProbe::new(
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        1024,
        "zapret-checker".into(),
    )
    .with_extra_root_certs(vec![cert_der]);
    if probe.prepare_socket(addr.ip()).is_err() {
        return;
    }
    let task = ProbeTask {
        strategy_id: "tls".into(),
        worker_id: 0,
        strategy_args: vec![],
        target_host: "example.org".into(),
        target_ip: addr.ip(),
        target_port: addr.port(),
        protocol: ProbeProtocol::Tls12Http11,
        path: "/".into(),
        timeouts: timeouts(),
    };
    let ctx = ProbeContext {
        qnum: 0,
        cancellation: None,
        baseline: true,
    };
    let result = probe.probe(task, ctx).await;
    assert_eq!(result.outcome, ProbeOutcome::Success);
    assert_eq!(result.http_status, Some(200));
    assert!(result.tls_ms.is_some());
    assert!(result.assigned_source_port.unwrap() > 0);
}

#[tokio::test]
async fn native_plain_http_probe_first_byte_timeout() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("bind local listener: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _peer) = listener.accept().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    let probe = NativeTcpTlsHttpProbe::new(
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        1024,
        "zapret-checker".into(),
    );
    if probe.prepare_socket(addr.ip()).is_err() {
        return;
    }
    let task = ProbeTask {
        strategy_id: "timeout".into(),
        worker_id: 0,
        strategy_args: vec![],
        target_host: "example.org".into(),
        target_ip: addr.ip(),
        target_port: addr.port(),
        protocol: ProbeProtocol::HttpPlain,
        path: "/".into(),
        timeouts: ProbeTimeouts {
            connect_ms: 500,
            tls_ms: 500,
            first_byte_ms: 25,
            total_ms: 1000,
        },
    };
    let ctx = ProbeContext {
        qnum: 0,
        cancellation: None,
        baseline: true,
    };
    let result = probe.probe(task, ctx).await;
    assert_eq!(result.outcome, ProbeOutcome::Timeout);
    assert_eq!(result.error_class, Some(ProbeErrorClass::FirstByteTimeout));
    assert_eq!(result.failure_kind, Some(FailureKind::TargetFailure));
}

#[tokio::test]
async fn native_probe_honors_pre_cancelled_token() {
    let probe = NativeTcpTlsHttpProbe::new(
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        1024,
        "zapret-checker".into(),
    );
    if probe.prepare_socket("127.0.0.1".parse().unwrap()).is_err() {
        return;
    }
    let token = CancellationToken::new();
    token.cancel();
    let task = ProbeTask {
        strategy_id: "cancel".into(),
        worker_id: 0,
        strategy_args: vec![],
        target_host: "example.org".into(),
        target_ip: "127.0.0.1".parse().unwrap(),
        target_port: 9,
        protocol: ProbeProtocol::HttpPlain,
        path: "/".into(),
        timeouts: timeouts(),
    };
    let ctx = ProbeContext {
        qnum: 0,
        cancellation: Some(token),
        baseline: true,
    };
    let result = probe.probe(task, ctx).await;
    assert_eq!(result.outcome, ProbeOutcome::Cancelled);
    assert_eq!(result.failure_kind, Some(FailureKind::Cancelled));
}
