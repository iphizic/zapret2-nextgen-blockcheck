# Native probe backend

The native backend is the default and critical path. It uses:

- `tokio::net::TcpSocket`
- `tokio-rustls`
- `rustls`
- `rustls-native-certs`

HTTP request:

```http
GET / HTTP/1.1
Host: <target_host>
User-Agent: zapret-checker
Connection: close
```

TLS SNI uses the target host, not the target IP. TCP connects to a resolved target IP provided by the controller.
