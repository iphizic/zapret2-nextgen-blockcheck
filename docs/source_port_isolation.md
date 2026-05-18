# Source-port isolation

The checker must never reserve a source port by binding and closing the socket. The same socket that performed `bind(local_ip:0)` must be used for `connect()`.

Required ordering:

```text
TcpSocket::new_v4/new_v6
bind(local_ip:0)
local_addr().port()
QueueAllocator.acquire()
start nfqws2 --qnum=<qnum>
install firewall rule: exact tcp sport <assigned_port> -> queue <qnum>
connect() with the same socket
TLS handshake / HTTP probe
cleanup
```

The qnum is independent from the source port. It is assigned by QueueAllocator.
