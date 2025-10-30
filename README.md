## Portforwarder - Build, Package, Deploy

A GO lang program to forward WebSocket connections to TCP backend, capable of running a child process and lifecycle management.

### Build

```bash
./scripts/build.sh
```

Output: `bin/portforwarder`

### Configuration

Create `config.json` in the same directory as the binary to customize settings:

```json
{
  "ws_port_offset": 10000,
  "wss_port_offset": 20000,
  "child_binary": "lcserver_org"
}
```

**Configuration Options:**
- `ws_port_offset`: Port offset for WebSocket (default: 10000). WS will listen on `offset + target_port`
- `wss_port_offset`: Port offset for WebSocket Secure (default: 20000). WSS will listen on `offset + target_port`
- `child_binary`: Name of child process binary (default: "lcserver_org")

If `config.json` is not found, default values will be used.

### Certificates
- Place certs under `cer/` in one of:
  - `portforward.crt` + `portforward.key`
  - `portforward.pem` (combined)
  - `portforward.p12` / `portforward.pfx` / `portforward.der` (empty password, or common passwords like "changeit")


### Deploy to server

Actions:
- Upload tarball, extract to `/opt/portforwarder`
- Install `/etc/init.d/portforwarder` and `/etc/sysconfig/portforwarder`
- Enable with `chkconfig` (if available) and start service

Edit runtime arguments in `/etc/sysconfig/portforwarder` (DAEMON_ARGS), e.g.:

```bash
DAEMON_ARGS="-p /pirate/lcserver -H 10.18.14.35:2182,10.18.14.36:2182,10.18.14.37:2182 -G game20817 -w 10.18.14.34 -l 10.18.14.34 -d pirate20817 -W 8817 -L 9817"
```

Service commands:

```bash
service portforwarder start
service portforwarder status
service portforwarder restart
service portforwarder stop
```

### Command Line Options

- `-w <IP>`: WAN IP address for WebSocket server
- `-W <PORT>`: WAN port to forward
- `-l <IP>`: LAN IP address for WebSocket server
- `-L <PORT>`: LAN port to forward
- `-v` / `--verbose`: Enable verbose logging (shows connection details and data transfer)
- `-p <path>`: Start child process (path will be replaced with config's child_binary)

**Example:**
```bash
# Basic usage with verbose logging
./portforwarder -w 127.0.0.1 -W 8001 -l 127.0.0.1 -L 8002 -v

# With child process
./portforwarder -w 10.18.14.34 -W 8817 -p /pirate/lcserver -d pirate20817
```

### Verbose Mode

When `-v` is enabled, you'll see detailed logs:
```
[CONN] New client connection from 127.0.0.1:54321 to target 127.0.0.1:8001
[CONN] 127.0.0.1:54321->127.0.0.1:8001: TCP connection established to 127.0.0.1:8001
[DATA] 127.0.0.1:54321->127.0.0.1:8001: Reading WebSocket frame: opcode=0x2, len=97 -> TCP
[DATA] 127.0.0.1:54321->127.0.0.1:8001: TCP read 128 bytes -> WebSocket
[DATA] 127.0.0.1:54321->127.0.0.1:8001: Writing WebSocket frame: opcode=0x2, len=128, header_len=2
```

### Notes
- Binary is CGO-disabled and statically linked (Go TLS, not system OpenSSL) for compatibility with any OpenSSL version.
- WebSocket listens on `ws_port_offset + target_port` (default: `10000 + port`)
- WebSocket Secure listens on `wss_port_offset + target_port` (default: `20000 + port`)
- Child process (configured by `child_binary`) will be started if `-p` is present; signals are forwarded.
