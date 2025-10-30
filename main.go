package main

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/gorilla/websocket"
    "golang.org/x/crypto/pkcs12"
)

type forwardPair struct {
    listenIP   string
    targetIP   string
    targetPort int
}

type serversGroup struct {
    httpServers []*http.Server
    mu          sync.Mutex
}

func (g *serversGroup) add(s *http.Server) {
    g.mu.Lock()
    g.httpServers = append(g.httpServers, s)
    g.mu.Unlock()
}

func (g *serversGroup) shutdownAll(ctx context.Context) {
    g.mu.Lock()
    servers := append([]*http.Server(nil), g.httpServers...)
    g.mu.Unlock()
    var wg sync.WaitGroup
    for _, s := range servers {
        wg.Add(1)
        go func(srv *http.Server) {
            defer wg.Done()
            _ = srv.Shutdown(ctx)
        }(s)
    }
    wg.Wait()
}

type Config struct {
    WSPortOffset  int    `json:"ws_port_offset"`
    WSSPortOffset int    `json:"wss_port_offset"`
    ChildBinary   string `json:"child_binary"`
}

var verbose bool
var appConfig Config

func loadConfig() Config {
    // Default values
    cfg := Config{
        WSPortOffset:  10000,
        WSSPortOffset: 20000,
        ChildBinary:   "lcserver_org",
    }

    // Try to load from config.json in same directory as executable
    exe, err := os.Executable()
    if err != nil {
        return cfg
    }
    baseDir := filepath.Dir(exe)
    configPath := filepath.Join(baseDir, "config.json")

    data, err := os.ReadFile(configPath)
    if err != nil {
        // Config file not found, use defaults
        return cfg
    }

    if err := json.Unmarshal(data, &cfg); err != nil {
        log.Printf("[CONFIG] Warning: failed to parse config.json, using defaults: %v", err)
        return Config{
            WSPortOffset:  10000,
            WSSPortOffset: 20000,
            ChildBinary:   "lcserver_org",
        }
    }

    log.Printf("[CONFIG] Loaded config: WS offset=%d, WSS offset=%d, Child binary=%s",
        cfg.WSPortOffset, cfg.WSSPortOffset, cfg.ChildBinary)
    return cfg
}

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    // Load configuration
    appConfig = loadConfig()

    // Extract only -w, -l, -W, -L, -v for this process. For child, restore ALL original flags (replace ONLY -p value!!!)
    var wIP, lIP string
    var WPort, LPort int
    shouldRunChild := false
    var childArgs []string

    args := os.Args[1:]
    for i := 0; i < len(args); i++ {
        arg := args[i]
        // Store locals for forwarder functionality only, do not remove from child!
        if arg == "-w" && i+1 < len(args) {
            wIP = args[i+1]
        }
        if arg == "-l" && i+1 < len(args) {
            lIP = args[i+1]
        }
        if arg == "-W" && i+1 < len(args) {
            fmt.Sscanf(args[i+1], "%d", &WPort)
        }
        if arg == "-L" && i+1 < len(args) {
            fmt.Sscanf(args[i+1], "%d", &LPort)
        }
        if arg == "-v" || arg == "--verbose" {
            verbose = true
        }
        // ------- Build childArgs by RESTORING ALL args, except for -p value
        // Replace -p xxx with -p lcserver
        if arg == "-p" {
            shouldRunChild = true
            childArgs = append(childArgs, "-p")
            if i+1 < len(args) {
                childArgs = append(childArgs, "lcserver")
                i++ // skip next (xxx)
            }
            continue
        }
        // Replace -p=xxx with -p=lcserver
        if strings.HasPrefix(arg, "-p=") {
            shouldRunChild = true
            childArgs = append(childArgs, "-p=lcserver")
            continue
        }
        // Other flags unchanged for child
        childArgs = append(childArgs, arg)
    }

    var srvGroup serversGroup
    stopCh := make(chan struct{})

    // Build forwarder pairs based on inputs
    var pairs []forwardPair
    if WPort > 0 && wIP != "" {
        pairs = append(pairs, forwardPair{listenIP: wIP, targetIP: wIP, targetPort: WPort})
    }
    if LPort > 0 && lIP != "" {
        pairs = append(pairs, forwardPair{listenIP: lIP, targetIP: lIP, targetPort: LPort})
    }

    // Start forwarders
    var wgForward sync.WaitGroup
    for _, p := range pairs {
        ip := p.listenIP
        tcpTarget := net.JoinHostPort(p.targetIP, fmt.Sprintf("%d", p.targetPort))
        // WS on configured offset + port
        wsPort := appConfig.WSPortOffset + p.targetPort
        wssPort := appConfig.WSSPortOffset + p.targetPort
        wgForward.Add(2)
        go func(bindIP string, listenPort int, target string) {
            defer wgForward.Done()
            srv := newWSServer(bindIP, listenPort, target, false, nil)
            srvGroup.add(srv)
            log.Printf("[WS] Starting WebSocket server: %s:%d -> %s", bindIP, listenPort, target)
            _ = listenAndServeHTTP(srv)
        }(ip, wsPort, tcpTarget)

        go func(bindIP string, listenPort int, target string) {
            defer wgForward.Done()
            tlsCfg, err := loadTLSConfig()
            if err != nil {
                log.Printf("[wss %s:%d] TLS not configured: %v", bindIP, listenPort, err)
                return
            }
            srv := newWSServer(bindIP, listenPort, target, true, tlsCfg)
            srvGroup.add(srv)
            log.Printf("[WSS] Starting WebSocket Secure server: %s:%d -> %s", bindIP, listenPort, target)
            _ = listenAndServeHTTP(srv)
        }(ip, wssPort, tcpTarget)
    }

    // Start child if requested
    var childCmd *exec.Cmd
    if shouldRunChild {
        childBinaryPath := "./" + appConfig.ChildBinary
        log.Printf("[CHILD] Starting child process: %s", childBinaryPath)
        childCmd = exec.Command(childBinaryPath, childArgs...)
        childCmd.Stdout = os.Stdout
        childCmd.Stderr = os.Stderr
        childCmd.Stdin = os.Stdin
        if err := childCmd.Start(); err != nil {
            log.Fatalf("[CHILD] Failed to start %s: %v", appConfig.ChildBinary, err)
        }
        go func() {
            err := childCmd.Wait()
            if err != nil {
                log.Printf("[CHILD] %s exited: %v", appConfig.ChildBinary, err)
            } else {
                log.Printf("[CHILD] %s exited", appConfig.ChildBinary)
            }
            close(stopCh)
        }()
    }

    // Signal handling: forward to child, and trigger shutdown
    sigCh := make(chan os.Signal, 8)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)

    select {
    case sig := <-sigCh:
        if childCmd != nil && childCmd.Process != nil {
            _ = childCmd.Process.Signal(sig)
        }
    case <-stopCh:
        // child exited
    }

    // Graceful shutdown of servers
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    srvGroup.shutdownAll(ctx)
    cancel()
}

func listenAndServeHTTP(srv *http.Server) error {
    // Allow binding to IP explicitly
    ln, err := net.Listen("tcp", srv.Addr)
    if err != nil {
        log.Printf("listen error on %s: %v", srv.Addr, err)
        return err
    }
    if srv.TLSConfig != nil {
        return srv.ServeTLS(ln, "", "")
    }
    return srv.Serve(ln)
}

func newWSServer(bindIP string, listenPort int, tcpTarget string, useTLS bool, tlsCfg *tls.Config) *http.Server {
    upgrader := &websocket.Upgrader{
        ReadBufferSize:  32 * 1024,
        WriteBufferSize: 32 * 1024,
        CheckOrigin:     func(r *http.Request) bool { return true },
    }

    handler := http.NewServeMux()
    handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            return
        }
        handleWS(conn, tcpTarget)
    })

    srv := &http.Server{
        Addr:         net.JoinHostPort(bindIP, fmt.Sprintf("%d", listenPort)),
        Handler:      handler,
        TLSConfig:    tlsCfg,
        ReadTimeout:  0,
        WriteTimeout: 0,
        IdleTimeout:  120 * time.Second,
    }
    return srv
}

func handleWS(wsConn *websocket.Conn, tcpTarget string) {
    defer wsConn.Close()

    wsRemote := wsConn.RemoteAddr().String()
    connID := fmt.Sprintf("%s->%s", wsRemote, tcpTarget)

    if verbose {
        log.Printf("[CONN] New client connection from %s to target %s", wsRemote, tcpTarget)
    } else {
        log.Printf("[CONN] %s connected", wsRemote)
    }

    d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
    tcpConn, err := d.Dial("tcp", tcpTarget)
    if err != nil {
        log.Printf("[CONN] Failed to connect to target %s: %v", tcpTarget, err)
        _ = wsConn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "dial failed"), time.Now().Add(2*time.Second))
        return
    }
    defer tcpConn.Close()

    if verbose {
        log.Printf("[CONN] %s: TCP connection established to %s", connID, tcpTarget)
    }

    _ = tcpConn.(*net.TCPConn).SetKeepAlive(true)
    _ = tcpConn.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)

    // Keepalive for websocket
    wsConn.SetReadLimit(64 * 1024 * 1024)
    _ = wsConn.SetReadDeadline(time.Now().Add(120 * time.Second))
    wsConn.SetPongHandler(func(string) error {
        return wsConn.SetReadDeadline(time.Now().Add(120 * time.Second))
    })

    stop := make(chan struct{})
    var once sync.Once
    closeAll := func() {
        once.Do(func() {
            close(stop)
            if verbose {
                log.Printf("[CONN] %s: Connection closed", connID)
            }
        })
    }

    // ws -> tcp
    go func() {
        for {
            mt, data, err := wsConn.ReadMessage()
            if err != nil {
                if verbose {
                    log.Printf("[DATA] %s: WS read error: %v", connID, err)
                }
                break
            }
            if mt == websocket.PingMessage {
                if verbose {
                    log.Printf("[DATA] %s: Received ping, sending pong", connID)
                }
                _ = wsConn.WriteControl(websocket.PongMessage, nil, time.Now().Add(2*time.Second))
                continue
            }
            if len(data) > 0 {
                if verbose {
                    log.Printf("[DATA] %s: Reading WebSocket frame: opcode=0x%x, len=%d -> TCP", connID, mt, len(data))
                }
                if _, err := tcpConn.Write(data); err != nil {
                    if verbose {
                        log.Printf("[DATA] %s: TCP write error: %v", connID, err)
                    }
                    break
                }
            }
        }
        closeAll()
    }()

    // tcp -> ws
    go func() {
        buf := make([]byte, 32*1024)
        for {
            n, err := tcpConn.Read(buf)
            if n > 0 {
                if verbose {
                    log.Printf("[DATA] %s: TCP read %d bytes -> WebSocket", connID, n)
                }
                w, werr := wsConn.NextWriter(websocket.BinaryMessage)
                if werr != nil {
                    if verbose {
                        log.Printf("[DATA] %s: WS writer error: %v", connID, werr)
                    }
                    break
                }
                nw, _ := w.Write(buf[:n])
                _ = w.Close()
                if verbose {
                    // Calculate header length (WebSocket frame header is typically 2-14 bytes)
                    headerLen := 2
                    if n > 125 {
                        if n > 65535 {
                            headerLen = 10
                        } else {
                            headerLen = 4
                        }
                    }
                    log.Printf("[DATA] %s: Writing WebSocket frame: opcode=0x2, len=%d, header_len=%d", connID, nw, headerLen)
                }
            }
            if err != nil {
                if verbose && !errors.Is(err, io.EOF) {
                    log.Printf("[DATA] %s: TCP read error: %v", connID, err)
                }
                break
            }
        }
        closeAll()
    }()

    // ping ticker
    ticker := time.NewTicker(45 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            if verbose {
                log.Printf("[DATA] %s: Sending keepalive ping", connID)
            }
            _ = wsConn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
        case <-stop:
            return
        }
    }
}

func loadTLSConfig() (*tls.Config, error) {
    exe, _ := os.Executable()
    base := filepath.Dir(exe)
    cerDir := filepath.Join(base, "cer")

    // Try PEM combined FIRST (most common for combined cert+key)
    pem := filepath.Join(cerDir, "portforward.pem")
    if fileExists(pem) {
        cert, err := tls.LoadX509KeyPair(pem, pem)
        if err == nil {
            log.Printf("[TLS] Loaded pem: %s", pem)
            return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10}, nil
        }
        log.Printf("[TLS] Failed to load pem (%s): %v", pem, err)
    }

    // Try CRT/KEY pairs
    crt := filepath.Join(cerDir, "portforward.crt")
    key := filepath.Join(cerDir, "portforward.key")
    if fileExists(crt) && fileExists(key) {
        cert, err := tls.LoadX509KeyPair(crt, key)
        if err == nil {
            log.Printf("[TLS] Loaded crt/key: %s / %s", crt, key)
            return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10}, nil
        }
        log.Printf("[TLS] Failed to load crt/key (%s, %s): %v", crt, key, err)
    }

    // Try PKCS#12: .p12, .pfx, .der with empty password and common passwords
    for _, name := range []string{"portforward.p12", "portforward.pfx", "portforward.der"} {
        p := filepath.Join(cerDir, name)
        if !fileExists(p) {
            continue
        }
        b, err := os.ReadFile(p)
        if err != nil {
            continue
        }

        // Try multiple password options - empty password first
        passwords := []string{"", "changeit", "password", "123456"}
        var lastErr error
        for _, pwd := range passwords {
            priv, cert, err := pkcs12.Decode(b, pwd)
            if err == nil {
                tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv}
                log.Printf("[TLS] Loaded pkcs12: %s (password: %s)", p, func() string {
                    if pwd == "" {
                        return "empty"
                    }
                    return "***"
                }())
                return &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS10}, nil
            }
            lastErr = err
        }
        if lastErr != nil {
            log.Printf("[TLS] Failed to load pkcs12 (%s): %v", p, lastErr)
        }
    }
    return nil, fmt.Errorf("no valid TLS certificate found in cer/")
}

func fileExists(p string) bool {
    st, err := os.Stat(p)
    return err == nil && !st.IsDir()
}

func normalizeChildArgs(args []string) []string {
    out := make([]string, 0, len(args))
    replaceNext := false
    for _, a := range args {
        if replaceNext {
            out = append(out, "lcserver")
            replaceNext = false
            continue
        }
        out = append(out, a)
        if a == "-p" {
            replaceNext = true
        } else if strings.HasPrefix(a, "-p=") {
            out[len(out)-1] = "-p=lcserver"
        }
    }
    return out
}

func containsFlag(args []string, name string) bool {
    for _, a := range args {
        if a == name || strings.HasPrefix(a, name+"=") {
            return true
        }
    }
    return false
}
