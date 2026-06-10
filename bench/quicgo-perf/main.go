package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	protocolVersion          = uint32(3)
	controlStreamID          = int64(0)
	applicationProtocol      = "coquic-perf/1"
	transferConnectionWindow = uint64(32 * 1024 * 1024)
	transferStreamWindow     = uint64(16 * 1024 * 1024)
	serverReadyTimeout       = 10 * time.Second
	defaultDrainTimeout      = 2 * time.Second
)

const (
	modeBulk         = "bulk"
	modeRR           = "rr"
	modeCRR          = "crr"
	modePersistentRR = "persistent-rr"
)

const (
	directionUpload   = "upload"
	directionDownload = "download"
)

const (
	messageSessionStart    = byte(1)
	messageSessionReady    = byte(2)
	messageSessionError    = byte(3)
	messageSessionComplete = byte(4)
)

type durationFlag time.Duration

func (d *durationFlag) String() string {
	return time.Duration(*d).String()
}

func (d *durationFlag) Set(value string) error {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = durationFlag(parsed)
	return nil
}

type config struct {
	host              string
	port              uint
	serverName        string
	verifyPeer        bool
	ioBackend         string
	congestionControl string
	certificateChain  string
	privateKey        string
	disablePMTUD      bool
	mode              string
	direction         string
	requestBytes      uint64
	responseBytes     uint64
	streams           uint64
	connections       uint64
	requestsInFlight  uint64
	requests          optionalUint64
	totalBytes        optionalUint64
	warmup            time.Duration
	duration          time.Duration
	jsonOut           string
}

type optionalUint64 struct {
	value uint64
	set   bool
}

func (o *optionalUint64) String() string {
	if !o.set {
		return "none"
	}
	return fmt.Sprintf("%d", o.value)
}

func (o *optionalUint64) Set(value string) error {
	parsed, err := parseUint64(value)
	if err != nil {
		return err
	}
	o.value = parsed
	o.set = true
	return nil
}

type runSummary struct {
	SchemaVersion           uint32         `json:"schema_version"`
	Status                  string         `json:"status"`
	Mode                    string         `json:"mode"`
	Direction               string         `json:"direction"`
	Backend                 string         `json:"backend"`
	CongestionControl       string         `json:"congestion_control"`
	RemoteHost              string         `json:"remote_host"`
	RemotePort              uint           `json:"remote_port"`
	ALPN                    string         `json:"alpn"`
	ElapsedMS               int64          `json:"elapsed_ms"`
	WarmupMS                int64          `json:"warmup_ms"`
	BytesSent               uint64         `json:"bytes_sent"`
	BytesReceived           uint64         `json:"bytes_received"`
	ServerCounters          serverCounters `json:"server_counters"`
	RequestsCompleted       uint64         `json:"requests_completed"`
	Streams                 uint64         `json:"streams"`
	Connections             uint64         `json:"connections"`
	RequestsInFlight        uint64         `json:"requests_in_flight"`
	RequestBytes            uint64         `json:"request_bytes"`
	ResponseBytes           uint64         `json:"response_bytes"`
	ThroughputMiBPerSecond  float64        `json:"throughput_mib_per_s"`
	ThroughputGbitPerSecond float64        `json:"throughput_gbit_per_s"`
	RequestsPerSecond       float64        `json:"requests_per_s"`
	Latency                 latencySummary `json:"latency"`
	FailureReason           string         `json:"failure_reason,omitempty"`
	SkippedSetupErrors      uint64         `json:"skipped_setup_errors,omitempty"`
}

type serverCounters struct {
	BytesSent         uint64 `json:"bytes_sent"`
	BytesReceived     uint64 `json:"bytes_received"`
	RequestsCompleted uint64 `json:"requests_completed"`
}

type latencySummary struct {
	MinUS uint64 `json:"min_us"`
	AvgUS uint64 `json:"avg_us"`
	P50US uint64 `json:"p50_us"`
	P90US uint64 `json:"p90_us"`
	P99US uint64 `json:"p99_us"`
	MaxUS uint64 `json:"max_us"`
}

type sessionStart struct {
	mode             string
	direction        string
	requestBytes     uint64
	responseBytes    uint64
	totalBytes       optionalUint64
	requests         optionalUint64
	warmup           time.Duration
	duration         time.Duration
	streams          uint64
	connections      uint64
	requestsInFlight uint64
}

type sessionComplete struct {
	bytesSent         uint64
	bytesReceived     uint64
	requestsCompleted uint64
}

type controlMessage struct {
	messageType byte
	ready       bool
	errorReason string
	start       sessionStart
	complete    sessionComplete
}

type measuredCounters struct {
	bytesSent         atomic.Uint64
	bytesReceived     atomic.Uint64
	requestsCompleted atomic.Uint64

	latencyMu sync.Mutex
	latencies []time.Duration

	skippedSetupErrors atomic.Uint64
}

type connectionState struct {
	conn    *quic.Conn
	control *quic.Stream
}

type clientDialer struct {
	transport *quic.Transport
	remote    *net.UDPAddr
}

type bulkStreamResult struct {
	counts   bool
	sent     uint64
	received uint64
	err      error
}

type rrStreamResult struct {
	connectionIndex uint64
	counts          bool
	latency         time.Duration
	received        uint64
	err             error
}

type persistentRRResult struct {
	bytesSent         uint64
	bytesReceived     uint64
	requestsCompleted uint64
	latencies         []time.Duration
	err               error
}

type serverSession struct {
	conn *quic.Conn

	control *quic.Stream
	start   sessionStart

	bytesSent         atomic.Uint64
	bytesReceived     atomic.Uint64
	requestsCompleted atomic.Uint64
	completeOnce      sync.Once
}

type persistentRequest struct {
	startedAt time.Time
	counts    bool
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "client" && os.Args[1] != "server") {
		fmt.Fprintln(os.Stderr, "usage: quicgo-perf [client|server] [options]")
		os.Exit(2)
	}

	cfg, err := parseArgs(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if os.Args[1] == "server" {
		if err := runServer(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	summary, err := runClient(cfg)
	if err != nil {
		summary.Status = "failed"
		summary.FailureReason = err.Error()
	}
	finalizeSummary(&summary)
	if writeErr := emitSummary(summary, cfg.jsonOut); writeErr != nil {
		fmt.Fprintln(os.Stderr, writeErr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		host:              "127.0.0.1",
		port:              4433,
		serverName:        "localhost",
		ioBackend:         "socket",
		congestionControl: "newreno",
		certificateChain:  "tests/fixtures/quic-server-cert.pem",
		privateKey:        "tests/fixtures/quic-server-key.pem",
		disablePMTUD:      true,
		mode:              modeBulk,
		direction:         directionDownload,
		requestBytes:      64,
		responseBytes:     64,
		streams:           1,
		connections:       1,
		requestsInFlight:  1,
		duration:          5 * time.Second,
	}
	fs := flag.NewFlagSet("quicgo-perf client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.host, "host", cfg.host, "")
	fs.UintVar(&cfg.port, "port", cfg.port, "")
	fs.StringVar(&cfg.serverName, "server-name", cfg.serverName, "")
	fs.BoolVar(&cfg.verifyPeer, "verify-peer", cfg.verifyPeer, "")
	fs.StringVar(&cfg.ioBackend, "io-backend", cfg.ioBackend, "")
	fs.StringVar(&cfg.congestionControl, "congestion-control", cfg.congestionControl, "")
	fs.StringVar(&cfg.certificateChain, "certificate-chain", cfg.certificateChain, "")
	fs.StringVar(&cfg.privateKey, "private-key", cfg.privateKey, "")
	fs.BoolVar(&cfg.disablePMTUD, "disable-pmtud", cfg.disablePMTUD, "")
	fs.StringVar(&cfg.mode, "mode", cfg.mode, "")
	fs.StringVar(&cfg.direction, "direction", cfg.direction, "")
	fs.Uint64Var(&cfg.requestBytes, "request-bytes", cfg.requestBytes, "")
	fs.Uint64Var(&cfg.responseBytes, "response-bytes", cfg.responseBytes, "")
	fs.Uint64Var(&cfg.streams, "streams", cfg.streams, "")
	fs.Uint64Var(&cfg.connections, "connections", cfg.connections, "")
	fs.Uint64Var(&cfg.requestsInFlight, "requests-in-flight", cfg.requestsInFlight, "")
	fs.Var(&cfg.requests, "requests", "")
	fs.Var(&cfg.totalBytes, "total-bytes", "")
	warmup := durationFlag(cfg.warmup)
	duration := durationFlag(cfg.duration)
	fs.Var(&warmup, "warmup", "")
	fs.Var(&duration, "duration", "")
	fs.StringVar(&cfg.jsonOut, "json-out", cfg.jsonOut, "")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	cfg.warmup = time.Duration(warmup)
	cfg.duration = time.Duration(duration)
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cfg.mode != modeBulk && cfg.mode != modeRR && cfg.mode != modeCRR && cfg.mode != modePersistentRR {
		return cfg, fmt.Errorf("unsupported mode: %s", cfg.mode)
	}
	if cfg.ioBackend != "socket" && cfg.ioBackend != "io_uring" {
		return cfg, fmt.Errorf("unsupported io-backend label: %s", cfg.ioBackend)
	}
	if cfg.congestionControl != "newreno" && cfg.congestionControl != "cubic" &&
		cfg.congestionControl != "bbr" && cfg.congestionControl != "copa" &&
		cfg.congestionControl != "default" {
		return cfg, fmt.Errorf("unsupported congestion-control label: %s", cfg.congestionControl)
	}
	if cfg.direction != directionUpload && cfg.direction != directionDownload {
		return cfg, fmt.Errorf("unsupported direction: %s", cfg.direction)
	}
	if cfg.streams == 0 || cfg.connections == 0 || cfg.requestsInFlight == 0 {
		return cfg, errors.New("streams, connections, and requests-in-flight must be greater than zero")
	}
	if cfg.mode == modePersistentRR && (cfg.requestBytes == 0 || cfg.responseBytes == 0) {
		return cfg, errors.New("persistent-rr requires nonzero request and response bytes")
	}
	if cfg.port > 65535 {
		return cfg, errors.New("port must fit in uint16")
	}
	return cfg, nil
}

func parseUint64(value string) (uint64, error) {
	var out uint64
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid unsigned integer: %s", value)
		}
		out = out*10 + uint64(ch-'0')
	}
	return out, nil
}

func runServer(cfg config) error {
	cert, err := tls.LoadX509KeyPair(cfg.certificateChain, cfg.privateKey)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	listener, err := quic.ListenAddrEarly(fmt.Sprintf("%s:%d", cfg.host, cfg.port), &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{applicationProtocol},
	}, &quic.Config{
		HandshakeIdleTimeout:           5 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     transferStreamWindow,
		MaxStreamReceiveWindow:         transferStreamWindow,
		InitialConnectionReceiveWindow: transferConnectionWindow,
		MaxConnectionReceiveWindow:     transferConnectionWindow,
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          -1,
		DisablePathMTUDiscovery:        cfg.disablePMTUD,
	})
	if err != nil {
		return fmt.Errorf("listen quic-go server: %w", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept quic-go connection: %w", err)
		}
		go handleServerConnection(conn)
	}
}

func handleServerConnection(conn *quic.Conn) {
	control, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(1, "control stream accept failed")
		return
	}
	if int64(control.StreamID()) != controlStreamID {
		_ = conn.CloseWithError(1, "unexpected control stream id")
		return
	}
	msg, err := readControlMessage(control)
	if err != nil || msg.messageType != messageSessionStart {
		_ = sendControlMessage(control, encodeSessionError("expected session_start"), true)
		_ = conn.CloseWithError(1, "invalid session_start")
		return
	}
	session := &serverSession{
		conn:    conn,
		control: control,
		start:   msg.start,
	}
	if err := sendControlMessage(control, encodeSessionReady(), false); err != nil {
		_ = conn.CloseWithError(1, "session_ready failed")
		return
	}
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleServerDataStream(session, stream)
	}
}

func handleServerDataStream(session *serverSession, stream *quic.Stream) {
	if session.start.mode == modePersistentRR {
		handlePersistentRRServerStream(session, stream)
		return
	}
	received, err := copyAndCount(io.Discard, stream)
	if err != nil {
		return
	}
	session.bytesReceived.Add(received)
	requestsCompleted := session.requestsCompleted.Add(1)

	var responseBytes uint64
	if session.start.mode == modeBulk && session.start.direction == directionDownload && session.start.totalBytes.set {
		streamIndex := requestsCompleted - 1
		perStream := session.start.totalBytes.value / session.start.streams
		remainder := session.start.totalBytes.value % session.start.streams
		responseBytes = perStream
		if streamIndex < remainder {
			responseBytes++
		}
	} else if session.start.mode == modeBulk && session.start.direction == directionDownload {
		responseBytes = session.start.responseBytes
	} else if session.start.mode == modeRR || session.start.mode == modeCRR {
		responseBytes = session.start.responseBytes
	}

	if responseBytes != 0 {
		sent, err := writeN(stream, responseBytes)
		session.bytesSent.Add(sent)
		if err != nil {
			return
		}
	}
	if err := stream.Close(); err != nil {
		return
	}
	if shouldSendSessionComplete(session, requestsCompleted) {
		session.completeOnce.Do(func() {
			_ = sendControlMessage(session.control, encodeSessionComplete(sessionComplete{
				bytesSent:         session.bytesSent.Load(),
				bytesReceived:     session.bytesReceived.Load(),
				requestsCompleted: session.requestsCompleted.Load(),
			}), true)
		})
	}
}

func handlePersistentRRServerStream(session *serverSession, stream *quic.Stream) {
	buf := make([]byte, 64*1024)
	var pending uint64
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			byteCount := uint64(n)
			session.bytesReceived.Add(byteCount)
			pending += byteCount
			for pending >= session.start.requestBytes {
				sent, writeErr := writeN(stream, session.start.responseBytes)
				session.bytesSent.Add(sent)
				if writeErr != nil {
					return
				}
				requestsCompleted := session.requestsCompleted.Add(1)
				pending -= session.start.requestBytes
				if shouldSendSessionComplete(session, requestsCompleted) {
					session.completeOnce.Do(func() {
						_ = sendControlMessage(session.control, encodeSessionComplete(sessionComplete{
							bytesSent:         session.bytesSent.Load(),
							bytesReceived:     session.bytesReceived.Load(),
							requestsCompleted: session.requestsCompleted.Load(),
						}), true)
					})
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func shouldSendSessionComplete(session *serverSession, requestsCompleted uint64) bool {
	if session.start.mode == modeBulk && session.start.totalBytes.set &&
		requestsCompleted >= session.start.streams {
		return true
	}
	if session.start.mode == modeBulk && session.start.direction == directionUpload &&
		session.start.totalBytes.set &&
		requestsCompleted >= session.start.streams {
		return true
	}
	return (session.start.mode == modeRR || session.start.mode == modePersistentRR) &&
		session.start.requests.set &&
		requestsCompleted >= session.start.requests.value
}

func sendControlMessage(stream *quic.Stream, data []byte, fin bool) error {
	if _, err := stream.Write(data); err != nil {
		return err
	}
	if !fin {
		return nil
	}
	return stream.Close()
}

func runClient(cfg config) (runSummary, error) {
	summary := newRunSummary(cfg)
	start := sessionStart{
		mode:             cfg.mode,
		direction:        cfg.direction,
		requestBytes:     cfg.requestBytes,
		responseBytes:    cfg.responseBytes,
		totalBytes:       cfg.totalBytes,
		requests:         cfg.requests,
		warmup:           cfg.warmup,
		duration:         cfg.duration,
		streams:          cfg.streams,
		connections:      cfg.connections,
		requestsInFlight: cfg.requestsInFlight,
	}

	dialer, err := newClientDialer(cfg)
	if err != nil {
		return summary, err
	}
	defer dialer.Close()

	var connections []connectionState
	if cfg.mode != modeCRR {
		connections, err = openConnections(context.Background(), dialer, cfg, start, rrConnectionTarget(cfg))
		if err != nil {
			return summary, err
		}
		defer closeConnections(connections)
	}

	counters := &measuredCounters{}
	var elapsed time.Duration
	runStart := time.Now()
	switch cfg.mode {
	case modeBulk:
		if !cfg.totalBytes.set {
			err = runTimedBulk(cfg, connections, counters)
			elapsed = cfg.duration
		} else {
			err = runFixedBulk(cfg, connections, counters)
			elapsed = time.Since(runStart)
		}
	case modeRR:
		err = runRR(cfg, connections, counters)
		if cfg.requests.set {
			elapsed = time.Since(runStart)
		} else {
			elapsed = cfg.duration
		}
	case modePersistentRR:
		err = runPersistentRR(cfg, connections, counters)
		if cfg.requests.set {
			elapsed = time.Since(runStart)
		} else {
			elapsed = cfg.duration
		}
	case modeCRR:
		err = runCRR(cfg, start, counters, dialer)
		if cfg.requests.set {
			elapsed = time.Since(runStart)
		} else {
			elapsed = cfg.duration
		}
	}
	if err != nil {
		return summary, err
	}
	summary.ElapsedMS = elapsed.Milliseconds()

	var complete sessionComplete
	if expectsSessionComplete(cfg) {
		complete, _ = readFirstComplete(connections)
	}
	summary.ServerCounters = serverCounters{
		BytesSent:         complete.bytesSent,
		BytesReceived:     complete.bytesReceived,
		RequestsCompleted: complete.requestsCompleted,
	}
	summary.BytesSent = counters.bytesSent.Load()
	summary.BytesReceived = counters.bytesReceived.Load()
	summary.RequestsCompleted = counters.requestsCompleted.Load()
	summary.SkippedSetupErrors = counters.skippedSetupErrors.Load()
	if cfg.mode == modeRR || cfg.mode == modePersistentRR || cfg.mode == modeCRR || !expectsSessionComplete(cfg) {
		summary.ServerCounters.BytesSent = summary.BytesReceived
		summary.ServerCounters.BytesReceived = summary.BytesSent
		summary.ServerCounters.RequestsCompleted = summary.RequestsCompleted
	}
	counters.latencyMu.Lock()
	summary.Latency = summarizeLatency(counters.latencies)
	counters.latencyMu.Unlock()
	return summary, nil
}

func newRunSummary(cfg config) runSummary {
	return runSummary{
		SchemaVersion:     1,
		Status:            "ok",
		Mode:              cfg.mode,
		Direction:         cfg.direction,
		Backend:           "quic-go",
		CongestionControl: cfg.congestionControl,
		RemoteHost:        cfg.host,
		RemotePort:        cfg.port,
		ALPN:              applicationProtocol,
		WarmupMS:          cfg.warmup.Milliseconds(),
		Streams:           cfg.streams,
		Connections:       cfg.connections,
		RequestsInFlight:  cfg.requestsInFlight,
		RequestBytes:      cfg.requestBytes,
		ResponseBytes:     cfg.responseBytes,
	}
}

func expectsSessionComplete(cfg config) bool {
	if cfg.mode == modeBulk && cfg.totalBytes.set {
		return true
	}
	return (cfg.mode == modeRR || cfg.mode == modePersistentRR) && cfg.requests.set
}

func newClientDialer(cfg config) (*clientDialer, error) {
	remote, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", cfg.host, cfg.port))
	if err != nil {
		return nil, fmt.Errorf("resolve quic-go server address: %w", err)
	}
	local := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if remote.IP != nil && remote.IP.To4() == nil {
		local.IP = net.IPv6zero
	}
	udpConn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("open quic-go client UDP socket: %w", err)
	}
	transport := &quic.Transport{Conn: udpConn}
	return &clientDialer{transport: transport, remote: remote}, nil
}

func (d *clientDialer) Close() {
	_ = d.transport.Close()
}

func openConnections(ctx context.Context, dialer *clientDialer, cfg config, start sessionStart, count uint64) ([]connectionState, error) {
	connections := make([]connectionState, 0, intCap(count))
	for i := uint64(0); i < count; i++ {
		connectionStart := start
		if (connectionStart.mode == modeRR || connectionStart.mode == modePersistentRR) && connectionStart.requests.set {
			connectionStart.requests.value = rrRequestLimitForConnection(cfg, i)
		}
		conn, err := dialer.dialConnection(ctx, cfg)
		if err != nil {
			closeConnections(connections)
			return nil, fmt.Errorf("dial quic-go connection: %w", err)
		}
		control, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			_ = conn.CloseWithError(0, "control stream open failed")
			closeConnections(connections)
			return nil, fmt.Errorf("open control stream: %w", err)
		}
		if int64(control.StreamID()) != controlStreamID {
			control.CancelWrite(0)
			_ = conn.CloseWithError(0, "unexpected control stream id")
			closeConnections(connections)
			return nil, fmt.Errorf("unexpected control stream id: %d", control.StreamID())
		}
		if _, err := control.Write(encodeSessionStart(connectionStart)); err != nil {
			_ = conn.CloseWithError(0, "session_start failed")
			closeConnections(connections)
			return nil, fmt.Errorf("write session_start: %w", err)
		}
		if err := control.Close(); err != nil {
			_ = conn.CloseWithError(0, "session_start failed")
			closeConnections(connections)
			return nil, fmt.Errorf("close control stream write side: %w", err)
		}
		if err := waitForReady(control); err != nil {
			_ = conn.CloseWithError(0, "session_ready failed")
			closeConnections(connections)
			return nil, err
		}
		connections = append(connections, connectionState{conn: conn, control: control})
	}
	return connections, nil
}

func (d *clientDialer) dialConnection(ctx context.Context, cfg config) (*quic.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return d.transport.Dial(dialCtx, d.remote, &tls.Config{
		ServerName:         cfg.serverName,
		InsecureSkipVerify: !cfg.verifyPeer, //nolint:gosec
		NextProtos:         []string{applicationProtocol},
	}, &quic.Config{
		HandshakeIdleTimeout:           5 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     transferStreamWindow,
		MaxStreamReceiveWindow:         transferStreamWindow,
		InitialConnectionReceiveWindow: transferConnectionWindow,
		MaxConnectionReceiveWindow:     transferConnectionWindow,
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          -1,
		DisablePathMTUDiscovery:        cfg.disablePMTUD,
	})
}

func closeConnections(connections []connectionState) {
	for _, c := range connections {
		_ = c.conn.CloseWithError(0, "done")
	}
}

func waitForReady(control *quic.Stream) error {
	if err := control.SetReadDeadline(time.Now().Add(serverReadyTimeout)); err != nil {
		return err
	}
	msg, err := readControlMessage(control)
	_ = control.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("read session_ready: %w", err)
	}
	if msg.messageType == messageSessionError {
		return fmt.Errorf("server session error: %s", msg.errorReason)
	}
	if msg.messageType != messageSessionReady || !msg.ready {
		return fmt.Errorf("unexpected control message type %d while waiting for ready", msg.messageType)
	}
	return nil
}

func runTimedBulk(cfg config, connections []connectionState, counters *measuredCounters) error {
	measureStart := time.Now().Add(cfg.warmup)
	measureDeadline := measureStart.Add(cfg.duration)
	resultCh := make(chan bulkStreamResult, intCap(cfg.streams*cfg.connections+64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var active atomic.Uint64
	var nextConnection atomic.Uint64
	openNext := func(c connectionState, counts bool) {
		active.Add(1)
		go func() {
			defer active.Add(^uint64(0))
			sent, received, err := runTimedBulkStream(ctx, c.conn, cfg)
			resultCh <- bulkStreamResult{counts: counts, sent: sent, received: received, err: err}
		}()
	}

	for _, c := range connections {
		for s := uint64(0); s < cfg.streams; s++ {
			openNext(c, false)
		}
	}

	timer := time.NewTimer(time.Until(measureStart))
	<-timer.C
	for time.Now().Before(measureDeadline) {
		result := <-resultCh
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			return result.err
		}
		if result.counts {
			counters.bytesSent.Add(result.sent)
			counters.bytesReceived.Add(result.received)
		}
		for active.Load() < cfg.streams*cfg.connections && time.Now().Before(measureDeadline) {
			index := nextConnection.Add(1) - 1
			openNext(connections[index%uint64(len(connections))], true)
		}
	}
	cancel()
	drainDeadline := time.Now().Add(defaultDrainTimeout)
	for active.Load() != 0 && time.Now().Before(drainDeadline) {
		result := <-resultCh
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			return result.err
		}
	}
	return nil
}

func runTimedBulkStream(ctx context.Context, conn *quic.Conn, cfg config) (uint64, uint64, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, 0, err
	}
	if cfg.direction == directionUpload {
		sent, err := writeN(stream, maxU64(cfg.requestBytes, cfg.responseBytes))
		if err != nil {
			return sent, 0, err
		}
		if err := stream.Close(); err != nil {
			return sent, 0, err
		}
		return sent, 0, nil
	}
	if _, err := stream.Write(nil); err != nil {
		return 0, 0, err
	}
	if err := stream.Close(); err != nil {
		return 0, 0, err
	}
	received, err := copyAndCount(io.Discard, stream)
	return 0, received, err
}

func runFixedBulk(cfg config, connections []connectionState, counters *measuredCounters) error {
	if cfg.totalBytes.set {
		perStream := cfg.totalBytes.value / cfg.streams
		remainder := cfg.totalBytes.value % cfg.streams
		var wg sync.WaitGroup
		errCh := make(chan error, intCap(cfg.streams))
		for i := uint64(0); i < cfg.streams; i++ {
			targetBytes := perStream
			if i < remainder {
				targetBytes++
			}
			conn := connections[i%uint64(len(connections))].conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				sent, received, err := runFixedBulkStream(conn, cfg.direction, targetBytes)
				counters.bytesSent.Add(sent)
				counters.bytesReceived.Add(received)
				if err != nil {
					errCh <- err
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("fixed bulk requires --total-bytes for quic-go client")
}

func runFixedBulkStream(conn *quic.Conn, direction string, targetBytes uint64) (uint64, uint64, error) {
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return 0, 0, err
	}
	if direction == directionUpload {
		sent, err := writeN(stream, targetBytes)
		if err != nil {
			return sent, 0, err
		}
		if err := stream.Close(); err != nil {
			return sent, 0, err
		}
		return sent, 0, nil
	}
	if err := stream.Close(); err != nil {
		return 0, 0, err
	}
	received, err := copyAndCount(io.Discard, stream)
	return 0, received, err
}

func runRR(cfg config, connections []connectionState, counters *measuredCounters) error {
	measureStart := time.Now().Add(cfg.warmup)
	measureDeadline := measureStart.Add(cfg.duration)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan rrStreamResult, intCap(cfg.requestsInFlight*uint64(len(connections))+64))
	active := uint64(0)
	activeByConnection := make([]uint64, len(connections))
	startedByConnection := make([]uint64, len(connections))
	started := uint64(0)
	openNext := func(index uint64, conn *quic.Conn, counts bool) {
		atomic.AddUint64(&active, 1)
		activeByConnection[index]++
		atomic.AddUint64(&started, 1)
		go func() {
			latency, received, err := runRequestResponseStream(ctx, conn, cfg.requestBytes)
			resultCh <- rrStreamResult{connectionIndex: index, counts: counts, latency: latency, received: received, err: err}
		}()
	}

	for index, c := range connections {
		for activeByConnection[index] < cfg.requestsInFlight &&
			canStartRRRequest(cfg, started, startedByConnection, uint64(index)) {
			openNext(uint64(index), c.conn, cfg.requests.set || time.Now().After(measureStart))
			startedByConnection[index]++
		}
	}
	for {
		if !cfg.requests.set && time.Now().After(measureDeadline) {
			break
		}
		if cfg.requests.set && atomic.LoadUint64(&started) >= cfg.requests.value && atomic.LoadUint64(&active) == 0 {
			break
		}
		result := <-resultCh
		atomic.AddUint64(&active, ^uint64(0))
		activeByConnection[result.connectionIndex]--
		if result.err != nil {
			return result.err
		}
		if result.counts && time.Now().After(measureStart) {
			counters.bytesSent.Add(cfg.requestBytes)
			counters.bytesReceived.Add(result.received)
			counters.requestsCompleted.Add(1)
			counters.latencyMu.Lock()
			counters.latencies = append(counters.latencies, result.latency)
			counters.latencyMu.Unlock()
		}
		for activeByConnection[result.connectionIndex] < cfg.requestsInFlight {
			if !canStartRRRequest(cfg, atomic.LoadUint64(&started), startedByConnection, result.connectionIndex) {
				break
			}
			if !cfg.requests.set && time.Now().After(measureDeadline) {
				break
			}
			c := connections[result.connectionIndex]
			openNext(result.connectionIndex, c.conn, cfg.requests.set || time.Now().After(measureStart))
			startedByConnection[result.connectionIndex]++
		}
	}
	cancel()
	return nil
}

func runPersistentRR(cfg config, connections []connectionState, counters *measuredCounters) error {
	measureStart := time.Now().Add(cfg.warmup)
	measureDeadline := measureStart.Add(cfg.duration)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan persistentRRResult, len(connections))
	var remaining uint64
	if cfg.requests.set {
		remaining = cfg.requests.value
	}
	for index, connection := range connections {
		limit := uint64(0)
		if cfg.requests.set {
			limit = rrRequestLimitForConnection(cfg, uint64(index))
		}
		go func(conn *quic.Conn, requestLimit uint64) {
			resultCh <- runPersistentRRConnection(ctx, cfg, conn, measureStart, measureDeadline, requestLimit)
		}(connection.conn, limit)
	}

	for range connections {
		result := <-resultCh
		if result.err != nil {
			return result.err
		}
		counters.bytesSent.Add(result.bytesSent)
		counters.bytesReceived.Add(result.bytesReceived)
		counters.requestsCompleted.Add(result.requestsCompleted)
		counters.latencyMu.Lock()
		counters.latencies = append(counters.latencies, result.latencies...)
		counters.latencyMu.Unlock()
		if cfg.requests.set {
			if result.requestsCompleted > remaining {
				remaining = 0
			} else {
				remaining -= result.requestsCompleted
			}
		}
	}
	return nil
}

func runPersistentRRConnection(
	ctx context.Context,
	cfg config,
	conn *quic.Conn,
	measureStart time.Time,
	measureDeadline time.Time,
	requestLimit uint64,
) persistentRRResult {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return persistentRRResult{err: err}
	}
	var result persistentRRResult
	outstanding := make([]persistentRequest, 0, cfg.requestsInFlight)
	started := uint64(0)
	var pendingRead uint64
	buf := make([]byte, 64*1024)

	canStart := func(now time.Time) bool {
		if cfg.requests.set {
			return started < requestLimit
		}
		return now.Before(measureDeadline)
	}
	sendOne := func(now time.Time) error {
		if _, err := writeN(stream, cfg.requestBytes); err != nil {
			return err
		}
		counts := cfg.requests.set || now.After(measureStart)
		outstanding = append(outstanding, persistentRequest{startedAt: now, counts: counts})
		started++
		if counts {
			result.bytesSent += cfg.requestBytes
		}
		return nil
	}

	for uint64(len(outstanding)) < cfg.requestsInFlight && canStart(time.Now()) {
		if err := sendOne(time.Now()); err != nil {
			return persistentRRResult{err: err}
		}
	}
	for {
		if len(outstanding) == 0 && (cfg.requests.set || time.Now().After(measureDeadline)) {
			break
		}
		n, err := stream.Read(buf)
		if n > 0 {
			now := time.Now()
			pendingRead += uint64(n)
			for pendingRead >= cfg.responseBytes && len(outstanding) > 0 {
				request := outstanding[0]
				copy(outstanding, outstanding[1:])
				outstanding = outstanding[:len(outstanding)-1]
				pendingRead -= cfg.responseBytes
				if request.counts && now.After(measureStart) {
					result.bytesReceived += cfg.responseBytes
					result.requestsCompleted++
					result.latencies = append(result.latencies, now.Sub(request.startedAt))
				}
				for uint64(len(outstanding)) < cfg.requestsInFlight && canStart(now) {
					if err := sendOne(now); err != nil {
						return persistentRRResult{err: err}
					}
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(outstanding) == 0 {
				break
			}
			return persistentRRResult{err: err}
		}
	}
	if err := stream.Close(); err != nil {
		return persistentRRResult{err: err}
	}
	return result
}

func rrConnectionTarget(cfg config) uint64 {
	if (cfg.mode == modeRR || cfg.mode == modePersistentRR) && cfg.requests.set && cfg.requests.value < cfg.connections {
		return cfg.requests.value
	}
	return cfg.connections
}

func rrRequestLimitForConnection(cfg config, connectionIndex uint64) uint64 {
	connections := rrConnectionTarget(cfg)
	base := cfg.requests.value / connections
	remainder := cfg.requests.value % connections
	if connectionIndex < remainder {
		return base + 1
	}
	return base
}

func canStartRRRequest(cfg config, started uint64, startedByConnection []uint64, connectionIndex uint64) bool {
	if !cfg.requests.set {
		return true
	}
	return started < cfg.requests.value &&
		startedByConnection[connectionIndex] < rrRequestLimitForConnection(cfg, connectionIndex)
}

func runCRR(cfg config, start sessionStart, counters *measuredCounters, dialer *clientDialer) error {
	measureStart := time.Now().Add(cfg.warmup)
	measureDeadline := measureStart.Add(cfg.duration)
	sem := make(chan struct{}, intCap(cfg.connections))
	resultCh := make(chan rrStreamResult, intCap(cfg.connections+64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var started atomic.Uint64
	var active atomic.Uint64
	startOne := func(counts bool) bool {
		if cfg.requests.set && started.Load() >= cfg.requests.value {
			return false
		}
		sem <- struct{}{}
		started.Add(1)
		active.Add(1)
		go func() {
			defer func() { <-sem }()
			connections, err := openConnections(ctx, dialer, cfg, start, 1)
			if err != nil {
				resultCh <- rrStreamResult{counts: counts, err: maybeSkipCRRSetupError(cfg, counters, counts, err)}
				return
			}
			conn := connections[0].conn
			latency, received, err := runRequestResponseStream(ctx, conn, cfg.requestBytes)
			closeConnections(connections)
			resultCh <- rrStreamResult{counts: counts, latency: latency, received: received, err: err}
		}()
		return true
	}

	for i := uint64(0); i < cfg.connections; i++ {
		if !startOne(cfg.requests.set || time.Now().After(measureStart)) {
			break
		}
	}
	for {
		if !cfg.requests.set && time.Now().After(measureDeadline) {
			break
		}
		result := <-resultCh
		active.Add(^uint64(0))
		if result.err != nil {
			return result.err
		}
		if result.counts && time.Now().After(measureStart) {
			counters.bytesSent.Add(cfg.requestBytes)
			counters.bytesReceived.Add(result.received)
			counters.requestsCompleted.Add(1)
			counters.latencyMu.Lock()
			counters.latencies = append(counters.latencies, result.latency)
			counters.latencyMu.Unlock()
		}
		if cfg.requests.set && started.Load() >= cfg.requests.value {
			if active.Load() == 0 {
				break
			}
			continue
		}
		if !cfg.requests.set && time.Now().After(measureDeadline) {
			continue
		}
		_ = startOne(cfg.requests.set || time.Now().After(measureStart))
	}
	cancel()
	return nil
}

func maybeSkipCRRSetupError(cfg config, counters *measuredCounters, counts bool, err error) error {
	if cfg.mode == modeCRR && !cfg.requests.set && isTransientCRRSetupError(err) {
		counters.skippedSetupErrors.Add(1)
		time.Sleep(2 * time.Millisecond)
		return nil
	}
	return err
}

func isTransientCRRSetupError(err error) bool {
	if isDeadlineExceeded(err) {
		return true
	}
	var transportErr *quic.TransportError
	return errors.As(err, &transportErr) && transportErr.ErrorCode == quic.ConnectionRefused
}

func isDeadlineExceeded(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func runRequestResponseStream(ctx context.Context, conn *quic.Conn, requestBytes uint64) (time.Duration, uint64, error) {
	start := time.Now()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, 0, err
	}
	if _, err := writeN(stream, requestBytes); err != nil {
		return 0, 0, err
	}
	if err := stream.Close(); err != nil {
		return 0, 0, err
	}
	received, err := copyAndCount(io.Discard, stream)
	if err != nil {
		return 0, received, err
	}
	return time.Since(start), received, nil
}

func readFirstComplete(connections []connectionState) (sessionComplete, error) {
	for _, c := range connections {
		if err := c.control.SetReadDeadline(time.Now().Add(defaultDrainTimeout)); err != nil {
			continue
		}
		msg, err := readControlMessage(c.control)
		_ = c.control.SetReadDeadline(time.Time{})
		if err != nil {
			continue
		}
		if msg.messageType == messageSessionComplete {
			return msg.complete, nil
		}
	}
	return sessionComplete{}, errors.New("no session_complete received")
}

func readControlMessage(r io.Reader) (controlMessage, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return controlMessage{}, err
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[1:]))
	if _, err := io.ReadFull(r, payload); err != nil {
		return controlMessage{}, err
	}
	msg := controlMessage{messageType: header[0]}
	switch header[0] {
	case messageSessionStart:
		if len(payload) != 79 {
			return msg, errors.New("malformed session_start")
		}
		version := binary.BigEndian.Uint32(payload[0:4])
		if version != protocolVersion {
			return msg, fmt.Errorf("unsupported protocol version: %d", version)
		}
		flags := payload[22]
		totalBytes := optionalUint64{
			value: binary.BigEndian.Uint64(payload[23:31]),
			set:   flags&0x01 != 0,
		}
		requests := optionalUint64{
			value: binary.BigEndian.Uint64(payload[31:39]),
			set:   flags&0x02 != 0,
		}
		msg.start = sessionStart{
			mode:             modeFromCode(payload[4]),
			direction:        directionFromCode(payload[5]),
			requestBytes:     binary.BigEndian.Uint64(payload[6:14]),
			responseBytes:    binary.BigEndian.Uint64(payload[14:22]),
			totalBytes:       totalBytes,
			requests:         requests,
			warmup:           time.Duration(binary.BigEndian.Uint64(payload[39:47])) * time.Microsecond,
			duration:         time.Duration(binary.BigEndian.Uint64(payload[47:55])) * time.Microsecond,
			streams:          binary.BigEndian.Uint64(payload[55:63]),
			connections:      binary.BigEndian.Uint64(payload[63:71]),
			requestsInFlight: binary.BigEndian.Uint64(payload[71:79]),
		}
		if msg.start.mode != modeBulk && msg.start.mode != modeRR && msg.start.mode != modeCRR && msg.start.mode != modePersistentRR {
			return msg, errors.New("malformed session_start mode")
		}
		if msg.start.direction != directionUpload && msg.start.direction != directionDownload {
			return msg, errors.New("malformed session_start direction")
		}
		if msg.start.streams == 0 || msg.start.connections == 0 || msg.start.requestsInFlight == 0 {
			return msg, errors.New("malformed session_start counts")
		}
	case messageSessionReady:
		if len(payload) != 4 {
			return msg, errors.New("malformed session_ready")
		}
		msg.ready = binary.BigEndian.Uint32(payload) == protocolVersion
	case messageSessionError:
		if len(payload) < 4 {
			return msg, errors.New("malformed session_error")
		}
		n := binary.BigEndian.Uint32(payload)
		if len(payload[4:]) != int(n) {
			return msg, errors.New("malformed session_error length")
		}
		msg.errorReason = string(payload[4:])
	case messageSessionComplete:
		if len(payload) != 24 {
			return msg, errors.New("malformed session_complete")
		}
		msg.complete = sessionComplete{
			bytesSent:         binary.BigEndian.Uint64(payload[0:8]),
			bytesReceived:     binary.BigEndian.Uint64(payload[8:16]),
			requestsCompleted: binary.BigEndian.Uint64(payload[16:24]),
		}
	default:
		return msg, fmt.Errorf("unknown control message type %d", header[0])
	}
	return msg, nil
}

func encodeSessionStart(start sessionStart) []byte {
	payload := make([]byte, 0, 80)
	payload = appendU32(payload, protocolVersion)
	payload = append(payload, modeCode(start.mode), directionCode(start.direction))
	payload = appendU64(payload, start.requestBytes)
	payload = appendU64(payload, start.responseBytes)
	flags := byte(0)
	if start.totalBytes.set {
		flags |= 0x01
	}
	if start.requests.set {
		flags |= 0x02
	}
	payload = append(payload, flags)
	payload = appendU64(payload, start.totalBytes.value)
	payload = appendU64(payload, start.requests.value)
	payload = appendU64(payload, uint64(start.warmup.Microseconds()))
	payload = appendU64(payload, uint64(start.duration.Microseconds()))
	payload = appendU64(payload, start.streams)
	payload = appendU64(payload, start.connections)
	payload = appendU64(payload, start.requestsInFlight)

	out := []byte{messageSessionStart, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	out = append(out, payload...)
	return out
}

func encodeSessionReady() []byte {
	payload := make([]byte, 0, 4)
	payload = appendU32(payload, protocolVersion)
	out := []byte{messageSessionReady, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	out = append(out, payload...)
	return out
}

func encodeSessionError(reason string) []byte {
	payload := make([]byte, 0, 4+len(reason))
	payload = appendU32(payload, uint32(len(reason)))
	payload = append(payload, []byte(reason)...)
	out := []byte{messageSessionError, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	out = append(out, payload...)
	return out
}

func encodeSessionComplete(complete sessionComplete) []byte {
	payload := make([]byte, 0, 24)
	payload = appendU64(payload, complete.bytesSent)
	payload = appendU64(payload, complete.bytesReceived)
	payload = appendU64(payload, complete.requestsCompleted)
	out := []byte{messageSessionComplete, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	out = append(out, payload...)
	return out
}

func modeCode(mode string) byte {
	switch mode {
	case modeRR:
		return 1
	case modeCRR:
		return 2
	case modePersistentRR:
		return 3
	default:
		return 0
	}
}

func directionCode(direction string) byte {
	if direction == directionDownload {
		return 1
	}
	return 0
}

func modeFromCode(value byte) string {
	switch value {
	case 0:
		return modeBulk
	case 1:
		return modeRR
	case 2:
		return modeCRR
	case 3:
		return modePersistentRR
	default:
		return "unknown"
	}
}

func directionFromCode(value byte) string {
	switch value {
	case 0:
		return directionUpload
	case 1:
		return directionDownload
	default:
		return "unknown"
	}
}

func appendU32(out []byte, value uint32) []byte {
	return binary.BigEndian.AppendUint32(out, value)
}

func appendU64(out []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(out, value)
}

func writeN(w io.Writer, n uint64) (uint64, error) {
	buf := make([]byte, 32*1024)
	for i := range buf {
		buf[i] = 0x5a
	}
	var sent uint64
	for sent < n {
		chunk := uint64(len(buf))
		if remaining := n - sent; remaining < chunk {
			chunk = remaining
		}
		written, err := w.Write(buf[:int(chunk)])
		sent += uint64(written)
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

func copyAndCount(dst io.Writer, src io.Reader) (uint64, error) {
	buf := make([]byte, 64*1024)
	var total uint64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			total += uint64(n)
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return total, writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func finalizeSummary(summary *runSummary) {
	if summary.ElapsedMS == 0 {
		summary.ElapsedMS = int64(summary.WarmupMS)
	}
	seconds := math.Max(float64(summary.ElapsedMS)/1000.0, 0.001)
	totalBytes := summary.BytesSent + summary.BytesReceived
	summary.ThroughputMiBPerSecond = float64(totalBytes) / (1024.0 * 1024.0) / seconds
	summary.ThroughputGbitPerSecond = float64(totalBytes*8) / 1_000_000_000.0 / seconds
	summary.RequestsPerSecond = float64(summary.RequestsCompleted) / seconds
}

func summarizeLatency(samples []time.Duration) latencySummary {
	if len(samples) == 0 {
		return latencySummary{}
	}
	micros := make([]uint64, 0, len(samples))
	var total uint64
	for _, sample := range samples {
		us := uint64(sample.Microseconds())
		micros = append(micros, us)
		total += us
	}
	sort.Slice(micros, func(i, j int) bool { return micros[i] < micros[j] })
	return latencySummary{
		MinUS: micros[0],
		AvgUS: total / uint64(len(micros)),
		P50US: percentile(micros, 50),
		P90US: percentile(micros, 90),
		P99US: percentile(micros, 99),
		MaxUS: micros[len(micros)-1],
	}
}

func percentile(sorted []uint64, pct float64) uint64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil((pct / 100.0) * float64(len(sorted))))
	if rank <= 0 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func emitSummary(summary runSummary, jsonOut string) error {
	text := fmt.Sprintf("status=%s mode=%s cc=%s direction=%s throughput_mib/s=%.3f throughput_gbit/s=%.3f requests/s=%.3f",
		summary.Status, summary.Mode, summary.CongestionControl, summary.Direction,
		summary.ThroughputMiBPerSecond, summary.ThroughputGbitPerSecond, summary.RequestsPerSecond)
	fmt.Println(text)
	if jsonOut == "" {
		return nil
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(jsonOut, encoded, 0o644)
}

func intCap(value uint64) int {
	if value > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(value)
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
