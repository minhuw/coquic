package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	coquic "github.com/minhuw/coquic/bindings/go/coquic"
)

const ApplicationProtocol = "coquic-perf/1"

const (
	PerfMaxOutboundDatagramSize         = 1472
	PerfPMTUDMaxDatagramSize            = 0
	PerfMinUDPPayloadSize               = 1200
	PerfTransferConnectionReceiveWindow = 32 * 1024 * 1024
	PerfTransferStreamReceiveWindow     = 16 * 1024 * 1024
	PerfAckElicitingThreshold           = 2
	PerfCopaBulkAckElicitingThreshold   = 1
	PerfCopaInteractiveAckThreshold     = 8
	PerfServerInitialMaxBidiStreams     = 4096
)

type Role int

const (
	RoleServer Role = iota
	RoleClient
)

type Mode int

const (
	ModeBulk Mode = iota
	ModeRR
	ModeCRR
	ModePersistentRR
)

type Direction int

const (
	DirectionUpload Direction = iota
	DirectionDownload
)

type PerfConfig struct {
	Role                    Role
	Mode                    Mode
	Direction               Direction
	Host                    string
	Port                    uint16
	ServerName              string
	VerifyPeer              bool
	CertificateChainPath    string
	PrivateKeyPath          string
	JSONOut                 string
	RequestBytes            uint64
	ResponseBytes           uint64
	Streams                 uint64
	Connections             uint64
	RequestsInFlight        uint64
	Requests                *uint64
	TotalBytes              *uint64
	MaxOutboundDatagramSize uint64
	PMTUDMaxDatagramSize    uint64
	Warmup                  time.Duration
	Duration                time.Duration
	CongestionControl       coquic.CongestionControl
}

func DefaultPerfConfig() PerfConfig {
	return PerfConfig{
		Role:                    RoleServer,
		Mode:                    ModeBulk,
		Direction:               DirectionDownload,
		Host:                    "127.0.0.1",
		Port:                    4433,
		ServerName:              "localhost",
		VerifyPeer:              false,
		CertificateChainPath:    filepath.FromSlash("tests/fixtures/quic-server-cert.pem"),
		PrivateKeyPath:          filepath.FromSlash("tests/fixtures/quic-server-key.pem"),
		RequestBytes:            64,
		ResponseBytes:           64,
		Streams:                 1,
		Connections:             1,
		RequestsInFlight:        1,
		MaxOutboundDatagramSize: PerfMaxOutboundDatagramSize,
		PMTUDMaxDatagramSize:    PerfPMTUDMaxDatagramSize,
		Warmup:                  0,
		Duration:                5 * time.Second,
		CongestionControl:       coquic.CongestionControlNewReno,
	}
}

func ParseRuntimeArgs(args []string) (PerfConfig, error) {
	if len(args) == 0 {
		return PerfConfig{}, fmt.Errorf("%s", Usage())
	}

	config := DefaultPerfConfig()
	switch args[0] {
	case "server":
		config.Role = RoleServer
	case "client":
		config.Role = RoleClient
	default:
		return PerfConfig{}, fmt.Errorf("%s", Usage())
	}

	sawDirection := false
	for index := 1; index < len(args); {
		arg := args[index]
		index++
		if arg == "--verify-peer" {
			config.VerifyPeer = true
			continue
		}
		if index >= len(args) {
			return PerfConfig{}, fmt.Errorf("missing value for %s\n%s", arg, Usage())
		}
		value := args[index]
		index++

		switch arg {
		case "--host":
			config.Host = value
		case "--port":
			port, err := parseSize(value)
			if err != nil || port > uint64(^uint16(0)) {
				return PerfConfig{}, fmt.Errorf("%s", Usage())
			}
			config.Port = uint16(port)
		case "--io-backend":
			if value != "socket" {
				return PerfConfig{}, fmt.Errorf("coquic-go-perf currently supports --io-backend socket")
			}
		case "--congestion-control":
			cc, err := parseCongestionControl(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.CongestionControl = cc
		case "--mode":
			mode, err := parseMode(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.Mode = mode
		case "--direction":
			direction, err := parseDirection(value)
			if err != nil {
				return PerfConfig{}, err
			}
			sawDirection = true
			config.Direction = direction
		case "--request-bytes":
			value, err := parseSize(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.RequestBytes = value
		case "--response-bytes":
			value, err := parseSize(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.ResponseBytes = value
		case "--streams":
			value, err := parseSize(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.Streams = value
		case "--connections":
			value, err := parseSize(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.Connections = value
		case "--requests-in-flight":
			value, err := parseSize(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.RequestsInFlight = value
		case "--requests":
			value, err := parseSize(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.Requests = &value
		case "--total-bytes":
			value, err := parseSize(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.TotalBytes = &value
		case "--max-outbound-datagram-size":
			value, err := parseSize(value)
			if err != nil || value < PerfMinUDPPayloadSize {
				return PerfConfig{}, fmt.Errorf("%s", Usage())
			}
			config.MaxOutboundDatagramSize = value
		case "--pmtud-max-datagram-size":
			value, err := parseSize(value)
			if err != nil || (value != 0 && value < PerfMinUDPPayloadSize) {
				return PerfConfig{}, fmt.Errorf("%s", Usage())
			}
			config.PMTUDMaxDatagramSize = value
		case "--warmup":
			duration, err := parseDuration(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.Warmup = duration
		case "--duration":
			duration, err := parseDuration(value)
			if err != nil {
				return PerfConfig{}, err
			}
			config.Duration = duration
		case "--certificate-chain":
			config.CertificateChainPath = value
		case "--private-key":
			config.PrivateKeyPath = value
		case "--server-name":
			config.ServerName = value
		case "--json-out":
			config.JSONOut = value
		default:
			return PerfConfig{}, fmt.Errorf("%s", Usage())
		}
	}

	if config.Mode != ModeBulk && sawDirection {
		return PerfConfig{}, fmt.Errorf("%s", Usage())
	}
	if config.Streams == 0 || config.Connections == 0 || config.RequestsInFlight == 0 {
		return PerfConfig{}, fmt.Errorf("%s", Usage())
	}
	if config.Mode == ModePersistentRR && (config.RequestBytes == 0 || config.ResponseBytes == 0) {
		return PerfConfig{}, fmt.Errorf("%s", Usage())
	}

	return config, nil
}

func ClientEndpointConfig(config PerfConfig) coquic.EndpointConfig {
	endpoint := coquic.DefaultEndpointConfig()
	endpoint.Role = coquic.RoleClient
	endpoint.VerifyPeer = config.VerifyPeer
	endpoint.ApplicationProtocol = []byte(ApplicationProtocol)
	endpoint.MaxOutboundDatagramSize = int(config.MaxOutboundDatagramSize)
	endpoint.EmitSharedReceiveStreamData = true
	applyTransportDefaults(config, &endpoint.Transport)
	return endpoint
}

func ServerEndpointConfig(config PerfConfig) (coquic.EndpointConfig, error) {
	cert, err := readFile(config.CertificateChainPath)
	if err != nil {
		return coquic.EndpointConfig{}, err
	}
	key, err := readFile(config.PrivateKeyPath)
	if err != nil {
		return coquic.EndpointConfig{}, err
	}

	endpoint := coquic.DefaultEndpointConfig()
	endpoint.Role = coquic.RoleServer
	endpoint.VerifyPeer = config.VerifyPeer
	endpoint.ApplicationProtocol = []byte(ApplicationProtocol)
	endpoint.Identity = &coquic.TlsIdentity{
		CertificatePEM: cert,
		PrivateKeyPEM:  key,
	}
	endpoint.MaxOutboundDatagramSize = int(config.MaxOutboundDatagramSize)
	endpoint.EmitSharedReceiveStreamData = true
	applyTransportDefaults(config, &endpoint.Transport)
	if endpoint.Transport.InitialMaxStreamsBidi < PerfServerInitialMaxBidiStreams {
		endpoint.Transport.InitialMaxStreamsBidi = PerfServerInitialMaxBidiStreams
	}
	return endpoint, nil
}

func applyTransportDefaults(config PerfConfig, transport *coquic.TransportConfig) {
	transport.CongestionControl = config.CongestionControl
	transport.EnableHyStartPlusPlus = perfEnableHyStartPlusPlus(config)
	transport.SendStreamFairness = perfSendStreamFairness(config)
	transport.AckElicitingThreshold = perfAckElicitingThreshold(config)
	transport.PMTUDMaxDatagramSize = int(config.PMTUDMaxDatagramSize)
	transport.InitialMaxData = PerfTransferConnectionReceiveWindow
	transport.InitialMaxStreamDataBidiLocal = PerfTransferStreamReceiveWindow
	transport.InitialMaxStreamDataBidiRemote = PerfTransferStreamReceiveWindow
}

func perfAckElicitingThreshold(config PerfConfig) uint64 {
	if config.CongestionControl == coquic.CongestionControlCopa {
		if config.Mode == ModeBulk {
			return PerfCopaBulkAckElicitingThreshold
		}
		return PerfCopaInteractiveAckThreshold
	}
	return PerfAckElicitingThreshold
}

func perfEnableHyStartPlusPlus(config PerfConfig) bool {
	if config.Mode != ModeBulk {
		return true
	}
	return config.CongestionControl != coquic.CongestionControlNewReno &&
		config.CongestionControl != coquic.CongestionControlCubic
}

func perfSendStreamFairness(config PerfConfig) bool {
	return config.Mode != ModeBulk
}

func ModeName(mode Mode) string {
	switch mode {
	case ModeBulk:
		return "bulk"
	case ModeRR:
		return "rr"
	case ModeCRR:
		return "crr"
	case ModePersistentRR:
		return "persistent-rr"
	default:
		return "unknown"
	}
}

func DirectionName(direction Direction) string {
	switch direction {
	case DirectionUpload:
		return "upload"
	case DirectionDownload:
		return "download"
	default:
		return "unknown"
	}
}

func CongestionControlName(cc coquic.CongestionControl) string {
	switch cc {
	case coquic.CongestionControlNewReno:
		return "newreno"
	case coquic.CongestionControlCubic:
		return "cubic"
	case coquic.CongestionControlBBR:
		return "bbr"
	case coquic.CongestionControlCopa:
		return "copa"
	default:
		return "unknown"
	}
}

func Usage() string {
	return "usage: coquic-go-perf [server|client] [--host HOST] [--port PORT] " +
		"[--io-backend socket] [--congestion-control newreno|cubic|bbr|copa] " +
		"[--mode bulk|rr|crr|persistent-rr] [--direction upload|download] [--request-bytes N] " +
		"[--response-bytes N] [--streams N] [--connections N] " +
		"[--requests-in-flight N] [--requests N] [--total-bytes N] " +
		"[--warmup 250ms|2s] [--duration 250ms|2s] " +
		"[--max-outbound-datagram-size N] [--pmtud-max-datagram-size N] " +
		"[--certificate-chain PATH] [--private-key PATH] [--server-name NAME] " +
		"[--verify-peer] [--json-out PATH]"
}

func parseMode(value string) (Mode, error) {
	switch value {
	case "bulk":
		return ModeBulk, nil
	case "rr":
		return ModeRR, nil
	case "crr":
		return ModeCRR, nil
	case "persistent-rr":
		return ModePersistentRR, nil
	default:
		return 0, fmt.Errorf("%s", Usage())
	}
}

func parseDirection(value string) (Direction, error) {
	switch value {
	case "upload":
		return DirectionUpload, nil
	case "download":
		return DirectionDownload, nil
	default:
		return 0, fmt.Errorf("%s", Usage())
	}
}

func parseCongestionControl(value string) (coquic.CongestionControl, error) {
	switch value {
	case "newreno":
		return coquic.CongestionControlNewReno, nil
	case "cubic":
		return coquic.CongestionControlCubic, nil
	case "bbr":
		return coquic.CongestionControlBBR, nil
	case "copa":
		return coquic.CongestionControlCopa, nil
	default:
		return 0, fmt.Errorf("%s", Usage())
	}
}

func parseSize(value string) (uint64, error) {
	return strconv.ParseUint(value, 10, 64)
}

func parseDuration(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "ms") {
		ms, err := strconv.ParseUint(strings.TrimSuffix(value, "ms"), 10, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(ms) * time.Millisecond, nil
	}
	if strings.HasSuffix(value, "s") {
		seconds, err := strconv.ParseUint(strings.TrimSuffix(value, "s"), 10, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(seconds) * time.Second, nil
	}
	return 0, fmt.Errorf("duration must use ms or s suffix")
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return data, nil
}
