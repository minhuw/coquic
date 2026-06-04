package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/config"
)

type LatencySummary struct {
	MinUs uint64 `json:"min_us"`
	AvgUs uint64 `json:"avg_us"`
	P50Us uint64 `json:"p50_us"`
	P90Us uint64 `json:"p90_us"`
	P99Us uint64 `json:"p99_us"`
	MaxUs uint64 `json:"max_us"`
}

type ServerCounters struct {
	BytesSent         uint64 `json:"bytes_sent"`
	BytesReceived     uint64 `json:"bytes_received"`
	RequestsCompleted uint64 `json:"requests_completed"`
}

type RunSummary struct {
	SchemaVersion      uint32          `json:"schema_version"`
	Status             string          `json:"status"`
	Mode               string          `json:"mode"`
	Direction          string          `json:"direction"`
	Backend            string          `json:"backend"`
	CongestionControl  string          `json:"congestion_control"`
	RemoteHost         string          `json:"remote_host"`
	RemotePort         uint16          `json:"remote_port"`
	ALPN               string          `json:"alpn"`
	ElapsedMs          uint64          `json:"elapsed_ms"`
	WarmupMs           uint64          `json:"warmup_ms"`
	BytesSent          uint64          `json:"bytes_sent"`
	BytesReceived      uint64          `json:"bytes_received"`
	ServerCounters     ServerCounters  `json:"server_counters"`
	RequestsCompleted  uint64          `json:"requests_completed"`
	Streams            uint64          `json:"streams"`
	Connections        uint64          `json:"connections"`
	RequestsInFlight   uint64          `json:"requests_in_flight"`
	RequestBytes       uint64          `json:"request_bytes"`
	ResponseBytes      uint64          `json:"response_bytes"`
	ThroughputMiBPerS  float64         `json:"throughput_mib_per_s"`
	ThroughputGbitPerS float64         `json:"throughput_gbit_per_s"`
	RequestsPerS       float64         `json:"requests_per_s"`
	Latency            LatencySummary  `json:"latency"`
	LatencySamples     []time.Duration `json:"-"`
	FailureReason      string          `json:"failure_reason,omitempty"`
}

func NewRunSummary(cfg config.PerfConfig) RunSummary {
	return RunSummary{
		SchemaVersion:     1,
		Status:            "ok",
		Mode:              config.ModeName(cfg.Mode),
		Direction:         config.DirectionName(cfg.Direction),
		Backend:           "go",
		CongestionControl: config.CongestionControlName(cfg.CongestionControl),
		RemoteHost:        cfg.Host,
		RemotePort:        cfg.Port,
		ALPN:              config.ApplicationProtocol,
		WarmupMs:          DurationMillis(cfg.Warmup),
		Streams:           cfg.Streams,
		Connections:       cfg.Connections,
		RequestsInFlight:  cfg.RequestsInFlight,
		RequestBytes:      cfg.RequestBytes,
		ResponseBytes:     cfg.ResponseBytes,
	}
}

func ResetMeasurement(summary *RunSummary) {
	summary.ElapsedMs = 0
	summary.BytesSent = 0
	summary.BytesReceived = 0
	summary.ServerCounters = ServerCounters{}
	summary.RequestsCompleted = 0
	summary.Latency = LatencySummary{}
	summary.LatencySamples = nil
	summary.ThroughputMiBPerS = 0
	summary.ThroughputGbitPerS = 0
	summary.RequestsPerS = 0
}

func FinalizeSummary(summary *RunSummary) {
	summary.Latency = SummarizeLatencySamples(summary.LatencySamples)
	seconds := float64(max(summary.ElapsedMs, 1)) / 1000.0
	transferBytes := summary.BytesSent + summary.BytesReceived
	summary.ThroughputMiBPerS = float64(transferBytes) / (1024.0 * 1024.0) / seconds
	summary.ThroughputGbitPerS = (float64(transferBytes) * 8.0) / 1_000_000_000.0 / seconds
	summary.RequestsPerS = float64(summary.RequestsCompleted) / seconds
}

func EmitSummary(summary RunSummary, jsonOut string) error {
	fmt.Println(RenderSummary(summary))
	if jsonOut == "" {
		return nil
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonOut, payload, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", jsonOut, err)
	}
	return nil
}

func RenderSummary(summary RunSummary) string {
	return fmt.Sprintf(
		"status=%s mode=%s cc=%s direction=%s throughput_mib/s=%.3f throughput_gbit/s=%.3f requests/s=%.3f",
		summary.Status,
		summary.Mode,
		summary.CongestionControl,
		summary.Direction,
		summary.ThroughputMiBPerS,
		summary.ThroughputGbitPerS,
		summary.RequestsPerS,
	)
}

func SummarizeLatencySamples(samples []time.Duration) LatencySummary {
	if len(samples) == 0 {
		return LatencySummary{}
	}
	micros := make([]uint64, len(samples))
	var total uint64
	for index, sample := range samples {
		value := DurationMicros(sample)
		micros[index] = value
		total += value
	}
	sort.Slice(micros, func(left, right int) bool {
		return micros[left] < micros[right]
	})
	return LatencySummary{
		MinUs: micros[0],
		AvgUs: total / uint64(len(micros)),
		P50Us: percentileValue(micros, 50),
		P90Us: percentileValue(micros, 90),
		P99Us: percentileValue(micros, 99),
		MaxUs: micros[len(micros)-1],
	}
}

func DurationMillis(duration time.Duration) uint64 {
	return uint64(duration / time.Millisecond)
}

func DurationMicros(duration time.Duration) uint64 {
	return uint64(duration / time.Microsecond)
}

func percentileValue(sorted []uint64, percentile uint64) uint64 {
	rank := int(math.Ceil((float64(percentile) / 100.0) * float64(len(sorted))))
	if rank == 0 {
		return sorted[0]
	}
	index := min(rank-1, len(sorted)-1)
	return sorted[index]
}
