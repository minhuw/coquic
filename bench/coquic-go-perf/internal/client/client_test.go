package client

import (
	"testing"
	"time"

	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/config"
	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/metrics"
	coquic "github.com/minhuw/coquic/bindings/go/coquic"
)

func TestTimedPersistentRRDrainSchedulesDeadline(t *testing.T) {
	cfg := config.DefaultPerfConfig()
	cfg.Role = config.RoleClient
	cfg.Mode = config.ModePersistentRR
	cfg.Duration = 45 * time.Second

	client := &Client{
		config:             cfg,
		connections:        map[coquic.ConnectionHandle]*connectionState{},
		closingConnections: map[coquic.ConnectionHandle]bool{},
		phase:              phaseMeasure,
		benchmarkStartedAt: timePtr(1_000),
		measureStartedAt:   1_000,
		measureDeadline:    2_000,
		summary:            metrics.NewRunSummary(cfg),
	}

	if err := client.enterDrainPhase(2_000); err != nil {
		t.Fatal(err)
	}

	if client.drainDeadline == nil {
		t.Fatal("expected timed persistent-rr drain deadline")
	}
	wantDeadline := coquic.TimeUs(2_000 + durationUs(drainTimeout))
	if *client.drainDeadline != wantDeadline {
		t.Fatalf("drain deadline = %d, want %d", *client.drainDeadline, wantDeadline)
	}
	wakeup, ok := client.benchmarkNextWakeup()
	if !ok || wakeup != wantDeadline {
		t.Fatalf("benchmark wakeup = (%d, %v), want (%d, true)", wakeup, ok, wantDeadline)
	}
}

func TestTimedPersistentRRDrainDeadlineForcesCloseWithPendingResponses(t *testing.T) {
	cfg := config.DefaultPerfConfig()
	cfg.Role = config.RoleClient
	cfg.Mode = config.ModePersistentRR

	client := &Client{
		config: cfg,
		connections: map[coquic.ConnectionHandle]*connectionState{
			1: {
				persistentFinSent: true,
				persistentRequests: []outstandingRequest{
					{startedAt: 1_000, countsTowardMeasurement: true},
				},
			},
		},
		closingConnections: map[coquic.ConnectionHandle]bool{},
		phase:              phaseDrain,
		drainDeadline:      timePtr(4_000),
	}

	commands, err := client.forceCloseTimedDrainCommands(3_999)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 0 {
		t.Fatalf("commands before deadline = %d, want 0", len(commands))
	}
	if client.connections[1].closeRequested {
		t.Fatal("persistent-rr connection closed before drain deadline")
	}

	commands, err = client.forceCloseTimedDrainCommands(4_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 {
		t.Fatalf("commands at deadline = %d, want 1", len(commands))
	}
	if commands[0].kind != commandClose {
		t.Fatalf("command kind = %v, want commandClose", commands[0].kind)
	}
	if !client.connections[1].closeRequested {
		t.Fatal("expected persistent-rr connection close to be requested")
	}
	if !client.closingConnections[1] {
		t.Fatal("expected persistent-rr connection to enter closing set")
	}
}
