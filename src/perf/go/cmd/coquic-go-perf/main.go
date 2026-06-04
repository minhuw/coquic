package main

import (
	"fmt"
	"os"

	"github.com/minhuw/coquic/src/perf/go/internal/client"
	"github.com/minhuw/coquic/src/perf/go/internal/config"
	"github.com/minhuw/coquic/src/perf/go/internal/metrics"
	"github.com/minhuw/coquic/src/perf/go/internal/server"
)

func main() {
	cfg, err := config.ParseRuntimeArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if cfg.Role == config.RoleServer {
		if _, err := server.Run(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	summary := metrics.NewRunSummary(cfg)
	done, err := client.Run(cfg)
	if err != nil {
		summary.Status = "failed"
		summary.FailureReason = err.Error()
	} else {
		summary = done
	}
	metrics.FinalizeSummary(&summary)
	if err := metrics.EmitSummary(summary, cfg.JSONOut); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if summary.Status != "ok" {
		os.Exit(1)
	}
}
