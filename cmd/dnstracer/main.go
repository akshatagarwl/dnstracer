//go:build linux

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/akshatagarwl/dnstracer/internal/config"
	"github.com/akshatagarwl/dnstracer/internal/tracer"
)

// Build-time variables (injected via ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting DNS tracer", 
		"version", version,
		"build_time", buildTime,
		"arch", runtime.GOARCH,
		"os", runtime.GOOS,
		"message", "capturing DNS queries and responses")

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	t, err := tracer.New(cfg.UsePerfBuf)
	if err != nil {
		slog.Error("failed to create tracer", "error", err)
		os.Exit(1)
	}
	defer t.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		slog.Info("received signal, shutting down")
		t.Close()
		os.Exit(0)
	}()

	if err := t.Run(); err != nil {
		slog.Error("failed to run tracer", "error", err)
		os.Exit(1)
	}
}