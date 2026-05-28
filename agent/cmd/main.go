package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KabirMoulana/terrapulse/agent/internal/publisher"
	"github.com/KabirMoulana/terrapulse/agent/internal/scanner"
	"github.com/KabirMoulana/terrapulse/agent/internal/reconciler"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(log)

	cfg := loadConfig()

	// Cloud-native auth: IRSA on AWS, Workload Identity on GCP, Managed Identity on Azure
	// No static credentials anywhere in this codebase.
	cloudClient, err := scanner.NewCloudClient(cfg.CloudProvider, cfg.Region)
	if err != nil {
		log.Error("failed to create cloud client", "error", err)
		os.Exit(1)
	}

	pub, err := publisher.New(cfg.ControlPlaneURL, cfg.AgentID, cfg.AgentToken)
	if err != nil {
		log.Error("failed to create publisher", "error", err)
		os.Exit(1)
	}

	rec := reconciler.New(cloudClient, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Scan interval: configurable, default 5 minutes
	scanInterval := cfg.ScanInterval
	if scanInterval == 0 {
		scanInterval = 5 * time.Minute
	}

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	log.Info("terrapulse agent started",
		"cloud", cfg.CloudProvider,
		"region", cfg.Region,
		"account", cfg.AccountID,
		"interval", scanInterval,
	)

	// Run initial scan immediately
	runScan(ctx, cloudClient, pub, rec, cfg, log)

	for {
		select {
		case <-quit:
			log.Info("agent shutting down")
			return
		case <-ticker.C:
			runScan(ctx, cloudClient, pub, rec, cfg, log)
		}
	}
}

func runScan(
	ctx context.Context,
	cloud *scanner.CloudClient,
	pub *publisher.Publisher,
	rec *reconciler.Reconciler,
	cfg *Config,
	log *slog.Logger,
) {
	start := time.Now()
	log.Info("starting drift scan")

	resources, err := cloud.ScanAll(ctx)
	if err != nil {
		log.Error("scan failed", "error", err)
		return
	}

	log.Info("scan complete", "resources", len(resources), "duration", time.Since(start))

	// Publish resource snapshot to control plane
	if err := pub.PublishSnapshot(ctx, resources); err != nil {
		log.Error("failed to publish snapshot", "error", err)
	}

	// Check for remediations assigned to this agent
	remediations, err := pub.FetchRemediations(ctx, cfg.AgentID)
	if err != nil {
		log.Error("failed to fetch remediations", "error", err)
		return
	}

	for _, r := range remediations {
		if err := rec.Apply(ctx, r); err != nil {
			log.Error("remediation failed",
				"resource_id", r.ResourceID,
				"action", r.Action,
				"error", err,
			)
			pub.ReportRemediationResult(ctx, r.ID, "failure", err.Error())
		} else {
			log.Info("remediation applied",
				"resource_id", r.ResourceID,
				"action", r.Action,
			)
			pub.ReportRemediationResult(ctx, r.ID, "success", "")
		}
	}
}
