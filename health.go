package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"
)

// HealthChecker performs periodic health checks
type HealthChecker struct {
	url    string
	client *http.Client
}

// NewHealthChecker creates a new health checker instance
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		url: os.Getenv("RENDER_EXTERNAL_URL"),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// performHealthCheck performs a single health check
func (hc *HealthChecker) performHealthCheck() {
	if hc.url == "" {
		return
	}

	resp, err := hc.client.Get(hc.url)
	if err != nil {
		log.Printf("Health check failed: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("Health check successful: %d", resp.StatusCode)
	} else {
		log.Printf("Health check returned status: %d", resp.StatusCode)
	}
}

// Start begins the periodic health check routine
func (hc *HealthChecker) Start(ctx context.Context) {
	if hc.url == "" {
		log.Println("RENDER_EXTERNAL_URL not set, skipping health checks")
		return
	}

	log.Printf("Starting health checks for: %s", hc.url)

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.performHealthCheck()
		case <-ctx.Done():
			log.Println("Health checker stopped")
			return
		}
	}
}

// StartHealthChecker starts the health checker as a goroutine
func StartHealthChecker(ctx context.Context) {
	hc := NewHealthChecker()
	go hc.Start(ctx)
}
