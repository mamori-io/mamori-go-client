// Package setup holds the configuration shared by the examples.
package setup

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	mamori "mamori.io/mamori-go-client"
)

// Env returns the server, username and password from MAMORI_SERVER,
// MAMORI_USERNAME and MAMORI_PASSWORD, exiting if any is missing.
func Env() (server, username, password string) {
	server, username, password = os.Getenv("MAMORI_SERVER"), os.Getenv("MAMORI_USERNAME"), os.Getenv("MAMORI_PASSWORD")
	if server == "" || username == "" || password == "" {
		log.Fatal("set MAMORI_SERVER (e.g. https://mamori.example.com), MAMORI_USERNAME and MAMORI_PASSWORD")
	}
	return server, username, password
}

// Client returns a context that expires after MAMORI_TIMEOUT (default 60s)
// and a client for MAMORI_SERVER. Set MAMORI_DEBUG=1 to log each HTTP
// request and its connection phases to stderr.
func Client() (context.Context, context.CancelFunc, *mamori.Client) {
	server, _, _ := Env()
	timeout := 60 * time.Second
	if s := os.Getenv("MAMORI_TIMEOUT"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			log.Fatalf("invalid MAMORI_TIMEOUT %q: %v", s, err)
		}
		timeout = d
	}
	opts := []mamori.Option{mamori.WithInsecureSkipVerify()}
	if os.Getenv("MAMORI_DEBUG") != "" {
		h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
		opts = append(opts, mamori.WithLogger(slog.New(h)))
	}
	c, err := mamori.New(server, opts...)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "connecting to %s (timeout %s)\n", c.BaseURL(), timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ctx, cancel, c
}
