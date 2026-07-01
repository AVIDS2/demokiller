package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// DK-GO-001 hardened: goroutine with context cancellation
func startBackgroundWorker(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				fmt.Println("worker shutting down")
				return
			default:
				processItem()
			}
		}
	}()
}

// DK-GO-002 hardened: all errors checked on separate lines
func handleRequest(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "missing session", http.StatusUnauthorized)
		return
	}
	fmt.Println(cookie.Value)

	n, err := w.Write([]byte("ok"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
	}
	fmt.Println(n)
}

func processItem() {}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-quit
		cancel()
	}()

	startBackgroundWorker(ctx)

	srv := &http.Server{Addr: ":8080"}
	http.HandleFunc("/api/data", handleRequest)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	go func() {
		err := srv.ListenAndServe()
		if err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	err := srv.Shutdown(shutdownCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shutdown error: %v\n", err)
	}
}
