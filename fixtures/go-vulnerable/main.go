package main

import (
	"fmt"
	"net/http"
)

// DK-GO-001: goroutine leak -- no context cancellation or timeout
func startBackgroundWorker() {
	go func() {
		// This goroutine runs forever with no way to stop it
		for {
			processItem()
		}
	}()
}

// DK-GO-002: unchecked errors
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Error return ignored (assigned to _)
	_ = r.ParseForm()

	// Error not checked within 5 lines
	name, err := r.Cookie("session")
	fmt.Println(name)
	fmt.Println(err)

	w.Write([]byte("ok"))
}

func processItem() {}

func main() {
	startBackgroundWorker()
	http.HandleFunc("/api/data", handleRequest)
	http.ListenAndServe(":8080", nil)
}
