package main

import (
	"log"
	"os"

	"github.com/sitraj/secret-detection/internal/api"
)

func main() {
	// Get GitHub token from environment
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN environment variable is required")
	}

	// Create and start the server
	server := api.NewServer(token)
	if err := server.Start(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
} 