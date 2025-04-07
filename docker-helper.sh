#!/bin/bash

# GitHub Secret Detector Docker Helper Script

# Function to display help
show_help() {
    echo "GitHub Secret Detector Docker Helper"
    echo ""
    echo "Usage: ./docker-helper.sh [command]"
    echo ""
    echo "Commands:"
    echo "  build       Build the Docker image"
    echo "  start       Start the Docker container"
    echo "  stop        Stop the Docker container"
    echo "  logs        View container logs"
    echo "  restart     Restart the Docker container"
    echo "  status      Check container status"
    echo "  help        Show this help message"
    echo ""
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker is not installed or not in PATH."
        echo "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi
}

# Build the Docker image
build_image() {
    echo "Building Docker image..."
    docker compose build
}

# Start the Docker container
start_container() {
    echo "Starting Docker container..."
    docker compose up -d
}

# Stop the Docker container
stop_container() {
    echo "Stopping Docker container..."
    docker compose down
}

# View container logs
view_logs() {
    echo "Viewing container logs..."
    docker compose logs -f
}

# Restart the Docker container
restart_container() {
    echo "Restarting Docker container..."
    docker compose restart
}

# Check container status
check_status() {
    echo "Checking container status..."
    docker compose ps
}

# Main script
check_docker

case "$1" in
    build)
        build_image
        ;;
    start)
        start_container
        ;;
    stop)
        stop_container
        ;;
    logs)
        view_logs
        ;;
    restart)
        restart_container
        ;;
    status)
        check_status
        ;;
    help|*)
        show_help
        ;;
esac 