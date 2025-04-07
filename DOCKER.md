# Docker Setup for GitHub Secret Detector

This document provides instructions for running the GitHub Secret Detector using Docker.

## Prerequisites

- Docker Desktop for Mac/Windows/Linux
- Git

## Quick Start

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/github-secret-detector.git
   cd github-secret-detector
   ```

2. Create a `.env` file with your GitHub token:
   ```
   GITHUB_TOKEN=your_github_token
   ```

3. Use the helper script to build and run the container:
   ```
   ./docker-helper.sh build
   ./docker-helper.sh start
   ```

4. Access the application at http://localhost:8080

## Docker Helper Script

The repository includes a helper script (`docker-helper.sh`) to simplify Docker operations:

- `./docker-helper.sh build` - Build the Docker image
- `./docker-helper.sh start` - Start the Docker container
- `./docker-helper.sh stop` - Stop the Docker container
- `./docker-helper.sh logs` - View container logs
- `./docker-helper.sh restart` - Restart the Docker container
- `./docker-helper.sh status` - Check container status
- `./docker-helper.sh help` - Show help message

## Manual Docker Commands

If you prefer to use Docker commands directly:

### Build the image
```
docker compose build
```

### Start the container
```
docker compose up -d
```

### Stop the container
```
docker compose down
```

### View logs
```
docker compose logs -f
```

## Environment Variables

The following environment variables can be configured in the `.env` file:

- `GITHUB_TOKEN` - Your GitHub Personal Access Token (required)
- `MAX_COMMITS` - Maximum number of commits to scan (default: 100)
- `SCAN_DEPTH_DAYS` - Number of days to look back in history (default: 30)
- `DEBUG_MODE` - Enable debug logging (default: false)
- `SKIP_BINARY` - Skip binary files during scan (default: true)
- `MAX_FILE_SIZE` - Maximum file size to scan in bytes (default: 1048576)

## Troubleshooting

### Container fails to start
Check the logs for errors:
```
./docker-helper.sh logs
```

### GitHub API rate limiting
If you encounter GitHub API rate limiting, ensure your token has the necessary permissions and is correctly set in the `.env` file.

### Port conflicts
If port 8080 is already in use, modify the `docker-compose.yml` file to use a different port. 