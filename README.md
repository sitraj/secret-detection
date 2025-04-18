# GitHub Secret Detector

A high-performance Go application for detecting secrets and sensitive information in GitHub repositories.

## Features

- Fast and efficient secret detection using Go
- Scans branches, commits, and pull requests
- Detects various types of secrets (API keys, tokens, credentials, etc.)
- Generates JSON results or HTML reports
- User-friendly web interface
- Swagger API documentation
- Docker support for easy deployment

## Installation

### Prerequisites

- Go 1.21 or later
- Docker (optional)

### Local Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sitraj/secret-detection.git
   cd secret-detection
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Set up your GitHub token:
   ```bash
   export GITHUB_TOKEN=your_github_token
   ```

4. Build and run the application:
   ```bash
   go run cmd/detector/main.go
   ```

### Docker Installation

1. Build the Docker image:
   ```bash
   docker build -t secret-detector .
   ```

2. Run the container:
   ```bash
   docker run -p 8080:8080 -e GITHUB_TOKEN=your_github_token secret-detector
   ```

## Usage

### Web Interface

1. Open your browser and navigate to `http://localhost:8080`
2. Enter a GitHub repository name in the format `owner/repo`
3. Configure scan options:
   - Days to look back
   - Scan commits
   - Scan pull requests
4. Click "Get JSON Results" or "Get HTML Report"

### API Endpoints

#### Scan Repository
```http
POST /scan
Content-Type: application/json

{
    "repository": "owner/repo",
    "days": 30,
    "scan_commits": true,
    "scan_pulls": true
}
```

#### Generate HTML Report
```http
POST /report
Content-Type: application/json

{
    "repository": "owner/repo",
    "days": 30,
    "scan_commits": true,
    "scan_pulls": true
}
```

#### API Documentation
- Swagger UI: `http://localhost:8080/api-docs`
- Swagger YAML: `http://localhost:8080/swagger.yaml`

## Development

### Project Structure

```
.
├── cmd/
│   └── detector/
│       └── main.go
├── internal/
│   ├── api/
│   │   └── server.go
│   │   └── detector.go
│   └── patterns/
│       └── patterns.go
├── templates/
│   ├── index.html
│   └── swagger.html
├── Dockerfile
├── go.mod
├── go.sum
└── README.md
```

### Adding New Secret Patterns

To add new secret patterns, modify the `loadPatterns` function in `internal/patterns/patterns.go`.

## License

MIT 