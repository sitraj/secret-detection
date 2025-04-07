# GitHub Secret Detector

A tool to scan GitHub repositories for potential secrets and sensitive information.

## Features

- Scan repository branches, commits, and pull requests for secrets
- Detect various types of secrets using pattern matching
- Generate JSON results or HTML reports
- User-friendly web interface
- Comprehensive test coverage
- Docker support for easy deployment
- Swagger API documentation

## Installation

### Option 1: Local Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/github-secret-detector.git
   cd github-secret-detector
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up your GitHub token:
   ```
   export GITHUB_TOKEN=your_github_token
   ```

### Option 2: Docker Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/github-secret-detector.git
   cd github-secret-detector
   ```

2. Create a `.env` file with your GitHub token and other configuration:
   ```
   GITHUB_TOKEN=your_github_token
   MAX_COMMITS=100
   SCAN_DEPTH_DAYS=30
   DEBUG_MODE=false
   SKIP_BINARY=true
   MAX_FILE_SIZE=1048576
   ```

3. Build and run the Docker container:
   ```
   docker-compose up -d
   ```

## Usage

### Web Interface

1. Start the Flask application:
   ```
   python github_secret_detector.py
   ```
   
   Or with Docker:
   ```
   docker-compose up -d
   ```

2. Open a web browser and navigate to `http://localhost:8080`

3. Enter a GitHub repository name in the format `owner/repo` (e.g., `octocat/Hello-World`)

4. Configure the scan options as needed

5. Click either "Get JSON Results" or "Get HTML Report" to start the scan

### API Documentation

The API documentation is available at `http://localhost:8080/api-docs`. This provides an interactive Swagger UI where you can:

- View detailed API documentation
- Test API endpoints directly from the browser
- See request and response schemas

### API Endpoints

#### Scan Repository

```
POST /scan
```

Request body:
```json
{
  "repository": "owner/repo",
  "days": 30,
  "scan_commits": true,
  "scan_pulls": true
}
```

Response:
```json
{
  "status": "success",
  "message": "Found X potential secrets",
  "secrets": [
    {
      "file": "path/to/file",
      "type": "Secret Type",
      "masked_secret": "masked_secret",
      "context": "context",
      "line_number": 42
    }
  ]
}
```

#### Generate HTML Report

```
POST /report
```

Request body:
```json
{
  "repository": "owner/repo",
  "days": 30,
  "scan_commits": true,
  "scan_pulls": true
}
```

Response: HTML report

## Running Tests

### Basic Test Run

To run the tests without coverage:

```
python run_tests.py
```

### With Coverage Report

To run the tests with a coverage report:

```
python run_tests.py --coverage
```

### With HTML Coverage Report

To run the tests with an HTML coverage report:

```
python run_tests.py --coverage --html
```

The HTML coverage report will be generated in the `htmlcov` directory.

## Docker Commands

### Build the Docker image

```
docker-compose build
```

### Start the container

```
docker-compose up -d
```

### Stop the container

```
docker-compose down
```

### View logs

```
docker-compose logs -f
```

## Requirements

- Python 3.6+
- Flask
- PyGithub
- python-dotenv
- rich
- coverage (for test coverage)
- Docker (optional)

## License

MIT 