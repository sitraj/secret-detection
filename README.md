# GitHub Secret Detector

A tool to scan GitHub repositories for potential secrets and sensitive information.

## Features

- Scan repository branches, commits, and pull requests for secrets
- Detect various types of secrets using pattern matching
- Generate JSON results or HTML reports
- User-friendly web interface
- Comprehensive test coverage

## Installation

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

## Usage

### Web Interface

1. Start the Flask application:
   ```
   python github_secret_detector.py
   ```

2. Open a web browser and navigate to `http://localhost:5000`

3. Enter a GitHub repository name in the format `owner/repo` (e.g., `octocat/Hello-World`)

4. Configure the scan options as needed

5. Click either "Get JSON Results" or "Get HTML Report" to start the scan

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

## Requirements

- Python 3.6+
- Flask
- PyGithub
- python-dotenv
- rich
- coverage (for test coverage)

## License

MIT 