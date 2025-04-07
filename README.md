# GitHub Secret Detector

A powerful tool to detect secrets, tokens, and sensitive information in GitHub repositories. The tool scans branches, commits, and pull requests to identify potential security risks.

## Features

- **Comprehensive Secret Detection**: Detects various types of secrets:
  - GitHub Tokens (Classic, Fine-grained, User-to-server, Server-to-server, Refresh)
  - AWS Access Keys and Secret Keys
  - API Keys
  - Private Keys
  - Bearer Tokens
  - Basic Auth Credentials
  - JWT Tokens
  - Passwords
  - Database URLs
  - SSH Keys
  - Generic Secrets
  - Hex-encoded Secrets

- **Multiple Scan Targets**:
  - Repository Branches
  - Recent Commits
  - Pull Requests
  - Individual Files

- **Flexible Pattern Matching**:
  - Customizable regex patterns via YAML configuration
  - Support for various secret formats
  - Easy to extend and maintain

- **Security Features**:
  - Secret masking in output
  - Skip binary and large files
  - Configurable scan depth

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secret-detection
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up your GitHub token:
```bash
export GITHUB_TOKEN=your_github_token
```

## Usage

Run the script:
```bash
python github_secret_detector.py
```

When prompted, enter the GitHub repository in the format `owner/repo`.

### Example Output

```
Scanning branches...
[Found secrets will be displayed in a table format]
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ File          ┃ Secret Type ┃ Masked Secret  ┃ Context  ┃ Line Number┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━┩
│ config.yml    │ AWS Key     │ AKIA****XXXX   │ master   │ 15         │
└───────────────┴─────────────┴───────────────┴──────────┴────────────┘
```

## Configuration

### Secret Patterns

Secret patterns are defined in `secret_patterns.yaml`. Each secret type has:
- Description
- List of regex patterns
- Optional comments

Example pattern configuration:
```yaml
GitHub Token:
  description: GitHub authentication tokens in various formats
  patterns:
    # Classic tokens
    - ghp_[0-9a-zA-Z]{35,40}
    # Variable assignments
    - |-
      (?:[A-Za-z_][A-Za-z0-9_]*)\s*[=:](?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{35,40}
```

### Adding New Patterns

1. Open `secret_patterns.yaml`
2. Add a new section with:
   - Secret type name
   - Description
   - List of patterns
3. Use YAML block scalar (`|-`) for complex regex patterns

## Limitations

- Maximum file size: 1MB
- Scans recent commits (default: last 30 days)
- Requires GitHub API access
- Some files might be inaccessible due to repository permissions

## Security Considerations

- Store GitHub tokens securely
- Review detected secrets carefully
- Don't commit the script's output
- Use appropriate access permissions

## Dependencies

- PyGithub==2.1.1
- python-dotenv==1.0.0
- rich==13.7.0
- PyYAML==6.0.1

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[Add your license information here] 