#!/usr/bin/env python3

import os
import re
from datetime import datetime, timedelta
from typing import List, Dict, Set
from github import Github
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from pattern_loader import PatternLoader
from flask import Flask, request, jsonify, render_template_string, render_template
from flask_cors import CORS

# Load environment variables
load_dotenv()

# Initialize Rich console
console = Console()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# HTML template for the report
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Secret Detection Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1, h2 {
            color: #2c3e50;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .secret-card {
            background-color: white;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .secret-type {
            font-weight: bold;
            color: #e74c3c;
        }
        .file-path {
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 2px 5px;
            border-radius: 3px;
        }
        .line-number {
            background-color: #e74c3c;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
        }
        .context {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .no-secrets {
            background-color: #2ecc71;
            color: white;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            font-size: 1.2em;
        }
        .filter-controls {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-controls select, .filter-controls input {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .filter-controls button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
        }
        .filter-controls button:hover {
            background-color: #2980b9;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.8em;
            text-align: right;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>GitHub Secret Detection Report</h1>
        <p>Repository: {{ repo_name }}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>{{ message }}</p>
        <p>Total secrets found: {{ secrets|length }}</p>
    </div>
    
    {% if secrets %}
    <div class="filter-controls">
        <select id="typeFilter">
            <option value="">All Secret Types</option>
            {% for type in secret_types %}
            <option value="{{ type }}">{{ type }}</option>
            {% endfor %}
        </select>
        <input type="text" id="fileFilter" placeholder="Filter by file path">
        <button onclick="applyFilters()">Apply Filters</button>
    </div>
    
    <div id="secrets-container">
        {% for secret in secrets %}
        <div class="secret-card" data-type="{{ secret.type }}" data-file="{{ secret.file }}">
            <div class="secret-type">{{ secret.type }}</div>
            <div class="file-path">{{ secret.file }} <span class="line-number">Line {{ secret.line_number }}</span></div>
            <div class="masked-secret">{{ secret.masked_secret }}</div>
            <div class="context">Context: {{ secret.context }}</div>
        </div>
        {% endfor %}
    </div>
    {% else %}
    <div class="no-secrets">
        <h2>No Secrets Found</h2>
        <p>Great job! No potential secrets were detected in this repository.</p>
    </div>
    {% endif %}
    
    <div class="timestamp">
        Report generated on {{ timestamp }}
    </div>
    
    <script>
        function applyFilters() {
            const typeFilter = document.getElementById('typeFilter').value.toLowerCase();
            const fileFilter = document.getElementById('fileFilter').value.toLowerCase();
            const cards = document.querySelectorAll('.secret-card');
            
            cards.forEach(card => {
                const type = card.getAttribute('data-type').toLowerCase();
                const file = card.getAttribute('data-file').toLowerCase();
                
                const typeMatch = !typeFilter || type.includes(typeFilter);
                const fileMatch = !fileFilter || file.includes(fileFilter);
                
                if (typeMatch && fileMatch) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
"""

class GitHubSecretDetector:
    def __init__(self, token: str):
        self.github = Github(token)
        self.found_secrets: Dict[str, List[Dict]] = {}
        self.scanned_files: Set[str] = set()
        self.debug_mode = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
        self.pattern_loader = PatternLoader()
        self.repo_name = ""

    def set_repo_name(self, repo_name: str) -> None:
        """Set the repository name for reporting purposes."""
        self.repo_name = repo_name

    def scan_branch(self, repo, branch_name: str) -> None:
        """Scan a specific branch for secrets."""
        try:
            console.print(f"[blue]Scanning branch: {branch_name}[/blue]")
            branch = repo.get_branch(branch_name)
            
            # Debug: Print branch details
            if self.debug_mode:
                console.print(f"[cyan]Branch details: {branch.name} (SHA: {branch.commit.sha})[/cyan]")
            
            # Try to get contents with explicit path
            try:
                contents = repo.get_contents("", ref=branch_name)
                if self.debug_mode:
                    console.print(f"[cyan]Found {len(contents)} items in root directory[/cyan]")
                self._scan_contents(repo, contents, branch_name)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get contents for branch {branch_name}: {str(e)}[/yellow]")
                
                # Try alternative approach - get tree
                try:
                    tree = repo.get_git_tree(branch.commit.sha, recursive=True)
                    if self.debug_mode:
                        console.print(f"[cyan]Found {len(tree.tree)} items in tree[/cyan]")
                    
                    for item in tree.tree:
                        if item.type == "blob":  # Only process files, not directories
                            try:
                                content = repo.get_contents(item.path, ref=branch_name)
                                if content.size <= 1024 * 1024:  # Skip files larger than 1MB
                                    file_content = content.decoded_content.decode('utf-8', errors='ignore')
                                    self._check_content_for_secrets(file_content, item.path, branch_name)
                                else:
                                    console.print(f"[yellow]Skipping large file: {item.path}[/yellow]")
                            except Exception as file_error:
                                console.print(f"[yellow]Warning: Could not read {item.path}: {str(file_error)}[/yellow]")
                except Exception as tree_error:
                    console.print(f"[red]Error getting tree for branch {branch_name}: {str(tree_error)}[/red]")
        except Exception as e:
            console.print(f"[red]Error scanning branch {branch_name}: {str(e)}[/red]")

    def scan_commits(self, repo, days_back: int = 30) -> None:
        """Scan recent commits for secrets."""
        since_date = datetime.now() - timedelta(days=days_back)
        try:
            commits = repo.get_commits(since=since_date)
            for commit in commits:
                console.print(f"[blue]Scanning commit: {commit.sha[:8]}[/blue]")
                self._scan_commit(repo, commit)
        except Exception as e:
            console.print(f"[red]Error scanning commits: {str(e)}[/red]")

    def scan_pull_requests(self, repo, days_back: int = 30) -> None:
        """Scan recent pull requests for secrets."""
        since_date = datetime.now() - timedelta(days=days_back)
        try:
            pulls = repo.get_pulls(state='all')
            for pull in pulls:
                if pull.created_at > since_date:
                    console.print(f"[blue]Scanning PR #{pull.number}[/blue]")
                    self._scan_pull_request(repo, pull)
        except Exception as e:
            console.print(f"[red]Error scanning pull requests: {str(e)}[/red]")

    def _scan_contents(self, repo, contents, branch_name: str, path: str = "") -> None:
        """Recursively scan repository contents."""
        for content in contents:
            if self.debug_mode:
                console.print(f"[cyan]Scanning: {content.path} (type: {content.type})[/cyan]")
                
            if content.type == "dir":
                try:
                    new_contents = repo.get_contents(content.path, ref=branch_name)
                    self._scan_contents(repo, new_contents, branch_name, content.path)
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not access directory {content.path}: {str(e)}[/yellow]")
            else:
                try:
                    # Skip binary files and large files
                    if content.size > 1024 * 1024:  # Skip files larger than 1MB
                        console.print(f"[yellow]Skipping large file: {content.path}[/yellow]")
                        continue

                    file_content = content.decoded_content.decode('utf-8', errors='ignore')
                    if self.debug_mode and content.path == "single_secret.txt":
                        console.print(f"[cyan]Content of single_secret.txt:[/cyan]")
                        console.print(file_content)
                    self._check_content_for_secrets(file_content, content.path, branch_name)
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not read {content.path}: {str(e)}[/yellow]")

    def _scan_commit(self, repo, commit) -> None:
        """Scan a specific commit for secrets."""
        try:
            files = commit.files
            for file in files:
                try:
                    if file.filename in self.scanned_files:
                        continue
                    
                    if self.debug_mode:
                        console.print(f"[cyan]Scanning file in commit: {file.filename}[/cyan]")
                    
                    content = repo.get_contents(file.filename, ref=commit.sha)
                    file_content = content.decoded_content.decode('utf-8', errors='ignore')
                    self._check_content_for_secrets(file_content, file.filename, f"commit_{commit.sha}")
                    self.scanned_files.add(file.filename)
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not read {file.filename} in commit {commit.sha}: {str(e)}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not process commit {commit.sha}: {str(e)}[/yellow]")

    def _scan_pull_request(self, repo, pull) -> None:
        """Scan a pull request for secrets."""
        try:
            files = pull.get_files()
            for file in files:
                try:
                    if file.filename in self.scanned_files:
                        continue

                    if self.debug_mode:
                        console.print(f"[cyan]Scanning file in PR: {file.filename}[/cyan]")

                    content = repo.get_contents(file.filename, ref=pull.head.sha)
                    file_content = content.decoded_content.decode('utf-8', errors='ignore')
                    self._check_content_for_secrets(file_content, file.filename, f"pr_{pull.number}")
                    self.scanned_files.add(file.filename)
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not read {file.filename} in PR #{pull.number}: {str(e)}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not process PR #{pull.number}: {str(e)}[/yellow]")

    def _check_content_for_secrets(self, content: str, file_path: str, context: str) -> None:
        """Check content for secret patterns."""
        patterns = self.pattern_loader.get_patterns()
        for secret_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, content)
                for match in matches:
                    secret = match.group(0)
                    # Mask the secret for display
                    masked_secret = self._mask_secret(secret)
                    
                    if file_path not in self.found_secrets:
                        self.found_secrets[file_path] = []
                    
                    # Check if this exact secret was already found in this file
                    if not any(s['secret'] == masked_secret and s['type'] == secret_type 
                             for s in self.found_secrets[file_path]):
                        line_num = content[:match.start()].count('\n') + 1
                        self.found_secrets[file_path].append({
                            'type': secret_type,
                            'secret': masked_secret,
                            'context': context,
                            'line_number': line_num
                        })
                        
                        if self.debug_mode:
                            console.print(f"[green]Found {secret_type} in {file_path} (line {line_num})[/green]")

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret for display."""
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]

    def get_results(self) -> Dict:
        """Return the results in a structured format."""
        if not self.found_secrets:
            return {"status": "success", "message": "No secrets found", "secrets": []}

        secrets_list = []
        for file_path, secrets in self.found_secrets.items():
            for secret in secrets:
                secrets_list.append({
                    "file": file_path,
                    "type": secret['type'],
                    "masked_secret": secret['secret'],
                    "context": secret['context'],
                    "line_number": secret['line_number']
                })

        return {
            "status": "success",
            "message": f"Found {len(secrets_list)} potential secrets",
            "secrets": secrets_list
        }
        
    def generate_html_report(self) -> str:
        """Generate an HTML report of the scan results."""
        results = self.get_results()
        
        # Extract unique secret types for the filter dropdown
        secret_types = set()
        for secret in results.get("secrets", []):
            secret_types.add(secret["type"])
        
        # Render the HTML template
        html = render_template_string(
            HTML_TEMPLATE,
            repo_name=self.repo_name,
            message=results.get("message", "Scan completed"),
            secrets=results.get("secrets", []),
            secret_types=sorted(list(secret_types)),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        return html

@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_repository():
    """API endpoint to scan a GitHub repository."""
    try:
        data = request.get_json()
        if not data or 'repository' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing repository parameter",
                "error": "Please provide a repository in the format 'owner/repo'"
            }), 400

        repo_name = data['repository']
        days = int(data.get('days', os.getenv('SCAN_DEPTH_DAYS', 30)))
        scan_commits = data.get('scan_commits', True)
        scan_pulls = data.get('scan_pulls', True)

        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            return jsonify({
                "status": "error",
                "message": "GitHub token not configured",
                "error": "Please set GITHUB_TOKEN in your environment"
            }), 500

        detector = GitHubSecretDetector(github_token)
        detector.set_repo_name(repo_name)
        
        try:
            repo = detector.github.get_repo(repo_name)
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Could not access repository: {repo_name}",
                "error": str(e)
            }), 404

        # Scan default branch
        default_branch = repo.default_branch
        detector.scan_branch(repo, default_branch)

        # Scan other branches
        branches = [branch.name for branch in repo.get_branches()]
        for branch in branches:
            if branch != default_branch:
                detector.scan_branch(repo, branch)

        # Scan commits if requested
        if scan_commits:
            detector.scan_commits(repo, days)

        # Scan pull requests if requested
        if scan_pulls:
            detector.scan_pull_requests(repo, days)

        return jsonify(detector.get_results())

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "An error occurred while scanning the repository",
            "error": str(e)
        }), 500

@app.route('/report', methods=['POST'])
def generate_report():
    """API endpoint to generate an HTML report."""
    try:
        data = request.get_json()
        if not data or 'repository' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing repository parameter",
                "error": "Please provide a repository in the format 'owner/repo'"
            }), 400

        repo_name = data['repository']
        days = int(data.get('days', os.getenv('SCAN_DEPTH_DAYS', 30)))
        scan_commits = data.get('scan_commits', True)
        scan_pulls = data.get('scan_pulls', True)

        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            return jsonify({
                "status": "error",
                "message": "GitHub token not configured",
                "error": "Please set GITHUB_TOKEN in your environment"
            }), 500

        detector = GitHubSecretDetector(github_token)
        detector.set_repo_name(repo_name)
        
        try:
            repo = detector.github.get_repo(repo_name)
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Could not access repository: {repo_name}",
                "error": str(e)
            }), 404

        # Scan default branch
        default_branch = repo.default_branch
        detector.scan_branch(repo, default_branch)

        # Scan other branches
        branches = [branch.name for branch in repo.get_branches()]
        for branch in branches:
            if branch != default_branch:
                detector.scan_branch(repo, branch)

        # Scan commits if requested
        if scan_commits:
            detector.scan_commits(repo, days)

        # Scan pull requests if requested
        if scan_pulls:
            detector.scan_pull_requests(repo, days)

        # Generate HTML report
        html_report = detector.generate_html_report()
        
        return html_report, 200, {'Content-Type': 'text/html'}

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "An error occurred while generating the report",
            "error": str(e)
        }), 500

if __name__ == '__main__':
    # Ensure templates directory exists
    os.makedirs('templates', exist_ok=True)
    
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)