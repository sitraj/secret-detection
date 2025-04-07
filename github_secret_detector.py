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

# Load environment variables
load_dotenv()

# Initialize Rich console
console = Console()

class GitHubSecretDetector:
    def __init__(self, token: str):
        self.github = Github(token)
        self.found_secrets: Dict[str, List[Dict]] = {}
        self.scanned_files: Set[str] = set()
        self.debug_mode = True  # Enable debug mode
        self.pattern_loader = PatternLoader()

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

    def print_results(self) -> None:
        """Print the results in a formatted table."""
        if not self.found_secrets:
            console.print("[green]No secrets found![/green]")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("File")
        table.add_column("Secret Type")
        table.add_column("Masked Secret")
        table.add_column("Context")
        table.add_column("Line Number")

        for file_path, secrets in self.found_secrets.items():
            for secret in secrets:
                table.add_row(
                    file_path,
                    secret['type'],
                    secret['secret'],
                    secret['context'],
                    str(secret['line_number'])
                )

        console.print(table)

def main():
    # Get GitHub token from environment variable
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set[/red]")
        return

    # Get repository information
    repo_name = input("Enter GitHub repository (format: owner/repo): ")
    
    try:
        # Initialize detector
        detector = GitHubSecretDetector(github_token)
        repo = detector.github.get_repo(repo_name)

        # Scan branches
        console.print("[bold blue]Scanning branches...[/bold blue]")
        branches = repo.get_branches()
        for branch in branches:
            detector.scan_branch(repo, branch.name)

        # Scan commits
        console.print("[bold blue]Scanning commits...[/bold blue]")
        detector.scan_commits(repo)

        # Scan pull requests
        console.print("[bold blue]Scanning pull requests...[/bold blue]")
        detector.scan_pull_requests(repo)

        # Print results
        console.print("\n[bold green]Scan complete! Results:[/bold green]")
        detector.print_results()

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

if __name__ == "__main__":
    main() 