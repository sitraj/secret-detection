#!/usr/bin/env python3

import unittest
import json
import os
import sys
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add the current directory to the path so we can import the main module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from github_secret_detector import GitHubSecretDetector, app

class TestGitHubSecretDetector(unittest.TestCase):
    """Test cases for the GitHubSecretDetector class."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a test client
        self.app = app.test_client()
        self.app.testing = True
        
        # Mock GitHub token
        self.github_token = "test_token"
        
        # Sample repository data
        self.repo_name = "test-owner/test-repo"
        
        # Sample scan parameters
        self.scan_params = {
            "repository": self.repo_name,
            "days": 30,
            "scan_commits": True,
            "scan_pulls": True
        }
    
    @patch('github.Github')
    def test_initialization(self, mock_github):
        """Test the initialization of GitHubSecretDetector."""
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Check that the GitHub client was initialized with the token
        mock_github.assert_called_once_with(self.github_token)
        
        # Check that the instance variables are initialized correctly
        self.assertEqual(detector.found_secrets, {})
        self.assertEqual(detector.scanned_files, set())
        self.assertFalse(detector.debug_mode)
        self.assertEqual(detector.repo_name, "")
    
    @patch('github.Github')
    def test_set_repo_name(self, mock_github):
        """Test setting the repository name."""
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Set the repository name
        detector.set_repo_name(self.repo_name)
        
        # Check that the repository name was set correctly
        self.assertEqual(detector.repo_name, self.repo_name)
    
    @patch('github.Github')
    def test_get_results_empty(self, mock_github):
        """Test getting results when no secrets are found."""
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Get the results
        results = detector.get_results()
        
        # Check that the results are correct
        self.assertEqual(results["status"], "success")
        self.assertEqual(results["message"], "No secrets found")
        self.assertEqual(results["secrets"], [])
    
    @patch('github.Github')
    def test_get_results_with_secrets(self, mock_github):
        """Test getting results when secrets are found."""
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Add some sample secrets
        detector.found_secrets = {
            "test_file.py": [
                {
                    "type": "API Key",
                    "secret": "abc123",
                    "context": "main",
                    "line_number": 42
                }
            ]
        }
        
        # Get the results
        results = detector.get_results()
        
        # Check that the results are correct
        self.assertEqual(results["status"], "success")
        self.assertEqual(results["message"], "Found 1 potential secrets")
        self.assertEqual(len(results["secrets"]), 1)
        self.assertEqual(results["secrets"][0]["file"], "test_file.py")
        self.assertEqual(results["secrets"][0]["type"], "API Key")
        self.assertEqual(results["secrets"][0]["masked_secret"], "abc123")
        self.assertEqual(results["secrets"][0]["context"], "main")
        self.assertEqual(results["secrets"][0]["line_number"], 42)
    
    @patch('github.Github')
    def test_generate_html_report(self, mock_github):
        """Test generating an HTML report."""
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Set the repository name
        detector.set_repo_name(self.repo_name)
        
        # Add some sample secrets
        detector.found_secrets = {
            "test_file.py": [
                {
                    "type": "API Key",
                    "secret": "abc123",
                    "context": "main",
                    "line_number": 42
                }
            ]
        }
        
        # Generate the HTML report
        html = detector.generate_html_report()
        
        # Check that the HTML contains the expected content
        self.assertIn("GitHub Secret Detection Report", html)
        self.assertIn(self.repo_name, html)
        self.assertIn("API Key", html)
        self.assertIn("test_file.py", html)
        self.assertIn("Line 42", html)
    
    @patch('github.Github')
    def test_scan_branch(self, mock_github):
        """Test scanning a branch."""
        # Create a mock repository
        mock_repo = MagicMock()
        mock_branch = MagicMock()
        mock_branch.name = "main"
        mock_branch.commit.sha = "abc123"
        mock_repo.get_branch.return_value = mock_branch
        
        # Create a mock content
        mock_content = MagicMock()
        mock_content.path = "test_file.py"
        mock_content.type = "file"
        mock_content.size = 100
        mock_content.decoded_content = b"API_KEY=abc123"
        
        # Set up the mock to return the content
        mock_repo.get_contents.return_value = [mock_content]
        
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Mock the _check_content_for_secrets method
        with patch.object(detector, '_check_content_for_secrets') as mock_check:
            # Scan the branch
            detector.scan_branch(mock_repo, "main")
            
            # Check that the branch was retrieved
            mock_repo.get_branch.assert_called_once_with("main")
            
            # Check that the contents were retrieved
            mock_repo.get_contents.assert_called_once_with("", ref="main")
            
            # Check that the content was checked for secrets
            mock_check.assert_called_once()
    
    @patch('github.Github')
    def test_scan_commits(self, mock_github):
        """Test scanning commits."""
        # Create a mock repository
        mock_repo = MagicMock()
        
        # Create a mock commit
        mock_commit = MagicMock()
        mock_commit.sha = "abc123"
        
        # Create a mock file
        mock_file = MagicMock()
        mock_file.filename = "test_file.py"
        
        # Set up the mock to return the commit and file
        mock_repo.get_commits.return_value = [mock_commit]
        mock_commit.files = [mock_file]
        
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Mock the _scan_commit method
        with patch.object(detector, '_scan_commit') as mock_scan:
            # Scan the commits
            detector.scan_commits(mock_repo, 30)
            
            # Check that the commits were retrieved
            mock_repo.get_commits.assert_called_once()
            
            # Check that the commit was scanned
            mock_scan.assert_called_once_with(mock_repo, mock_commit)
    
    @patch('github.Github')
    def test_scan_pull_requests(self, mock_github):
        """Test scanning pull requests."""
        # Create a mock repository
        mock_repo = MagicMock()
        
        # Create a mock pull request
        mock_pull = MagicMock()
        mock_pull.number = 42
        mock_pull.created_at = datetime.now()
        
        # Set up the mock to return the pull request
        mock_repo.get_pulls.return_value = [mock_pull]
        
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Mock the _scan_pull_request method
        with patch.object(detector, '_scan_pull_request') as mock_scan:
            # Scan the pull requests
            detector.scan_pull_requests(mock_repo, 30)
            
            # Check that the pull requests were retrieved
            mock_repo.get_pulls.assert_called_once_with(state='all')
            
            # Check that the pull request was scanned
            mock_scan.assert_called_once_with(mock_repo, mock_pull)
    
    @patch('github.Github')
    def test_check_content_for_secrets(self, mock_github):
        """Test checking content for secrets."""
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Mock the pattern loader
        detector.pattern_loader = MagicMock()
        detector.pattern_loader.get_patterns.return_value = {
            "API Key": [r"API_KEY\s*=\s*['\"]([^'\"]+)['\"]"]
        }
        
        # Check content for secrets
        detector._check_content_for_secrets("API_KEY=abc123", "test_file.py", "main")
        
        # Check that the secret was found
        self.assertIn("test_file.py", detector.found_secrets)
        self.assertEqual(len(detector.found_secrets["test_file.py"]), 1)
        self.assertEqual(detector.found_secrets["test_file.py"][0]["type"], "API Key")
        self.assertEqual(detector.found_secrets["test_file.py"][0]["secret"], "abc123")
        self.assertEqual(detector.found_secrets["test_file.py"][0]["context"], "main")
        self.assertEqual(detector.found_secrets["test_file.py"][0]["line_number"], 1)
    
    @patch('github.Github')
    def test_mask_secret(self, mock_github):
        """Test masking a secret."""
        # Create an instance of GitHubSecretDetector
        detector = GitHubSecretDetector(self.github_token)
        
        # Test masking a short secret
        masked = detector._mask_secret("abc")
        self.assertEqual(masked, "***")
        
        # Test masking a long secret
        masked = detector._mask_secret("abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(masked, "abcd********************wxyz")


class TestAPIEndpoints(unittest.TestCase):
    """Test cases for the API endpoints."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a test client
        self.app = app.test_client()
        self.app.testing = True
        
        # Sample repository data
        self.repo_name = "test-owner/test-repo"
        
        # Sample scan parameters
        self.scan_params = {
            "repository": self.repo_name,
            "days": 30,
            "scan_commits": True,
            "scan_pulls": True
        }
    
    @patch('github_secret_detector.GitHubSecretDetector')
    def test_scan_endpoint(self, mock_detector_class):
        """Test the /scan endpoint."""
        # Create a mock detector
        mock_detector = MagicMock()
        mock_detector_class.return_value = mock_detector
        
        # Set up the mock to return a result
        mock_detector.get_results.return_value = {
            "status": "success",
            "message": "Found 1 potential secrets",
            "secrets": [
                {
                    "file": "test_file.py",
                    "type": "API Key",
                    "masked_secret": "abc123",
                    "context": "main",
                    "line_number": 42
                }
            ]
        }
        
        # Mock the GitHub token
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
            # Send a POST request to the /scan endpoint
            response = self.app.post('/scan', json=self.scan_params)
            
            # Check that the response is correct
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["message"], "Found 1 potential secrets")
            self.assertEqual(len(data["secrets"]), 1)
    
    @patch('github_secret_detector.GitHubSecretDetector')
    def test_report_endpoint(self, mock_detector_class):
        """Test the /report endpoint."""
        # Create a mock detector
        mock_detector = MagicMock()
        mock_detector_class.return_value = mock_detector
        
        # Set up the mock to return an HTML report
        mock_detector.generate_html_report.return_value = "<html>Test Report</html>"
        
        # Mock the GitHub token
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
            # Send a POST request to the /report endpoint
            response = self.app.post('/report', json=self.scan_params)
            
            # Check that the response is correct
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content_type, 'text/html')
            self.assertIn("Test Report", response.data.decode('utf-8'))
    
    def test_index_endpoint(self):
        """Test the / endpoint."""
        # Send a GET request to the / endpoint
        response = self.app.get('/')
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertIn("GitHub Secret Detector", response.data.decode('utf-8'))
    
    def test_scan_endpoint_missing_repository(self):
        """Test the /scan endpoint with missing repository parameter."""
        # Send a POST request to the /scan endpoint without a repository
        response = self.app.post('/scan', json={})
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["message"], "Missing repository parameter")
    
    def test_report_endpoint_missing_repository(self):
        """Test the /report endpoint with missing repository parameter."""
        # Send a POST request to the /report endpoint without a repository
        response = self.app.post('/report', json={})
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["message"], "Missing repository parameter")
    
    def test_scan_endpoint_missing_token(self):
        """Test the /scan endpoint with missing GitHub token."""
        # Send a POST request to the /scan endpoint without a GitHub token
        with patch.dict(os.environ, {}, clear=True):
            response = self.app.post('/scan', json=self.scan_params)
            
            # Check that the response is correct
            self.assertEqual(response.status_code, 500)
            data = json.loads(response.data)
            self.assertEqual(data["status"], "error")
            self.assertEqual(data["message"], "GitHub token not configured")
    
    def test_report_endpoint_missing_token(self):
        """Test the /report endpoint with missing GitHub token."""
        # Send a POST request to the /report endpoint without a GitHub token
        with patch.dict(os.environ, {}, clear=True):
            response = self.app.post('/report', json=self.scan_params)
            
            # Check that the response is correct
            self.assertEqual(response.status_code, 500)
            data = json.loads(response.data)
            self.assertEqual(data["status"], "error")
            self.assertEqual(data["message"], "GitHub token not configured")


if __name__ == '__main__':
    unittest.main() 