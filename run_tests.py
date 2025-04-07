#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse

def run_tests(coverage=False, html_report=False):
    """
    Run the tests for the GitHub Secret Detector.
    
    Args:
        coverage (bool): Whether to generate a coverage report
        html_report (bool): Whether to generate an HTML coverage report
    """
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Change to the script directory
    os.chdir(script_dir)
    
    # Build the command
    if coverage:
        cmd = ["coverage", "run", "-m", "unittest", "test_github_secret_detector.py"]
    else:
        cmd = ["python", "-m", "unittest", "test_github_secret_detector.py"]
    
    # Run the tests
    print("Running tests...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Print the output
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    
    # Check if the tests passed
    if result.returncode != 0:
        print("Tests failed!")
        return False
    
    print("Tests passed!")
    
    # Generate coverage report if requested
    if coverage:
        print("\nGenerating coverage report...")
        subprocess.run(["coverage", "report"])
        
        if html_report:
            print("\nGenerating HTML coverage report...")
            subprocess.run(["coverage", "html"])
            print(f"HTML coverage report generated in {os.path.join(script_dir, 'htmlcov')}")
    
    return True

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run tests for the GitHub Secret Detector")
    parser.add_argument("--coverage", action="store_true", help="Generate a coverage report")
    parser.add_argument("--html", action="store_true", help="Generate an HTML coverage report")
    args = parser.parse_args()
    
    # Run the tests
    success = run_tests(args.coverage, args.html)
    
    # Exit with the appropriate status code
    sys.exit(0 if success else 1) 