"""
Pattern loader module for secret detection.
This module handles loading and managing secret patterns from the YAML configuration file.
"""

import os
import yaml
from typing import Dict, List, Optional

class PatternLoader:
    def __init__(self, pattern_file: str = 'secret_patterns.yaml'):
        """
        Initialize the pattern loader.
        
        Args:
            pattern_file (str): Path to the YAML file containing secret patterns.
        """
        self.pattern_file = pattern_file
        self.patterns = {}
        self.descriptions = {}
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load patterns from the YAML file."""
        try:
            with open(self.pattern_file, 'r') as f:
                data = yaml.safe_load(f)
                
            for secret_type, config in data.items():
                self.patterns[secret_type] = config['patterns']
                self.descriptions[secret_type] = config['description']
                
        except FileNotFoundError:
            raise FileNotFoundError(f"Pattern file not found: {self.pattern_file}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing pattern file: {str(e)}")

    def get_patterns(self) -> Dict[str, List[str]]:
        """
        Get all secret patterns.
        
        Returns:
            Dict[str, List[str]]: Dictionary mapping secret types to their patterns.
        """
        return self.patterns

    def get_descriptions(self) -> Dict[str, str]:
        """
        Get descriptions for all secret types.
        
        Returns:
            Dict[str, str]: Dictionary mapping secret types to their descriptions.
        """
        return self.descriptions

    def get_patterns_for_type(self, secret_type: str) -> Optional[List[str]]:
        """
        Get patterns for a specific secret type.
        
        Args:
            secret_type (str): The type of secret to get patterns for.
            
        Returns:
            Optional[List[str]]: List of patterns for the secret type, or None if not found.
        """
        return self.patterns.get(secret_type)

    def get_description(self, secret_type: str) -> Optional[str]:
        """
        Get description for a specific secret type.
        
        Args:
            secret_type (str): The type of secret to get description for.
            
        Returns:
            Optional[str]: Description for the secret type, or None if not found.
        """
        return self.descriptions.get(secret_type)

    def reload_patterns(self) -> None:
        """Reload patterns from the YAML file."""
        self._load_patterns() 