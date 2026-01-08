#!/usr/bin/env python3
"""
Language Strategy Base Class for Vulnhalla.

This module defines the abstract base class for all language-specific analysis strategies.
Each language (C/C++, Java, JavaScript, Python, Go, C#, etc.) has a dedicated strategy
that handles:
- Code extraction and truncation
- Prompt building with language-specific hints
- Post-processing of LLM responses

Strategy Pattern Implementation:
- BaseStrategy: Abstract base class defining the interface
- Concrete strategies inherit and implement language-specific behavior
- Factory (factory.py) creates the appropriate strategy based on language
"""
import re
from abc import ABC, abstractmethod
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.utils.common_functions import read_file as read_file_utf8
from src.utils.logger import get_logger

logger = get_logger(__name__)


class BaseStrategy(ABC):
    """
    Abstract base class for language-specific analysis strategies.
    
    All concrete language strategies must inherit from this class and implement
    the abstract methods. This ensures consistent interface across different languages
    while allowing language-specific optimizations.
    
    Attributes:
        lang (str): Language code (e.g., 'c', 'java', 'javascript')
        code_size_limit (int): Maximum characters for code snippets
        max_function_lines (int): Maximum lines per function
        system_prompt_additions (str): Language-specific hints for LLM
    """
    
    # Default configuration - subclasses can override
    lang: str = "base"
    code_size_limit: int = 10000  # Max characters for code snippets
    max_function_lines: int = 200  # Max lines per function
    support_js_beautifier: bool = False  # Whether to use JS beautifier
    required_csv_files: List[str] = ["FunctionTree.csv"]  # Required CSV files
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the strategy with optional configuration.
        
        Args:
            config (Dict, optional): Strategy-specific configuration. If None, uses defaults.
        """
        self.config = config or {}
        self._apply_config_overrides()
    
    def _apply_config_overrides(self) -> None:
        """Apply configuration overrides from the config dict."""
        if "code_size_limit" in self.config:
            self.code_size_limit = self.config["code_size_limit"]
        if "max_function_lines" in self.config:
            self.max_function_lines = self.config["max_function_lines"]
        if "system_prompt_additions" in self.config:
            self.system_prompt_additions = self.config["system_prompt_additions"]
    
    @abstractmethod
    def extract_function_code(
        self, 
        code_file: List[str], 
        function_dict: Dict[str, str]
    ) -> str:
        """
        Extract the function code from the file lines.
        
        Args:
            code_file (List[str]): List of all lines in the file.
            function_dict (Dict): Function metadata with start_line, end_line, etc.
        
        Returns:
            str: Extracted and possibly truncated function code.
        """
        pass
    
    @abstractmethod
    def build_prompt(
        self,
        issue: Dict[str, str],
        message: str,
        snippet: str,
        code: str
    ) -> str:
        """
        Build the LLM prompt with language-specific template and hints.
        
        Args:
            issue (Dict): Issue metadata from CodeQL.
            message (str): Processed message with bracket references replaced.
            snippet (str): Code snippet from the issue location.
            code (str): Full function code context.
        
        Returns:
            str: Complete prompt ready for LLM analysis.
        """
        pass
    
    @abstractmethod
    def post_process_response(self, llm_content: str) -> str:
        """
        Post-process the LLM response for language-specific handling.
        
        Args:
            llm_content (str): Raw content from LLM response.
        
        Returns:
            str: Processed content (classification, stats, etc.).
        """
        pass
    
    def should_skip_file(self, file_path: str) -> bool:
        """
        Check if this file should be skipped (e.g., static resources, minified files).
        
        Args:
            file_path (str): Path to the file being analyzed.
        
        Returns:
            bool: True if file should be skipped, False otherwise.
        """
        # Default implementation - subclasses can override
        return False
    
    def preprocess_code(
        self, 
        code_content: str, 
        file_path: str
    ) -> str:
        """
        Preprocess code before extraction (e.g., beautify, deobfuscate).
        
        Args:
            code_content (str): Raw code content.
            file_path (str): Path to the source file.
        
        Returns:
            str: Preprocessed code content.
        """
        return code_content
    
    def validate_issue(self, issue: Dict[str, str]) -> bool:
        """
        Validate that the issue has all required fields for this language.
        
        Args:
            issue (Dict): Issue metadata from CodeQL.
        
        Returns:
            bool: True if issue is valid, False otherwise.
        """
        required_fields = ["name", "message", "file", "start_line", "start_offset", "end_line", "end_offset"]
        return all(field in issue for field in required_fields)
    
    def get_truncation_warning(self, original_len: int, truncated_len: int) -> str:
        """
        Generate a warning message for code truncation.
        
        Args:
            original_len (int): Original code length.
            truncated_len (int): Truncated code length.
        
        Returns:
            str: Warning message.
        """
        return f"Code truncated from {original_len} to {truncated_len} characters"
    
    def __repr__(self) -> str:
        return f"<{self.lang.capitalize()}Strategy>"
    
    def __str__(self) -> str:
        return f"Language Strategy: {self.lang.upper()}"
