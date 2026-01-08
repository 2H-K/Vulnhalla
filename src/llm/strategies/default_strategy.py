#!/usr/bin/env python3
"""
Default Language Strategy for Vulnhalla.

This module provides a fallback strategy for languages that don't have
a dedicated strategy implementation. It implements basic code extraction
and prompt building without language-specific optimizations.

This strategy is used when:
- A requested language doesn't have a specific strategy
- The language-specific strategy fails to load
- A generic fallback is needed for testing
"""
import re
import sys
import os
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.llm.strategies.base import BaseStrategy
from src.utils.common_functions import read_file as read_file_utf8
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DefaultStrategy(BaseStrategy):
    """
    Default strategy implementation with basic functionality.
    
    This strategy provides sensible defaults for any language without
    requiring language-specific optimization. It can be used as a
    fallback or for languages not yet covered by specialized strategies.
    
    Features:
    - Basic code extraction with character limit
    - Generic prompt template
    - Simple response classification
    - File skip patterns for common non-source files
    """
    
    lang = "default"
    display_name = "Generic/Default"
    
    # Default configuration
    code_size_limit = 10000
    max_function_lines = 200
    support_js_beautifier = False
    
    # Common static resource patterns to skip
    STATIC_RESOURCE_PATTERNS = [
        r'/test/',
        r'/tests/',
        r'/example/',
        r'/examples/',
        r'/docs/',
        r'/doc/',
        r'/node_modules/',
        r'/dist/',
        r'/build/',
        r'/static/',
        r'/assets/',
        r'/vendor/',
        r'/third_party/',
        r'/external/',
        r'\.min\.(js|css|html)$',
        r'\.pyc$',
        r'\.class$',
        r'\.o$',
        r'\.obj$',
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the default strategy.
        
        Args:
            config (Dict, optional): Configuration dictionary.
        """
        super().__init__(config)
        logger.debug(f"Initialized DefaultStrategy with config: {self.config}")
    
    def extract_function_code(
        self, 
        code_file: List[str], 
        function_dict: Dict[str, str],
        max_chars: Optional[int] = None
    ) -> str:
        """
        Extract function code from file lines with basic truncation.
        
        Args:
            code_file (List[str]): List of all lines in the file.
            function_dict (Dict): Function metadata with start_line, end_line.
            max_chars (int, optional): Override for code_size_limit.
        
        Returns:
            str: Extracted and truncated function code.
        """
        if not function_dict:
            return ""
        
        try:
            start_line = int(function_dict["start_line"]) - 1
            end_line = int(function_dict["end_line"])
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(f"Invalid function dict: {e}")
            return ""
        
        # Ensure valid range
        if start_line < 0:
            start_line = 0
        if end_line > len(code_file):
            end_line = len(code_file)
        if start_line >= end_line:
            return ""
        
        # Extract lines
        snippet_lines = code_file[start_line:end_line]
        if not snippet_lines:
            return ""
        
        # Add line numbers
        full_snippet = "\n".join(
            f"{start_line + i + 1}: {s.replace(chr(9), '    ')}"
            for i, s in enumerate(snippet_lines)
        )
        
        # Apply truncation
        limit = max_chars or self.code_size_limit
        if len(full_snippet) > limit:
            truncated = full_snippet[:limit]
            # Try to cut at a line boundary
            last_newline = truncated.rfind('\n')
            if last_newline > limit * 0.8:  # If close to end, keep it
                truncated = truncated[:last_newline]
            full_snippet = truncated + "\n... (truncated)"
        
        return full_snippet
    
    def build_prompt(
        self,
        issue: Dict[str, str],
        message: str,
        snippet: str,
        code: str
    ) -> str:
        """
        Build a generic LLM prompt for vulnerability analysis.
        
        Args:
            issue (Dict): Issue metadata from CodeQL.
            message (str): Processed message with bracket references.
            snippet (str): Code snippet from issue location.
            code (str): Full function code context.
        
        Returns:
            str: Complete prompt ready for LLM.
        """
        # Build location string
        file_name = PurePosixPath(issue.get("file", "unknown")).name
        location = f"look at {file_name}:{int(issue.get('start_line', 0))} with '{snippet}'"
        
        # Basic template
        template = self._get_base_template()
        
        # Format template
        prompt = template.format(
            name=issue.get("name", "Unknown Issue"),
            description=issue.get("help", "No description available"),
            message=message,
            location=location,
            code=code
        )
        
        return prompt
    
    def _get_base_template(self) -> str:
        """
        Get the base prompt template.
        
        Returns:
            str: Template string with placeholders.
        """
        return """You are a security expert analyzing potential vulnerabilities in code.

## Issue Information
- **Issue Name**: {name}
- **Description**: {description}
- **Message**: {message}
- **Location**: {location}

## Code Context
```
{code}
```

## Analysis Task
Analyze the code above and determine if this is a true vulnerability or a false positive.

Respond with ONLY one of these formats:
- **TRUE POSITIVE**: [brief explanation why this is a real vulnerability]
- **FALSE POSITIVE**: [brief explanation why this is not a real vulnerability]
- **NEEDS MORE DATA**: [what additional information would help determine the severity]

IMPORTANT: Respond EXACTLY with one of these three prefixes:
- "1337" for TRUE POSITIVE
- "1007" for FALSE POSITIVE  
- "more" for NEEDS MORE DATA

Your response should start with one of these three codes followed by your explanation.
"""
    
    def post_process_response(self, llm_content: str) -> str:
        """
        Post-process LLM response to determine classification.
        
        Args:
            llm_content (str): Raw content from LLM response.
        
        Returns:
            str: Classification result ("true", "false", or "more").
        """
        content_lower = llm_content.lower()
        
        if "1337" in content_lower:
            return "true"
        elif "1007" in content_lower:
            return "false"
        else:
            return "more"
    
    def should_skip_file(self, file_path: str) -> bool:
        """
        Check if file should be skipped based on patterns.
        
        Args:
            file_path (str): Path to the file.
        
        Returns:
            bool: True if file should be skipped.
        """
        for pattern in self.STATIC_RESOURCE_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False
    
    def preprocess_code(
        self, 
        code_content: str, 
        file_path: str
    ) -> str:
        """
        Basic preprocessing - returns content unchanged.
        
        Args:
            code_content (str): Raw code content.
            file_path (str): Path to the source file.
        
        Returns:
            str: Unmodified code content.
        """
        return code_content
    
    def validate_issue(self, issue: Dict[str, str]) -> bool:
        """
        Validate that issue has minimum required fields.
        
        Args:
            issue (Dict): Issue metadata.
        
        Returns:
            bool: True if issue is valid.
        """
        # Check for essential fields
        essential_fields = ["name", "message", "file", "start_line"]
        return all(field in issue for field in essential_fields)
    
    def __repr__(self) -> str:
        return "<DefaultStrategy>"


# Convenience function for creating default strategy
def create_default_strategy(config: Optional[Dict[str, Any]] = None) -> DefaultStrategy:
    """Create a default strategy instance."""
    return DefaultStrategy(config=config)


__all__ = [
    "DefaultStrategy",
    "create_default_strategy",
]
