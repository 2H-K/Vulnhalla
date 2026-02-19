#!/usr/bin/env python3
"""
Go Language Strategy for Vulnhalla.

This module provides Go-specific analysis strategy with optimizations for Go code.
It handles:
- Code extraction with concurrency focus
- Prompt building with Go-specific hints
- Post-processing of LLM responses
- File skip patterns for Go projects

Go Strategy Features:
- Focuses on race conditions in goroutines
- Handles SQL injection in database/sql
- Considers template injection in html/template
- Checks for improper error handling leading to panics
- Pays attention to defer statements and resource cleanup
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
from src.utils.constants import (
    STATUS_TRUE_POSITIVE,
    STATUS_FALSE_POSITIVE,
    ISSUE_CLASSIFICATION_TRUE,
    ISSUE_CLASSIFICATION_FALSE,
)
from src.utils.common_functions import read_file as read_file_utf8
from src.utils.logger import get_logger

logger = get_logger(__name__)


class GoStrategy(BaseStrategy):
    """
    Go strategy implementation with concurrency focus.
    
    This strategy provides:
    - Concurrency and race condition detection
    - Go-specific prompt templates
    - Focus on goroutines, channels, defer statements
    - SQL injection in database/sql
    - Template injection in html/template
    
    Key Go vulnerabilities to focus on:
    - Race conditions in goroutines
    - SQL injection in database/sql
    - Command injection via os/exec
    - Template injection in html/template
    - Improper error handling leading to panics
    - Insecure use of crypto/tls
    - Resource leaks (missing defer)
    """
    
    lang = "go"
    display_name = "Go"
    
    # Go-specific skip patterns
    SKIP_PATTERNS = [
        r'/test/',
        r'/tests/',
        r'/example/',
        r'/vendor/',
        r'\.go\._',  # Generated files
        r'/gen/',
        r'/generated/',
        r'\.pb\.go$',  # Protocol buffer generated
        r'\.gen\.go$',  # Generated code
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize Go strategy.
        
        Args:
            config (Dict, optional): Configuration dictionary.
        """
        super().__init__(config)
        logger.debug(f"Initialized GoStrategy with config: {self.config}")
    
    def extract_function_code(
        self, 
        code_file: List[str], 
        function_dict: Dict[str, str],
        max_chars: Optional[int] = None
    ) -> str:
        """
        Extract function code from file lines.
        
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
        Build Go-specific LLM prompt for vulnerability analysis.
        
        Uses Go-specific templates from data/templates/go/ (if available)
        Falls back to general.template if issue-specific template not found.
        
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
        
        # Try to load Go-specific template for this issue
        issue_name = issue.get("name", "")
        templates_base = Path("data/templates/go")
        
        # Try issue-specific template first
        template_path = templates_base / f"{issue_name}.template"
        if not template_path.exists():
            # Fall back to general template
            template_path = templates_base / "general.template"
        
        # Read template (if exists)
        if template_path.exists():
            try:
                template = read_file_utf8(str(template_path))
                logger.debug(f"Loaded Go template: {template_path.name}")
            except Exception as e:
                logger.warning(f"Could not read template {template_path}: {e}")
                template = self._get_fallback_template()
        else:
            # Use fallback template
            template = self._get_fallback_template()
        
        # Format template
        prompt = template.format(
            name=issue.get("name", "Unknown Issue"),
            description=issue.get("help", "No description available"),
            message=message,
            location=location,
            code=code
        )
        
        return prompt
    
    def _get_fallback_template(self) -> str:
        """
        Get fallback template when Go templates are not available.
        
        Returns:
            str: Fallback template string.
        """
        return """You are a security expert analyzing potential vulnerabilities in Go code.

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
Analyze Go code above and determine if this is a true vulnerability or a false positive.

**Focus on:**
- Race conditions in goroutines and channels
- SQL injection in database/sql queries
- Command injection via os/exec
- Template injection in html/template
- Improper error handling leading to panics
- Insecure use of crypto/tls
- Resource leaks (missing defer statements)
- Input validation in handlers

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
        Post-process LLM response for Go-specific handling.
        
        Args:
            llm_content (str): Raw content from LLM response.
        
        Returns:
            str: Classification result ("true", "false", or "more").
        """
        content_lower = llm_content.lower()
        
        if STATUS_TRUE_POSITIVE in content_lower:
            return ISSUE_CLASSIFICATION_TRUE
        elif STATUS_FALSE_POSITIVE in content_lower:
            return ISSUE_CLASSIFICATION_FALSE
        else:
            return "more"
    
    def should_skip_file(self, file_path: str) -> bool:
        """
        Check if Go file should be skipped based on patterns.
        
        Skips:
        - Test files
        - Vendor dependencies
        - Generated code (protobuf, .gen.go)
        
        Args:
            file_path (str): Path to file.
        
        Returns:
            bool: True if file should be skipped.
        """
        for pattern in self.SKIP_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False
    
    def preprocess_code(
        self, 
        code_content: str, 
        file_path: str
    ) -> str:
        """
        Basic preprocessing for Go code.
        
        Args:
            code_content (str): Raw code content.
            file_path (str): Path to source file.
        
        Returns:
            str: Unmodified code content (Go doesn't need beautification).
        """
        return code_content
    
    def validate_issue(self, issue: Dict[str, str]) -> bool:
        """
        Validate that issue has minimum required fields for Go.
        
        Args:
            issue (Dict): Issue metadata.
        
        Returns:
            bool: True if issue is valid.
        """
        # Check for essential fields
        essential_fields = ["name", "message", "file", "start_line"]
        return all(field in issue for field in essential_fields)
    
    def __repr__(self) -> str:
        return "<GoStrategy>"


# Convenience function for creating Go strategy
def create_go_strategy(config: Optional[Dict[str, Any]] = None) -> GoStrategy:
    """Create a Go strategy instance."""
    return GoStrategy(config=config)


__all__ = [
    "GoStrategy",
    "create_go_strategy",
]
