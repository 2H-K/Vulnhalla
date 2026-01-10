#!/usr/bin/env python3
"""
JavaScript Language Strategy for Vulnhalla.

This module provides JavaScript-specific analysis strategy with optimizations for JS code.
It handles:
- Code extraction with minification handling
- JS beautification for minified files
- Prompt building with JavaScript-specific templates
- Post-processing of LLM responses
- File skip patterns for JavaScript projects

JavaScript Strategy Features:
- Automatic beautification of minified JS files
- Focuses on prototype pollution, XSS, eval vulnerabilities
- Handles Node.js command injection
- Stricter limits for minified code
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

# Check if jsbeautifier is available
try:
    import jsbeautifier
    JS_BEAUTIFIER_AVAILABLE = True
except ImportError:
    JS_BEAUTIFIER_AVAILABLE = False
    logger.warning("jsbeautifier not installed. JS minified files may cause issues.")


class JavaScriptStrategy(BaseStrategy):
    """
    JavaScript strategy implementation with minification handling.
    
    This strategy provides:
    - Automatic JS beautification for minified files
    - JavaScript-specific prompt templates
    - Focus on prototype pollution, XSS, eval vulnerabilities
    - Node.js command injection detection
    - Stricter limits for minified code
    
    Key JavaScript vulnerabilities to focus on:
    - Prototype pollution (Object.prototype modifications)
    - XSS vulnerabilities (innerHTML, document.write)
    - Unsafe eval() and Function() usage
    - Command injection in Node.js (child_process.exec)
    - SQL injection in database queries
    """
    
    lang = "javascript"
    display_name = "JavaScript/TypeScript"
    
    # JavaScript-specific skip patterns
    SKIP_PATTERNS = [
        r'/test/',
        r'/tests/',
        r'/example/',
        r'/node_modules/',
        r'/dist/',
        r'/build/',
        r'/static/',
        r'/assets/',
        r'/vendor/',
        r'/third_party/',
        r'/external/',
        r'\.min\.js$',
        r'\.min\.ts$',
        r'\.bundle\.js$',
        r'\.chunk\.js$',
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize JavaScript strategy.
        
        Args:
            config (Dict, optional): Configuration dictionary.
        """
        super().__init__(config)
        logger.debug(f"Initialized JavaScriptStrategy with config: {self.config}")
    
    def extract_function_code(
        self, 
        code_file: List[str], 
        function_dict: Dict[str, str],
        max_chars: Optional[int] = None
    ) -> str:
        """
        Extract function code from file lines with minification handling.
        
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
        
        # Check if function is too long (minified file)
        max_lines = self.max_function_lines
        if len(snippet_lines) > max_lines:
            logger.warning(f"JS function truncated to {max_lines} lines")
            snippet_lines = snippet_lines[:max_lines]
        
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
        Build JavaScript-specific LLM prompt for vulnerability analysis.
        
        Uses JavaScript-specific templates from data/templates/javascript/
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
        
        # Try to load JavaScript-specific template for this issue
        issue_name = issue.get("name", "")
        templates_base = Path("data/templates/javascript")
        
        # Try issue-specific template first
        template_path = templates_base / f"{issue_name}.template"
        if not template_path.exists():
            # Fall back to general template
            template_path = templates_base / "general.template"
        
        # Read template
        try:
            template = read_file_utf8(str(template_path))
            logger.debug(f"Loaded JavaScript template: {template_path.name}")
        except Exception as e:
            logger.warning(f"Could not read template {template_path}: {e}")
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
        Get fallback template when JavaScript templates are not available.
        
        Returns:
            str: Fallback template string.
        """
        return """You are a security expert analyzing potential vulnerabilities in JavaScript/TypeScript code.

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
Analyze JavaScript code above and determine if this is a true vulnerability or a false positive.

**Focus on:**
- Prototype pollution (modifying Object.prototype, __proto__)
- XSS vulnerabilities (innerHTML, document.write, eval)
- Unsafe eval() and Function() usage
- Command injection in Node.js (child_process.exec, spawn)
- SQL injection in database queries
- Insecure use of crypto libraries
- Input sanitization in Express/koa routes

**Important for minified code:**
- Request full function context if needed
- Check if code is client-side (browser) or server-side (Node.js)
- Client-side XSS (user attacking themselves) is often a false positive

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
        Post-process LLM response for JavaScript-specific handling.
        
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
        Check if JavaScript file should be skipped based on patterns.
        
        Skips:
        - Test files
        - Node modules
        - Minified files
        - Build artifacts (dist/, build/)
        - Static resources
        
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
        Preprocess JavaScript code - beautify if minified.
        
        Args:
            code_content (str): Raw code content.
            file_path (str): Path to source file.
        
        Returns:
            str: Beautified code content if minified, otherwise unchanged.
        """
        # Check if jsbeautifier is available
        if not JS_BEAUTIFIER_AVAILABLE:
            return code_content
        
        # Check if code is likely minified
        lines = code_content.split("\n")
        is_minified = (
            len(lines) <= 5 or  # Very few lines
            (len(lines) == 1 and len(code_content) > 10000)  # Single line with many chars
        )
        
        if not is_minified:
            return code_content
        
        # Try to beautify
        try:
            beautified = jsbeautifier.beautify(code_content)
            logger.debug(f"JavaScript code beautified ({len(code_content)} -> {len(beautified)} chars)")
            return beautified
        except Exception as e:
            logger.warning(f"JS beautification failed: {e}")
            return code_content
    
    def validate_issue(self, issue: Dict[str, str]) -> bool:
        """
        Validate that issue has minimum required fields for JavaScript.
        
        Args:
            issue (Dict): Issue metadata.
        
        Returns:
            bool: True if issue is valid.
        """
        # Check for essential fields
        essential_fields = ["name", "message", "file", "start_line"]
        return all(field in issue for field in essential_fields)
    
    def __repr__(self) -> str:
        return "<JavaScriptStrategy>"


# Convenience function for creating JavaScript strategy
def create_javascript_strategy(config: Optional[Dict[str, Any]] = None) -> JavaScriptStrategy:
    """Create a JavaScript strategy instance."""
    return JavaScriptStrategy(config=config)


__all__ = [
    "JavaScriptStrategy",
    "create_javascript_strategy",
]
