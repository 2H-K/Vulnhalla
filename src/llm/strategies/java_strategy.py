#!/usr/bin/env python3
"""
Java Language Strategy for Vulnhalla.

This module provides Java-specific analysis strategy with optimizations for Java code.
It handles:
- Code extraction with class definition preservation
- Prompt building with Java-specific templates
- Post-processing of LLM responses
- File skip patterns for Java projects

Java Strategy Features:
- Preserves complete class definitions (important for Java)
- Focuses on Spring Bean vulnerabilities, deserialization issues
- Handles SQL injection in JDBC/MyBatis
- Considers XXE in XML parsing
- Higher function line limits for Java's verbose style
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


class JavaStrategy(BaseStrategy):
    """
    Java strategy implementation with class definition preservation.
    
    This strategy provides:
    - Higher line limits for Java's verbose style
    - Java-specific prompt templates
    - Focus on Spring, deserialization, SQL injection
    - Preserves complete class definitions
    
    Key Java vulnerabilities to focus on:
    - Unsafe deserialization (ObjectInputStream, XMLDecoder)
    - SQL injection in JDBC/MyBatis
    - Command injection via Runtime.exec() or ProcessBuilder
    - XXE in XML parsing (DocumentBuilder, SAXParser)
    - Path traversal in File operations
    - Unsafe reflection and class loading
    """
    
    lang = "java"
    display_name = "Java"
    
    # Java-specific skip patterns
    SKIP_PATTERNS = [
        r'/test/',
        r'/tests/',
        r'/example/',
        r'/mock/',
        r'/generated/',
        r'\.java\._',  # Generated files
        r'/target/generated-sources/',
        r'/target/generated-test-sources/',
        r'\.R\.java$',  # RMI generated
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize Java strategy.
        
        Args:
            config (Dict, optional): Configuration dictionary.
        """
        super().__init__(config)
        logger.debug(f"Initialized JavaStrategy with config: {self.config}")
    
    def extract_function_code(
        self, 
        code_file: List[str], 
        function_dict: Dict[str, str],
        max_chars: Optional[int] = None
    ) -> str:
        """
        Extract function code from file lines with class header preservation.
        
        This method preserves class definition headers which are important
        for understanding Java context and framework usage.
        
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
        
        # Try to include class definition header
        # Look backwards from function start to find class/interface/enum declaration
        class_header_lines = []
        for i in range(start_line - 1, -1, -1):
            line = code_file[i].strip()
            # Check for class/interface/enum declaration
            if any(pattern in line for pattern in [
                'class ', 'interface ', 'enum ', '@', 'public ', 'private ', 
                'protected ', 'abstract ', 'final ', 'static '
            ]):
                class_header_lines.append(i + 1)
                break
        
        # Include class header if found
        extract_start = min(class_header_lines) if class_header_lines else start_line
        
        # Extract lines
        snippet_lines = code_file[extract_start:end_line]
        if not snippet_lines:
            return ""
        
        # Add line numbers
        full_snippet = "\n".join(
            f"{extract_start + i + 1}: {s.replace(chr(9), '    ')}"
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
        Build Java-specific LLM prompt for vulnerability analysis.
        
        Uses Java-specific templates from data/templates/java/
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
        
        # Try to load Java-specific template for this issue
        issue_name = issue.get("name", "")
        templates_base = Path("data/templates/java")
        
        # Try issue-specific template first
        template_path = templates_base / f"{issue_name}.template"
        if not template_path.exists():
            # Fall back to general template
            template_path = templates_base / "general.template"
        
        # Read template
        try:
            template = read_file_utf8(str(template_path))
            logger.debug(f"Loaded Java template: {template_path.name}")
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
        Get fallback template when Java templates are not available.
        
        Returns:
            str: Fallback template string.
        """
        return """You are a security expert analyzing potential vulnerabilities in Java code.

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
Analyze Java code above and determine if this is a true vulnerability or a false positive.

**Focus on:**
- Spring Bean vulnerabilities and deserialization issues
- SQL injection in JDBC/MyBatis
- Unsafe reflection and class loading
- XXE in XML parsing (DocumentBuilder, SAXParser)
- Command execution via Runtime.exec() or ProcessBuilder
- Path traversal in File operations
- Input validation in controller endpoints

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
        Post-process LLM response for Java-specific handling.
        
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
        Check if Java file should be skipped based on patterns.
        
        Skips:
        - Test files
        - Mock files
        - Generated code
        - RMI generated files
        
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
        Basic preprocessing for Java code.
        
        Args:
            code_content (str): Raw code content.
            file_path (str): Path to source file.
        
        Returns:
            str: Unmodified code content (Java doesn't need beautification).
        """
        return code_content
    
    def validate_issue(self, issue: Dict[str, str]) -> bool:
        """
        Validate that issue has minimum required fields for Java.
        
        Args:
            issue (Dict): Issue metadata.
        
        Returns:
            bool: True if issue is valid.
        """
        # Check for essential fields
        essential_fields = ["name", "message", "file", "start_line"]
        return all(field in issue for field in essential_fields)
    
    def __repr__(self) -> str:
        return "<JavaStrategy>"


# Convenience function for creating Java strategy
def create_java_strategy(config: Optional[Dict[str, Any]] = None) -> JavaStrategy:
    """Create a Java strategy instance."""
    return JavaStrategy(config=config)


__all__ = [
    "JavaStrategy",
    "create_java_strategy",
]
