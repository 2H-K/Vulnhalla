#!/usr/bin/env python3
"""
Language Configuration Center for Vulnhalla.

This module provides centralized configuration for all supported programming languages.
It defines recommended parameters for:
- Code size limits (token management)
- Function line limits
- Language-specific system prompt additions
- Required CSV files for analysis
- Static resource patterns to skip

This configuration is used by the strategy pattern implementation to ensure
consistent behavior across different languages while allowing fine-tuning.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class LanguageConfig:
    """
    Configuration for a single programming language.
    
    Attributes:
        lang: Language code (e.g., 'c', 'java', 'javascript')
        display_name: Human-readable name for logging
        code_size_limit: Maximum characters for code snippets (prevents token explosion)
        max_function_lines: Maximum lines per function extraction
        support_js_beautifier: Whether to apply JS beautification for minified files
        required_csv_files: List of required CSV files for this language
        skip_patterns: Regex patterns for files to skip (static resources, etc.)
        system_prompt_additions: Language-specific hints to append to LLM prompts
        query_path: Path to CodeQL queries relative to data/queries/
        template_path: Path to templates relative to data/templates/
    """
    lang: str
    display_name: str
    code_size_limit: int = 10000
    max_function_lines: int = 200
    support_js_beautifier: bool = False
    required_csv_files: List[str] = field(default_factory=lambda: ["FunctionTree.csv"])
    skip_patterns: List[str] = field(default_factory=list)
    system_prompt_additions: str = ""
    query_path: str = ""
    template_path: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for strategy initialization."""
        return {
            "code_size_limit": self.code_size_limit,
            "max_function_lines": self.max_function_lines,
            "system_prompt_additions": self.system_prompt_additions,
        }


# Centralized configuration for all supported languages
LANGUAGE_CONFIGS: Dict[str, LanguageConfig] = {
    # C/C++ Configuration
    "c": LanguageConfig(
        lang="c",
        display_name="C/C++",
        code_size_limit=12000,  # ~3000 tokens
        max_function_lines=300,
        support_js_beautifier=False,
        required_csv_files=["FunctionTree.csv", "Classes.csv", "GlobalVars.csv"],
        skip_patterns=[
            r'/test/',
            r'/tests/',
            r'/example/',
            r'\.min\.(c|h)$',
        ],
        system_prompt_additions="""
        - Focus on memory safety issues (buffer overflows, use-after-free)
        - Pay attention to pointer arithmetic and array bounds
        - Consider NULL pointer dereferences and uninitialized variables
        - Check for integer overflow in size calculations
        """,
        query_path="cpp",
        template_path="cpp",
    ),
    
    # Java Configuration
    "java": LanguageConfig(
        lang="java",
        display_name="Java",
        code_size_limit=12000,  # ~3000 tokens
        max_function_lines=400,
        support_js_beautifier=False,
        required_csv_files=["FunctionTree.csv", "Classes.csv"],
        skip_patterns=[
            r'/test/',
            r'/tests/',
            r'/example/',
            r'/mock/',
            r'/generated/',
        ],
        system_prompt_additions="""
        - Focus on Spring Bean vulnerabilities, deserialization issues
        - Pay attention to SQL injection in JDBC/MyBatis
        - Check for unsafe reflection and class loading
        - Consider XXE in XML parsing
        - Look for command execution via Runtime.exec() or ProcessBuilder
        - Verify input validation in controller endpoints
        """,
        query_path="java",
        template_path="java",
    ),
    
    # JavaScript/TypeScript Configuration
    "javascript": LanguageConfig(
        lang="javascript",
        display_name="JavaScript/TypeScript",
        code_size_limit=4000,  # Stricter limit for JS (minified files common)
        max_function_lines=100,
        support_js_beautifier=True,  # Handle minified files
        required_csv_files=["FunctionTree.csv"],
        skip_patterns=[
            r'/node_modules/',
            r'/dist/',
            r'/build/',
            r'/static/',
            r'/assets/',
            r'\.min\.js$',
            r'\.min\.ts$',
            r'/third_party/',
            r'/vendor/',
            r'/public/',
        ],
        system_prompt_additions="""
        - Focus on prototype pollution, XSS vulnerabilities
        - Pay attention to eval() and Function() usage
        - Check for command injection in child_process
        - Consider SQL injection in database queries
        - Look for insecure use of crypto libraries
        - Verify proper input sanitization in Express/koa routes
        - Handle minified code carefully - request full function context if needed
        """,
        query_path="javascript",
        template_path="javascript",
    ),
    
    # Python Configuration
    "python": LanguageConfig(
        lang="python",
        display_name="Python",
        code_size_limit=10000,  # ~2500 tokens
        max_function_lines=350,
        support_js_beautifier=False,
        required_csv_files=["FunctionTree.csv"],
        skip_patterns=[
            r'/test/',
            r'/tests/',
            r'/example/',
            r'/venv/',
            r'/__pycache__/',
            r'\.pyc$',
        ],
        system_prompt_additions="""
        - Focus on eval()/exec() usage and Pickle deserialization
        - Pay attention to SQL injection in database queries
        - Check for command injection via subprocess/OS modules
        - Consider YAML unsafe loading
        - Look for path traversal vulnerabilities
        - Verify template injection in Jinja2
        - Ensure try-except blocks are properly closed
        - Check for hardcoded secrets and API keys
        """,
        query_path="python",
        template_path="python",
    ),
    
    # Go Configuration
    "go": LanguageConfig(
        lang="go",
        display_name="Go",
        code_size_limit=10000,  # ~2500 tokens
        max_function_lines=400,
        support_js_beautifier=False,
        required_csv_files=["FunctionTree.csv"],
        skip_patterns=[
            r'/test/',
            r'/tests/',
            r'/example/',
            r'/vendor/',
        ],
        system_prompt_additions="""
        - Focus on race conditions in goroutines
        - Pay attention to SQL injection in database/sql
        - Check for command injection via os/exec
        - Consider template injection in html/template
        - Look for improper error handling leading to panics
        - Verify input validation in handlers
        - Check for insecure use of crypto/tls
        - Pay attention to defer statements and resource cleanup
        """,
        query_path="go",
        template_path="go",
    ),
    
    # C# Configuration
    "csharp": LanguageConfig(
        lang="csharp",
        display_name="C#/.NET",
        code_size_limit=10000,  # ~2500 tokens
        max_function_lines=300,
        support_js_beautifier=False,
        required_csv_files=["FunctionTree.csv", "Classes.csv"],
        skip_patterns=[
            r'/test/',
            r'/tests/',
            r'/example/',
            r'/obj/',
            r'/bin/',
        ],
        system_prompt_additions="""
        - Focus on deserialization vulnerabilities
        - Pay attention to SQL injection in ADO.NET/Entity Framework
        - Check for command injection via Process.Start
        - Consider XPath injection in XML processing
        - Look for unsafe reflection usage
        - Verify ViewState vulnerabilities in web apps
        - Check for insecure cryptographic implementations
        - Filter out auto-generated Property getters/setters
        """,
        query_path="csharp",
        template_path="csharp",
    ),
    
    # TypeScript (alias for JavaScript)
    "typescript": LanguageConfig(
        lang="typescript",
        display_name="TypeScript",
        code_size_limit=4000,
        max_function_lines=100,
        support_js_beautifier=True,
        required_csv_files=["FunctionTree.csv"],
        skip_patterns=[
            r'/node_modules/',
            r'/dist/',
            r'/build/',
            r'/static/',
            r'\.d\.ts$',  # Type declaration files
        ],
        system_prompt_additions="""
        - Focus on type-related vulnerabilities
        - Pay attention to improper type assertions
        - Check for unsafe use of 'any' type
        - Consider prototype pollution in typed contexts
        - Look for command injection in node:child_process
        - Verify input validation in Express/Next.js routes
        """,
        query_path="javascript",  # Use JS queries for TS
        template_path="javascript",  # Use JS templates for TS
    ),
}


def get_language_config(lang: str) -> Optional[LanguageConfig]:
    """
    Get configuration for a specific language.
    
    Args:
        lang (str): Language code (e.g., 'c', 'java', 'javascript')
    
    Returns:
        LanguageConfig: Configuration for the language, or None if not supported.
    """
    return LANGUAGE_CONFIGS.get(lang.lower())


def get_supported_languages() -> List[str]:
    """Get list of all supported language codes."""
    return list(LANGUAGE_CONFIGS.keys())


def get_language_display_name(lang: str) -> str:
    """Get human-readable display name for a language."""
    config = get_language_config(lang)
    return config.display_name if config else lang.upper()


def normalize_language(lang: str) -> str:
    """
    Normalize language name to internal code.
    
    Args:
        lang (str): Language name (e.g., 'c++', 'cpp', 'java')
    
    Returns:
        str: Normalized language code (e.g., 'c', 'java')
    """
    mapping = {
        "c++": "c",
        "cpp": "c",
        "c#": "csharp",
        "ts": "typescript",
        "js": "javascript",
        "py": "python",
    }
    return mapping.get(lang.lower(), lang.lower())


# Token limit constants for safety (hard limits)
MAX_TOTAL_TOKENS = 128000  # Safety limit for any single request
WARNING_TOKENS = 100000    # Warning threshold for large requests
