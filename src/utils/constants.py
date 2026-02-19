"""
Vulnhalla constants module.

Contains centralized constants for the application, including:
- Issue status codes for LLM classification
- Default configuration values
"""

# =============================================================================
# Issue Status Codes
# =============================================================================
# These codes are returned by the LLM to indicate the classification of a security finding

STATUS_TRUE_POSITIVE = "1337"  # Confirmed security vulnerability
STATUS_FALSE_POSITIVE = "1007" # Confirmed not a security issue (safe)
STATUS_NEED_MORE_DATA = "7331" # Need more context to determine
STATUS_LIKELY_SAFE = "3713"     # Pretty sure it's not a security problem

# Mapping from status codes to human-readable names
STATUS_NAMES = {
    STATUS_TRUE_POSITIVE: "true_positive",
    STATUS_FALSE_POSITIVE: "false_positive", 
    STATUS_NEED_MORE_DATA: "need_more_data",
    STATUS_LIKELY_SAFE: "likely_safe",
}

# All recognized status codes
RECOGNIZED_STATUS_CODES = {STATUS_TRUE_POSITIVE, STATUS_FALSE_POSITIVE, STATUS_NEED_MORE_DATA, STATUS_LIKELY_SAFE}


# =============================================================================
# Issue Classification Results
# =============================================================================
# Human-readable classification results returned by determine_issue_status()

ISSUE_CLASSIFICATION_TRUE = "true"    # True positive - real security issue
ISSUE_CLASSIFICATION_FALSE = "false"  # False positive - not a security issue
ISSUE_CLASSIFICATION_MORE = "more"    # Need more data


# =============================================================================
# LLM Analysis Configuration
# =============================================================================
DEFAULT_MAX_TOKENS = 100000  # Hard limit for prompt tokens
DEFAULT_TIMEOUT = 300         # Default timeout for CodeQL operations (seconds)
DEFAULT_THREADS = 16          # Default number of threads for parallel operations


# =============================================================================
# File Size Limits
# =============================================================================
MAX_FUNCTION_CODE_CHARS = 5000    # Default max characters for function code snippet
MAX_MINIFIED_JS_CHARS = 3000      # Stricter limit for minified JavaScript files
MAX_FUNCTION_LINES_JS = 500      # Max lines for JavaScript functions


# =============================================================================
# Error Handling
# =============================================================================
# Standard exit codes for the application
EXIT_CODE_SUCCESS = 0
EXIT_CODE_GENERAL_ERROR = 1
EXIT_CODE_CONFIG_ERROR = 2
EXIT_CODE_CODEQL_ERROR = 3
EXIT_CODE_LLM_ERROR = 4
EXIT_CODE_FILE_ERROR = 5

# Error message prefixes for consistent logging
ERROR_PREFIX_CONFIG = "⚠️ Configuration Error"
ERROR_PREFIX_CODEQL = "❌ CodeQL Error"
ERROR_PREFIX_LLM = "❌ LLM Error"
ERROR_PREFIX_FILE = "❌ File System Error"
ERROR_PREFIX_GENERAL = "❌ Error"
