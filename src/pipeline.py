#!/usr/bin/env python3
"""
Pipeline orchestration for Vulnhalla.
This module coordinates the complete analysis pipeline:
1. Fetch CodeQL databases (optional)
2. Run CodeQL queries
3. Classify results with LLM

Supported modes:
- Remote mode: Fetch databases from GitHub and analyze
- Local mode: Analyze existing local databases
"""
import sys
from pathlib import Path
from typing import Optional, List
import argparse

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.codeql.fetch_repos import fetch_codeql_dbs
from src.codeql.run_codeql_queries import compile_and_run_codeql_queries
from src.utils.config import get_codeql_path
from src.utils.config_validator import validate_and_exit_on_error
from src.utils.logger import setup_logging, get_logger
from src.utils.exceptions import (
    CodeQLError, CodeQLConfigError, CodeQLExecutionError,
    LLMError, LLMConfigError, LLMApiError,
    VulnhallaError
)
from src.vulnhalla import IssueAnalyzer
from src.utils.cache_manager import CacheManager

# Initialize logging
setup_logging()
logger = get_logger(__name__)

# Initialize cache manager
cache_manager = CacheManager()


# Language mapping: external language names to internal CodeQL language codes
LANGUAGE_MAPPING = {
    "c": "c",
    "cpp": "c",
    "c++": "c",
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "python": "python",
    "go": "go",
    "ruby": "ruby",
    "csharp": "csharp",
    "c#": "csharp",
    "typescript": "typescript",
    "ts": "typescript",
}

# Supported languages (for validation)
SUPPORTED_LANGUAGES = ["c", "java", "javascript", "python", "go", "ruby", "csharp", "typescript"]


def normalize_language(lang: str) -> str:
    """
    Normalize language name to internal CodeQL language code.
    
    Args:
        lang: Language name (e.g., "c++", "cpp", "java", "javascript")
    
    Returns:
        Normalized language code (e.g., "c", "java", "javascript")
    
    Raises:
        ValueError: If language is not supported
    """
    lang_lower = lang.lower().strip()
    
    if lang_lower in LANGUAGE_MAPPING:
        return LANGUAGE_MAPPING[lang_lower]
    
    # Check if already normalized
    if lang_lower in SUPPORTED_LANGUAGES:
        return lang_lower
    
    raise ValueError(f"Unsupported language: '{lang}'. Supported languages: {', '.join(SUPPORTED_LANGUAGES)}")


def find_first_database(lang: str, custom_db_path: Optional[str] = None) -> Optional[str]:
    """
    Find the first available database in the specified language directory.
    
    Default search path: output/databases/{lang}/{project_name}/{database_dir}
    Supports two-level structure: output/databases/{lang}/*/{database_dir}
    where database_dir contains codeql-database.yml
    
    Args:
        lang: Language code (e.g., "c", "java")
        custom_db_path: Optional custom database path. If provided, uses this path directly.
    
    Returns:
        Path to the first database directory, or None if not found
    """
    if custom_db_path:
        db_path = Path(custom_db_path)
        if db_path.exists() and db_path.is_dir():
            return str(db_path)
        logger.error(f"Custom database path does not exist: {custom_db_path}")
        return None
    
    # Default search path: output/databases/{lang}
    default_dbs_folder = Path("output/databases") / lang
    
    if not default_dbs_folder.exists():
        logger.error(f"Database folder not found: {default_dbs_folder}")
        return None
    
    # Find all database directories (support two-level structure)
    # Structure: output/databases/{lang}/{project_name}/{database_dir}
    # A database directory is identified by having codeql-database.yml file
    all_dbs = []
    
    for project_dir in default_dbs_folder.iterdir():
        if project_dir.is_dir():
            # Check second level: database directories within project directory
            for db_dir in project_dir.iterdir():
                if db_dir.is_dir():
                    # Check if this is a database directory (has codeql-database.yml)
                    db_yml = db_dir / "codeql-database.yml"
                    if db_yml.exists():
                        all_dbs.append(str(db_dir))
    
    if not all_dbs:
        logger.error(f"No databases found in: {default_dbs_folder}")
        logger.error(f"   Expected structure: output/databases/{lang}/{{project_name}}/{{database_dir}}/")
        return None
    
    # Sort and pick first
    first_db = sorted(all_dbs)[0]
    
    logger.info(f"Found database: {first_db}")
    return str(first_db)


def _log_exception_cause(e: Exception) -> None:
    """
    Log cause of an exception if available and not already included in the exception message.
    Checks both e.cause (if set via constructor) and e.__cause__ (if set via 'from e').
    """
    cause = getattr(e, 'cause', None) or getattr(e, '__cause__', None)
    if cause:
        # Only log cause if it's not already included in the exception message
        cause_str = str(cause)
        error_str = str(e)
        if cause_str not in error_str:
            logger.error(f"   Cause: {cause}")


def analyze_pipeline(
    mode: str = "remote",
    repo: Optional[str] = None,
    lang: str = "c",
    db_path: Optional[str] = None,
    threads: int = 16
) -> None:
    """
    Run the complete Vulnhalla pipeline: fetch (optional), analyze, and classify.
    
    Args:
        mode: Analysis mode - "remote" (fetch from GitHub) or "local" (use existing databases)
        repo: Optional GitHub repository name (e.g., "redis/redis"). Only used in remote mode.
        lang: Programming language code. Defaults to "c".
        db_path: Optional custom database path for local mode.
        threads: Number of threads for CodeQL operations. Defaults to 16.
    
    Note:
        This function catches and handles all exceptions internally, logging errors
        and exiting with code 1 on failure. It does not raise exceptions.
    """
    # Normalize language
    try:
        lang = normalize_language(lang)
    except ValueError as e:
        logger.error(f"❌ {e}")
        sys.exit(1)
    
    logger.info("🚀 Starting Vulnhalla Analysis Pipeline")
    logger.info("=" * 60)
    logger.info(f"Mode: {mode.upper()}")
    logger.info(f"Language: {lang}")
    if db_path:
        logger.info(f"Database path: {db_path}")
    
    try:
        # Validate configuration before starting
        validate_and_exit_on_error()
    except (CodeQLConfigError, LLMConfigError, VulnhallaError) as e:
        # Format error message for display
        message = f"""
⚠️ Configuration Validation Failed
===========================================================
{str(e)}
===========================================================
Please fix the configuration errors above and try again.
See README.md for configuration reference.
"""
        logger.error(message)
        _log_exception_cause(e)
        sys.exit(1)
    
    # Step 1: Fetch CodeQL databases (remote mode only)
    if mode == "remote":
        try:
            logger.info("\n[1/3] Fetching CodeQL Databases")
            logger.info("-" * 60)
            if repo:
                logger.info(f"Fetching database for: {repo}")
                fetch_codeql_dbs(lang=lang, threads=threads, single_repo=repo)
            else:
                logger.info(f"Fetching top repositories for language: {lang}")
                fetch_codeql_dbs(lang=lang, max_repos=100, threads=4)
        except CodeQLConfigError as e:
            logger.error(f"❌ Configuration error while fetching CodeQL databases: {e}")
            _log_exception_cause(e)
            logger.error("   Please check your GitHub token and permissions.")
            sys.exit(1)
        except CodeQLError as e:
            logger.error(f"❌ Failed to fetch CodeQL databases: {e}")
            _log_exception_cause(e)
            logger.error("   Please check file permissions, disk space, and GitHub API access.")
            sys.exit(1)
    else:
        logger.info("\n[1/3] Using Local Databases")
        logger.info("-" * 60)
        
        # Find database path
        actual_db_path = find_first_database(lang, db_path)
        if not actual_db_path:
            logger.error("❌ No database found. Please specify a valid database path or run in remote mode.")
            logger.error("   Default search path: output/databases/{lang}/{project_name}/{database_dir}/")
            logger.error("   Or use: --db-path <path>")
            sys.exit(1)
        
        logger.info(f"Using database at: {actual_db_path}")
    
    try:
        # Step 2: Run CodeQL queries
        logger.info("\n[2/3] Running CodeQL Queries")
        logger.info("-" * 60)
        compile_and_run_codeql_queries(
            codeql_bin=get_codeql_path(),
            lang=lang,
            threads=threads,
            timeout=300
        )
    except CodeQLConfigError as e:
        logger.error(f"❌ Configuration error while running CodeQL queries: {e}")
        _log_exception_cause(e)
        logger.error("   Please check your CODEQL_PATH configuration.")
        sys.exit(1)
    except CodeQLExecutionError as e:
        logger.error(f"❌ Failed to execute CodeQL queries: {e}")
        _log_exception_cause(e)
        logger.error("   Please check your CodeQL installation and database files.")
        sys.exit(1)
    except CodeQLError as e:
        logger.error(f"❌ CodeQL error: {e}")
        _log_exception_cause(e)
        sys.exit(1)
    
    try:
        # Step 3: Classify results with LLM
        logger.info("\n[3/3] Classifying Results with LLM")
        logger.info("-" * 60)
        analyzer = IssueAnalyzer(lang=lang)
        analyzer.run()
    except LLMConfigError as e:
        logger.error(f"❌ LLM configuration error: {e}")
        _log_exception_cause(e)
        logger.error("   Please check your LLM configuration and API credentials in .env file.")
        sys.exit(1)
    except LLMApiError as e:
        logger.error(f"❌ LLM API error: {e}")
        _log_exception_cause(e)
        logger.error("   Please check your API key, network connection, and rate limits.")
        sys.exit(1)
    except LLMError as e:
        logger.error(f"❌ LLM error: {e}")
        _log_exception_cause(e)
        sys.exit(1)
    except CodeQLError as e:
        logger.error(f"❌ CodeQL error while reading database files: {e}")
        _log_exception_cause(e)
        logger.error("   This step reads CodeQL database files (YAML, ZIP, CSV) to prepare data for LLM analysis.")
        logger.error("   Please check your CodeQL databases and files are accessible.")
        sys.exit(1)
    except VulnhallaError as e:
        logger.error(f"❌ File system error while saving results: {e}")
        _log_exception_cause(e)
        logger.error("   This step writes analysis results to disk and creates output directories.")
        logger.error("   Please check file permissions and disk space.")
        sys.exit(1)
    
    # Pipeline completed
    logger.info("\n✅ Pipeline completed successfully!")
    logger.info("Results saved to: output/results/")


def print_usage() -> None:
    """Print usage information."""
    print("""
Vulnhalla Analysis Pipeline
========================

Usage:
    vulnhalla-analyze [OPTIONS] [MODE]

Modes:
    remote (default)    Fetch databases from GitHub and analyze
    local-db           Analyze existing local databases

Options:
    --lang <language>   Programming language (default: c)
                        Supported: c, cpp, c++, java, javascript, js, 
                        python, go, ruby, csharp, c#, typescript, ts
    
    --db-path <path>    Custom database path (local mode only)
                        Default: output/databases/{lang}/*

Examples:
    # Remote mode - Analyze top 100 repos (default: C/C++)
    vulnhalla-analyze

    # Remote mode - Analyze specific repository
    vulnhalla-analyze redis/redis

    # Remote mode - Analyze Java repositories
    vulnhalla-analyze --lang java

    # Remote mode - Analyze specific c repository
    vulnhalla-analyze --lang c redis/redis

    # Local mode - Analyze default local database (default: C/C++)
    vulnhalla-analyze local-db

    # Local mode - Analyze Java local database
    vulnhalla-analyze --lang java local-db

    # Local mode - Analyze custom database path
    vulnhalla-analyze local-db --db-path D:/custom/path/to/database

    # Local mode - Analyze custom Java database
    vulnhalla-analyze --lang java local-db --db-path D:/custom/java/db
""")


def main_analyze() -> None:
    """
    CLI entry point for the complete analysis pipeline.
    """
    parser = argparse.ArgumentParser(
        description="Vulnhalla Analysis Pipeline - CodeQL + LLM Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    # Positional arguments
    parser.add_argument(
        "mode",
        nargs="?",
        default="remote",
        choices=["remote", "local-db"],
        help="Analysis mode: 'remote' (fetch from GitHub) or 'local-db' (use existing databases)"
    )
    
    parser.add_argument(
        "repo",
        nargs="?",
        help="GitHub repository in format 'org/repo' (remote mode only)"
    )
    
    # Optional arguments
    parser.add_argument(
        "--lang",
        default="c",
        help=f"Programming language (default: c). Supported: {', '.join(SUPPORTED_LANGUAGES)}"
    )
    
    parser.add_argument(
        "--db-path",
        help="Custom database path for local mode (default: output/databases/{lang}/{project_name}/{database_dir})"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=16,
        help="Number of threads for CodeQL operations (default: 16)"
    )
    
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Show this help message and exit"
    )
    
    args = parser.parse_args()
    
    # Show help if requested
    if args.help:
        print_usage()
        sys.exit(0)
    
    # Validate repo argument (only for remote mode)
    if args.mode == "remote" and args.repo:
        if "/" not in args.repo:
            logger.error("❌ Error: Repository must be in format 'org/repo'")
            logger.error("   Example: vulnhalla-analyze redis/redis")
            logger.error("   Or run without repository to analyze top repositories")
            sys.exit(1)
    
    # Validate db-path argument (only for local mode)
    if args.mode == "local-db" and args.repo:
        logger.error("❌ Error: Cannot specify both 'local-db' mode and a repository")
        logger.error("   Use 'vulnhalla-analyze local-db' for local analysis")
        sys.exit(1)
    
    # Run pipeline
    analyze_pipeline(
        mode=args.mode,
        repo=args.repo,
        lang=args.lang,
        db_path=args.db_path,
        threads=args.threads
    )


if __name__ == '__main__':
    main_analyze()
