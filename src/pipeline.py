#!/usr/bin/env python3
"""
Pipeline orchestration for Vulnhalla.
This module coordinates the complete analysis pipeline:
1. Fetch CodeQL databases
2. Run CodeQL queries
3. Classify results with LLM
4. Open UI (optional)
"""
import sys
import argparse
from pathlib import Path
from typing import Optional

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
from src.ui.ui_app import main as ui_main

# Initialize logging
setup_logging()
logger = get_logger(__name__)


def _log_exception_cause(e: Exception) -> None:
    """
    Log the cause of an exception if available and not already included in the exception message.
    Checks both e.cause (if set via constructor) and e.__cause__ (if set via 'from e').
    """
    cause = getattr(e, 'cause', None) or getattr(e, '__cause__', None)
    if cause:
        # Only log cause if it's not already included in the exception message
        cause_str = str(cause)
        error_str = str(e)
        if cause_str not in error_str:
            logger.error(f"   Cause: {cause}")


def analyze_pipeline(repo: Optional[str] = None, lang: str = "c", threads: int = 16, open_ui: bool = True, use_local_db: bool = False, db_dir: Optional[str] = None) -> None:
    """
    Run the complete Vulnhalla pipeline: fetch, analyze, classify, and optionally open UI.

    Args:
        repo: Optional GitHub repository name (e.g., "redis/redis"). If None, fetches top repos.
        lang: Programming language code. Defaults to "c".
        threads: Number of threads for CodeQL operations. Defaults to 16.
        open_ui: Whether to open the UI after completion. Defaults to True.
        use_local_db: Whether to use local databases instead of fetching. Defaults to False.
        db_dir: Database directory name when using local databases. Defaults to None.

    Note:
        This function catches and handles all exceptions internally, logging errors
        and exiting with code 1 on failure. It does not raise exceptions.
    """
    logger.info("🚀 Starting Vulnhalla Analysis Pipeline")
    logger.info("=" * 60)
    
    try:
        # Validate configuration before starting
        validate_and_exit_on_error()
    except (CodeQLConfigError, LLMConfigError, VulnhallaError) as e:
        # Format error message for display
        message = f"""
⚠️ Configuration Validation Failed
============================================================
{str(e)}
============================================================
Please fix the configuration errors above and try again.
See README.md for configuration reference.
"""
        logger.error(message)
        _log_exception_cause(e)
        sys.exit(1)
    
    if not use_local_db:
        try:
            # Step 1: Fetch CodeQL databases
            logger.info("\n[1/4] Fetching CodeQL Databases")
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
        logger.info("\n[1/4] Using Local CodeQL Databases")
        logger.info("-" * 60)
        logger.info("Skipping fetch step, using local databases.")

        # Check if local database exists
        if db_dir:
            db_path = Path("output/databases") / lang / db_dir
            if not db_path.exists():
                logger.error(f"❌ Local database path not found: {db_path}")
                logger.error("   Please manually place the CodeQL database in the correct location.")
                sys.exit(1)
        else:
            logger.error("❌ Local database mode requires specifying a database directory.")
            sys.exit(1)

    try:
        # Step 2: Run CodeQL queries
        logger.info("\n[2/4] Running CodeQL Queries")
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
        logger.info("\n[3/4] Classifying Results with LLM")
        logger.info("-" * 60)
        analyzer = IssueAnalyzer(lang=lang, db_dir=db_dir if use_local_db else None)
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
    
    # Step 4: Open UI
    if open_ui:
        logger.info("\n[4/4] Opening UI")
        logger.info("-" * 60)
        logger.info("✅ Pipeline completed successfully!")
        logger.info("Opening results UI...")
        ui_main()
    else:
        logger.info("\n✅ Pipeline completed successfully!")
        logger.info("View results with: python src/ui/ui_app.py")


def main_analyze() -> None:
    """
    CLI entry point for the complete analysis pipeline.
    Usage:
        vulnhalla-analyze                           # Analyze top 100 repos
        vulnhalla-analyze redis/redis               # Analyze specific repo
        vulnhalla-analyze local-db <db_dir>         # Use local database in specified directory
        --language, -l: Programming language (c, java, or javascript, default: c)
    """
    parser = argparse.ArgumentParser(description="Vulnhalla Analysis Pipeline")
    parser.add_argument("command", nargs="?", help="Command: 'local-db' or GitHub repository name (e.g., 'redis/redis')")
    parser.add_argument("db_dir", nargs="?", help="Database directory name when using local-db")
    parser.add_argument("--language", "-l", default="c", choices=["c", "java", "javascript"],
                       help="Programming language (default: c)")

    args = parser.parse_args()

    # Parse arguments
    repo = None
    db_dir = None
    use_local_db = False

    if args.command == "local-db":
        use_local_db = True
        db_dir = args.db_dir
        if not db_dir:
            logger.error("❌ Error: When using local-db, you must specify a database directory name")
            logger.error("   Example: python src/pipeline.py local-db redis --language c")
            sys.exit(1)
    elif args.command:
        repo = args.command
        if "/" not in repo:
            logger.error("❌ Error: Repository must be in format 'org/repo'")
            logger.error("   Example: python src/pipeline.py redis/redis")
            logger.error("   Or run without arguments to analyze top repositories")
            sys.exit(1)
    # If no command, repo remains None for top repos

    analyze_pipeline(repo=repo, lang=args.language, use_local_db=use_local_db, db_dir=db_dir)


if __name__ == '__main__':
    main_analyze()