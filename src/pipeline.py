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
from pathlib import Path
from typing import Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.codeql.fetch_repos import fetch_codeql_dbs
from src.codeql.run_codeql_queries import compile_and_run_codeql_queries
from src.utils.config import get_codeql_path
from src.vulnhalla import IssueAnalyzer
from src.ui.ui_app import main as ui_main


def analyze_pipeline(repo: Optional[str] = None, lang: str = "c", threads: int = 16, open_ui: bool = True) -> None:
    """
    Run the complete Vulnhalla pipeline: fetch, analyze, classify, and optionally open UI.
    Args:
        repo: Optional GitHub repository name (e.g., "redis/redis"). If None, fetches top repos.
        lang: Programming language code. Defaults to "c".
        threads: Number of threads for CodeQL operations. Defaults to 16.
        open_ui: Whether to open the UI after completion. Defaults to True.
    """
    print("🚀 Starting Vulnhalla Analysis Pipeline")
    print("=" * 60)
    # Step 1: Fetch CodeQL databases
    print("\n[1/4] Fetching CodeQL Databases")
    print("-" * 60)
    if repo:
        print(f"Fetching database for: {repo}")
        fetch_codeql_dbs(lang=lang, threads=threads, single_repo=repo)
    else:
        print(f"Fetching top repositories for language: {lang}")
        fetch_codeql_dbs(lang=lang, max_repos=100, threads=4)
    # Step 2: Run CodeQL queries
    print("\n[2/4] Running CodeQL Queries")
    print("-" * 60)
    compile_and_run_codeql_queries(
        codeql_bin=get_codeql_path(),
        lang=lang,
        threads=threads,
        timeout=300
    )
    # Step 3: Classify results with LLM
    print("\n[3/4] Classifying Results with LLM")
    print("-" * 60)
    analyzer = IssueAnalyzer(lang=lang)
    analyzer.run()
    # Step 4: Open UI (if requested)
    if open_ui:
        print("\n[4/4] Opening UI")
        print("-" * 60)
        print("✅ Pipeline completed successfully!")
        print("Opening results UI...")
        ui_main()
    else:
        print("\n✅ Pipeline completed successfully!")
        print("View results with: python src/ui/ui_app.py")


def main_analyze() -> None:
    """
    CLI entry point for the complete analysis pipeline.
    Usage:
        vulnhalla-analyze                    # Analyze top 100 repos
        vulnhalla-analyze redis/redis        # Analyze specific repo
    """
    # Parse command line arguments
    repo = None
    if len(sys.argv) > 1:
        repo = sys.argv[1]
        if "/" not in repo:
            print("❌ Error: Repository must be in format 'org/repo'")
            print("   Example: python src/pipeline.py redis/redis")
            print("   Or run without arguments to analyze top repositories")
            sys.exit(1)
    analyze_pipeline(repo=repo)


if __name__ == '__main__':
    main_analyze()