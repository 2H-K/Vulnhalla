#!/usr/bin/env python3

"""
example.py
----------
Example usage of Vulnhalla - demonstrates a full pipeline run:
1) Fetch CodeQL databases (from fetch_repos.py),
2) Run CodeQL queries (from run_codeql_queries.py),
3) Analyze results with LLM (from vulnhalla.py).
"""

import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.codeql.fetch_repos import fetch_codeql_dbs
from src.codeql.run_codeql_queries import compile_and_run_codeql_queries, DEFAULT_LANG
from src.vulnhalla import IssueAnalyzer
from src.utils.config import get_codeql_path
from src.ui.ui_app import main as ui_main


def main():
    print("Starting Vulnhalla pipeline... This may take a few minutes.")
    print()
    # 1) Fetch CodeQL database
    print("[1/3] Fetching CodeQL DBs")
    fetch_codeql_dbs(
        lang="c",          # Or use fetch_repos.LANG if set
        threads=4,        # Higher threads may exceed GitHub rate limits. Add a GitHub token if you need higher throughput.
        
        single_repo="videolan/vlc"
    )
    fetch_codeql_dbs(lang="c", threads=16, single_repo="redis/redis")

    # 2) Run CodeQL queries on all downloaded databases
    print("\n[2/3] Running CodeQL Queries")
    compile_and_run_codeql_queries(
        codeql_bin=get_codeql_path(),
        lang="c",
        threads=16,
        timeout=300
    )

    # 3) Build/Analyze CodeQL results
    print("\n[3/3] Building and Analyzing Results")
    # Load configuration from .env file (create .env from .env.example)
    # Or use: analyzer = IssueAnalyzer(lang="c", api_key="your-api-key")
    analyzer = IssueAnalyzer(lang="c")
    analyzer.run()

    print("\n✅ Pipeline completed successfully!")
    print("Opening results UI...")
    ui_main()

if __name__ == "__main__":
    main()
