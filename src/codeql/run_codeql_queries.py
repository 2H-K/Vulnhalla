#!/usr/bin/env python3
"""
Compile and run CodeQL queries on CodeQL databases for a specific language.

Requires that CodeQL is installed or available under the CODEQL path.
By default, it compiles all .ql files under 'data/queries/<LANG>/tools' and
'data/queries/<LANG>/issues', then runs them on each CodeQL database located
in 'output/databases/<LANG>'.

Example:
    python src/codeql/run_codeql_queries.py
"""

import subprocess
import os

# Make sure your common_functions module is in your PYTHONPATH or same folder
from src.utils.common_functions import get_all_dbs
from src.utils.config import get_codeql_path


# Default locations/values
DEFAULT_CODEQL = get_codeql_path()
DEFAULT_LANG = "c"  # Mapped to data/queries/cpp for some tasks


def pre_compile_ql(file_name: str, threads: int, codeql_bin: str) -> None:
    """
    Pre-compile a single .ql file using CodeQL.

    Args:
        file_name (str): The path to the .ql query file.
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    """
    if not os.path.exists(file_name + "x"):
        subprocess.run(
            [
                codeql_bin,
                "query",
                "compile",
                file_name,
                f'--threads={threads}',
                "--precompile"
            ],
            check=True,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )


def compile_all_queries(queries_folder: str, threads: int, codeql_bin: str) -> None:
    """
    Recursively pre-compile all .ql files in a folder.

    Args:
        queries_folder (str): Directory containing .ql files (and possibly subdirectories).
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    """
    for subdir, dirs, files in os.walk(queries_folder):
        for file in files:
            if os.path.splitext(file)[1].lower() == ".ql":
                file_path = os.path.join(subdir, file)
                pre_compile_ql(file_path, threads, codeql_bin)


def run_one_query(
    query_file: str,
    curr_db: str,
    output_bqrs: str,
    output_csv: str,
    threads: int,
    codeql_bin: str
) -> None:
    """
    Execute a single CodeQL query on a specific database and export the results.

    Args:
        query_file (str): The path to the .ql file to run.
        curr_db (str): The path to the CodeQL database on which to run queries.
        output_bqrs (str): Where to write the intermediate BQRS output.
        output_csv (str): Where to write the CSV representation of the results.
        threads (int): Number of threads to use during query execution.
        codeql_bin (str): Full path to the 'codeql' executable.
    """
    # Run the query
    subprocess.run(
        [
            codeql_bin, "query", "run", query_file,
            f'--database={curr_db}',
            f'--output={output_bqrs}',
            f'--threads={threads}'
        ],
        check=True,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Decode BQRS to CSV
    subprocess.run(
        [
            codeql_bin, "bqrs", "decode", output_bqrs,
            '--format=csv', f'--output={output_csv}'
        ],
        check=True,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def run_queries_on_db(
    curr_db: str,
    tools_folder: str,
    queries_folder: str,
    threads: int,
    codeql_bin: str,
    timeout: int = 300
) -> None:
    """
    Execute all tool queries in 'tools_folder' individually on a given database,
    then run a bulk 'database analyze' with all queries in 'queries_folder'.

    Args:
        curr_db (str): The path to the CodeQL database.
        tools_folder (str): Folder containing individual .ql files to run.
        queries_folder (str): Folder containing .ql queries for bulk analysis.
        threads (int): Number of threads to use during query execution.
        codeql_bin (str): Full path to the 'codeql' executable.
        timeout (int, optional): Timeout in seconds for the bulk 'database analyze'.
            Defaults to 300.
    """
    # 1) Run each .ql in tools_folder individually
    if os.path.isdir(tools_folder):
        for file in os.listdir(tools_folder):
            if os.path.splitext(file)[1].lower() == ".ql":
                run_one_query(
                    os.path.join(tools_folder, file),
                    curr_db,
                    os.path.join(curr_db, os.path.splitext(file)[0] + ".bqrs"),
                    os.path.join(curr_db, os.path.splitext(file)[0] + ".csv"),
                    threads,
                    codeql_bin
                )
    else:
        print(f"Tools folder '{tools_folder}' not found. Skipping individual queries.")

    # 2) Run the entire queries folder in one go (bulk analysis)
    if os.path.isdir(queries_folder):
        subprocess.run(
            [
                codeql_bin,
                "database",
                "analyze",
                curr_db,
                queries_folder,
                f'--timeout={timeout}',
                '--format=csv',
                f'--output={os.path.join(curr_db, "issues.csv")}',
                f'--threads={threads}'
            ],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        print(f"Queries folder '{queries_folder}' not found. Skipping bulk analysis.")


def compile_and_run_codeql_queries(
    codeql_bin: str = DEFAULT_CODEQL,
    lang: str = DEFAULT_LANG,
    threads: int = 16,
    timeout: int = 300
) -> None:
    """
    Compile and run CodeQL queries on CodeQL databases for a specific language.

    1. Pre-compile all .ql files in the tools and queries folders.
    2. Enumerate all CodeQL DBs for the given language.
    3. Run each DB against both the 'tools' and 'issues' queries folders.

    Args:
        codeql_bin (str, optional): Full path to the 'codeql' executable. Defaults to DEFAULT_CODEQL.
        lang (str, optional): Language code. Defaults to 'c' (which maps to data/queries/cpp).
        threads (int, optional): Number of threads for compilation/execution. Defaults to 16.
        timeout (int, optional): Timeout in seconds for bulk analysis. Defaults to 300.
    """
    # Setup paths
    queries_subfolder = "cpp" if lang == "c" else lang
    queries_folder = os.path.join("data/queries", queries_subfolder, "issues")
    tools_folder = os.path.join("data/queries", queries_subfolder, "tools")
    dbs_folder = os.path.join("output/databases", lang)

    # Step 1: Pre-compile all queries
    compile_all_queries(tools_folder, threads, codeql_bin)
    compile_all_queries(queries_folder, threads, codeql_bin)

    # Step 2: List databases and run queries
    print("Running queries on each DB in", dbs_folder)
    dbs_path = get_all_dbs(dbs_folder)
    for curr_db in dbs_path:
        print("Processing DB:", curr_db)
        # If issues.csv was not generated yet, or FunctionTree.csv missing, run
        if (not os.path.exists(os.path.join(curr_db, "FunctionTree.csv")) or
                not os.path.exists(os.path.join(curr_db, "issues.csv"))):
            run_queries_on_db(
                curr_db,
                tools_folder,
                queries_folder,
                threads,
                codeql_bin,
                timeout
            )
        else:
            print("Output files already exist for this DB, skipping...")

    print("All databases processed.")


def main_cli() -> None:
    """
    CLI entry point for running codeql queries with defaults.
    """
    compile_and_run_codeql_queries(
        codeql_bin=DEFAULT_CODEQL,
        lang=DEFAULT_LANG,
        threads=16,
        timeout=300
    )


if __name__ == '__main__':
    main_cli()
