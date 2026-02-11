#!/usr/bin/env python3
"""
Compile and run CodeQL queries on CodeQL databases for a specific language.

Requires that CodeQL is installed or available under the CODEQL path.
By default, it compiles all .ql files under 'data/queries/<LANG>/tools' and
'data/queries/<LANG>/issues', then runs them on each CodeQL database located
in 'output/databases/<LANG>'.

Example:
    python src/codeql/run_codeql_queries.py -l java --db-dir webgoat
"""

import subprocess
import argparse
import sys
import os
from pathlib import Path

# 确保项目根目录在 Python 路径中
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.common_functions import get_all_dbs
from src.utils.config import get_codeql_path
from src.utils.logger import get_logger
from src.utils.exceptions import CodeQLError, CodeQLConfigError, CodeQLExecutionError

logger = get_logger(__name__)


# Default locations/values
DEFAULT_CODEQL = get_codeql_path()
DEFAULT_LANG = "c"  # Mapped to data/queries/cpp for some tasks

# 语言映射表：支持多种语言别名
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

# 支持的语言列表
SUPPORTED_LANGUAGES = ["c", "java", "javascript", "python", "go", "ruby", "csharp", "typescript"]

def normalize_language(lang: str) -> str:
    """
    规范化语言名称为内部 CodeQL 语言代码。
    
    参数:
        lang: 语言名称 (例如: "c++", "cpp", "java", "javascript")
    
    返回:
        规范化的语言代码 (例如: "c", "java", "javascript")
    """
    lang_lower = lang.lower().strip()
    
    if lang_lower in LANGUAGE_MAPPING:
        return LANGUAGE_MAPPING[lang_lower]
    
    if lang_lower in SUPPORTED_LANGUAGES:
        return lang_lower
    
    raise ValueError(f"不支持的语言: '{lang}'. 支持的语言: {', '.join(SUPPORTED_LANGUAGES)}")


def pre_compile_ql(file_name: str, threads: int, codeql_bin: str) -> None:
    """
    Pre-compile a single .ql file using CodeQL.

    Args:
        file_name (str): The path to the .ql query file.
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query compilation fails.
    """
    qlx_path = Path(str(file_name) + "x")
    if not qlx_path.exists():
        try:
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
        except FileNotFoundError as e:
            raise CodeQLConfigError(
                f"CodeQL executable not found: {codeql_bin}. "
                "Please check your CODEQL_PATH configuration."
            ) from e
        except subprocess.CalledProcessError as e:
            raise CodeQLExecutionError(
                f"Failed to compile query {file_name}: CodeQL returned exit code {e.returncode}"
            ) from e


def compile_all_queries(queries_folder: str, threads: int, codeql_bin: str) -> None:
    """
    Recursively pre-compile all .ql files in a folder.

    Args:
        queries_folder (str): Directory containing .ql files (and possibly subdirectories).
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query compilation fails.
    """
    queries_folder_path = Path(queries_folder)
    for file_path in queries_folder_path.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() == ".ql":
            pre_compile_ql(str(file_path), threads, codeql_bin)


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
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query execution or BQRS decoding fails.
    """
    # Run the query
    try:
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
    except FileNotFoundError as e:
        raise CodeQLConfigError(
            f"CodeQL executable not found: {codeql_bin}. "
            "Please check your CODEQL_PATH configuration."
        ) from e
    except subprocess.CalledProcessError as e:
        raise CodeQLExecutionError(
            f"Failed to run query {query_file} on database {curr_db}: "
            f"CodeQL returned exit code {e.returncode}"
        ) from e

    # Decode BQRS to CSV
    try:
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
    except subprocess.CalledProcessError as e:
        raise CodeQLExecutionError(
            f"Failed to decode BQRS file {output_bqrs} to CSV: "
            f"CodeQL returned exit code {e.returncode}"
        ) from e


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
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query execution or database analysis fails.
    """
    # 1) Run each .ql in tools_folder individually
    tools_folder_path = Path(tools_folder)
    if tools_folder_path.is_dir():
        for file_path in tools_folder_path.iterdir():
            if file_path.is_file() and file_path.suffix.lower() == ".ql":
                file_stem = file_path.stem
                run_one_query(
                    str(file_path),
                    curr_db,
                    str(Path(curr_db) / f"{file_stem}.bqrs"),
                    str(Path(curr_db) / f"{file_stem}.csv"),
                    threads,
                    codeql_bin
                )
    else:
        logger.warning(f"Tools folder '{tools_folder}' not found. Skipping individual queries.")

    # 2) Run the entire queries folder in one go (bulk analysis)
    queries_folder_path = Path(queries_folder)
    if queries_folder_path.is_dir():
        try:
            subprocess.run(
                [
                    codeql_bin,
                    "database",
                    "analyze",
                    curr_db,
                    queries_folder,
                    f'--timeout={timeout}',
                    '--format=csv',
                    f'--output={str(Path(curr_db) / "issues.csv")}',
                    f'--threads={threads}'
                ],
                check=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except FileNotFoundError as e:
            raise CodeQLConfigError(
                f"CodeQL executable not found: {codeql_bin}. "
                "Please check your CODEQL_PATH configuration."
            ) from e
        except subprocess.CalledProcessError as e:
            raise CodeQLExecutionError(
                f"Failed to analyze database {curr_db} with queries from {queries_folder}: "
                f"CodeQL returned exit code {e.returncode}"
            ) from e
    else:
        logger.warning(f"Queries folder '{queries_folder}' not found. Skipping bulk analysis.")


def compile_and_run_codeql_queries(
    codeql_bin: str = DEFAULT_CODEQL,
    lang: str = DEFAULT_LANG,
    threads: int = 16,
    timeout: int = 300,
    db_dir: str = None
) -> None:
    """
    Compile and run CodeQL queries on CodeQL databases for a specific language.

    1. Pre-compile all .ql files in the tools and queries folders.
    2. Enumerate all CodeQL DBs for the given language.
    3. Run each DB against both the 'tools' and 'issues' queries folders.

    参数:
        codeql_bin (str, optional): Full path to the 'codeql' executable. Defaults to DEFAULT_CODEQL.
        lang (str, optional): Language code. Defaults to 'c' (which maps to data/queries/cpp).
        threads (int, optional): Number of threads for compilation/execution. Defaults to 16.
        timeout (int, optional): Timeout in seconds for bulk analysis. Defaults to 300.
        db_dir (str, optional): Specific database directory to process. If None, processes all databases.
    
    异常:
        CodeQLConfigError: If CodeQL executable not found (from compilation or query execution).
        CodeQLExecutionError: If query compilation or execution fails.
    """
    # 规范化语言代码
    try:
        lang = normalize_language(lang)
    except ValueError as e:
        logger.error(f"❌ {e}")
        sys.exit(1)
    
    # Setup paths
    queries_subfolder = "cpp" if lang == "c" else lang
    queries_folder = str(Path("data/queries") / queries_subfolder / "issues")
    tools_folder = str(Path("data/queries") / queries_subfolder / "tools")
    
    # 确定数据库文件夹路径
    if db_dir:
        # 如果指定了 db_dir，只处理指定的数据库目录
        dbs_folder = str(Path("output/databases") / lang / db_dir)
    else:
        # 否则处理所有数据库
        dbs_folder = str(Path("output/databases") / lang)

    logger.info("🚀 开始运行 CodeQL 查询")
    logger.info("=" * 60)
    logger.info(f"语言: {lang}")
    logger.info(f"数据库路径: {dbs_folder}")
    logger.info("")
    
    # Step 1: Pre-compile all queries
    logger.info("[1/2] 预编译查询文件")
    logger.info("-" * 60)
    compile_all_queries(tools_folder, threads, codeql_bin)
    compile_all_queries(queries_folder, threads, codeql_bin)

    # Step 2: List databases and run queries
    logger.info("")
    logger.info("[2/2] 在数据库上运行查询")
    logger.info("-" * 60)
    logger.info(f"运行查询: {dbs_folder}")
    
    # List what's in the folder for debugging
    try:
        dbs_folder_path = Path(dbs_folder)
        if not dbs_folder_path.exists():
            logger.error(f"❌ 数据库文件夹不存在: {dbs_folder}")
            logger.error("   请确保数据库已放置在正确的位置。")
            return
            
        contents = list(dbs_folder_path.iterdir())
        if len(contents) == 0:
            logger.warning(f"数据库文件夹 '{dbs_folder}' 为空。没有数据库需要处理。")
            return
        logger.debug(f"在数据库文件夹中发现 {len(contents)} 个项目: {[str(c) for c in contents]}")
    except OSError as e:
        logger.warning(f"无法访问数据库文件夹 '{dbs_folder}': {e}. 没有数据库需要处理。")
        return
    
    # 获取数据库路径列表
    if db_dir:
        # 如果指定了 db_dir，尝试多种方式查找数据库
        dbs_path = []
        
        # 方式1: 直接检查指定路径是否包含 codeql-database.yml
        if (dbs_folder_path / "codeql-database.yml").exists():
            dbs_path.append(str(dbs_folder_path))
            logger.info(f"在指定路径找到数据库: {dbs_folder_path}")
        else:
            # 方式2: 递归搜索指定目录下的所有数据库
            for root, dirs, files in os.walk(str(dbs_folder_path)):
                if 'codeql-database.yml' in files:
                    dbs_path.append(root)
                    logger.info(f"递归找到数据库: {root}")
            
            if not dbs_path:
                logger.warning(f"在 '{dbs_folder}' 中未找到包含 codeql-database.yml 的数据库目录。")
    else:
        # 使用通用方法获取所有数据库
        dbs_path = get_all_dbs(dbs_folder)
    
    if len(dbs_path) == 0:
        logger.warning(f"在 '{dbs_folder}' 中未找到有效的数据库。")
        logger.warning("期望结构: <dbs_folder>/<repo_name>/<db_name>/codeql-database.yml")
        logger.warning("请确保数据库已正确下载和解压。")
        return
    
    for curr_db in dbs_path:
        logger.info(f"处理数据库: {curr_db}")
        
        # Check if database folder is empty
        curr_db_path = Path(curr_db)
        if curr_db_path.is_dir():
            try:
                if len(list(curr_db_path.iterdir())) == 0:
                    logger.warning(f"数据库文件夹 '{curr_db}' 为空。跳过查询。")
                    continue
            except OSError:
                logger.warning(f"无法访问数据库文件夹 '{curr_db}'。跳过。")
                continue
        
        # If issues.csv was not generated yet, or FunctionTree.csv missing, run
        if (not (curr_db_path / "FunctionTree.csv").exists() or
                not (curr_db_path / "issues.csv").exists()):
            run_queries_on_db(
                curr_db,
                tools_folder,
                queries_folder,
                threads,
                codeql_bin,
                timeout
            )
        else:
            logger.info("输出文件已存在，跳过...")

    logger.info("")
    logger.info("✅ 所有数据库处理完成！")


def main_cli() -> None:
    """
    命令行入口点，用于运行 CodeQL 查询。
    
    使用方法:
        python src/codeql/run_codeql_queries.py -l java --db-dir webgoat
        python src/codeql/run_codeql_queries.py --lang cpp --threads 8
    """
    parser = argparse.ArgumentParser(
        description="编译并运行 CodeQL 查询，分析指定语言的代码数据库。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    # 分析 Java 数据库 (默认使用 output/databases/java 下的所有数据库)
    python -m src.codeql.run_codeql_queries -l java
    
    # 分析特定的 Java 数据库目录
    python -m src.codeql.run_codeql_queries -l java --db-dir webgoat
    
    # 分析 C++ 数据库，使用 8 个线程
    python -m src.codeql.run_codeql_queries -l cpp --threads 8
        """
    )
    
    parser.add_argument(
        "--language", "-l",
        type=str,
        default="c",
        help="编程语言 (默认: c). 支持: c, cpp, c++, java, javascript, js, python, go, ruby, csharp, c#, typescript, ts"
    )
    
    parser.add_argument(
        "--db-dir",
        type=str,
        default=None,
        help="特定的数据库目录名称。如果不指定，将处理该语言下所有数据库。"
    )
    
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=16,
        help="编译和执行时使用的线程数 (默认: 16)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="批量分析的超时时间（秒）(默认: 300)"
    )
    
    args = parser.parse_args()
    
    # 运行查询
    compile_and_run_codeql_queries(
        codeql_bin=DEFAULT_CODEQL,
        lang=args.language,
        threads=args.threads,
        timeout=args.timeout,
        db_dir=args.db_dir
    )


if __name__ == '__main__':
    # Initialize logging
    from src.utils.logger import setup_logging
    setup_logging()
    
    main_cli()
