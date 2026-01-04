"""
Common utility functions for Vulnhalla.

This module provides reusable helpers for file and path handling,
working with CodeQL database directories, and other small I/O utilities
that are shared across multiple parts of the project.
"""

from pathlib import Path
import zipfile
import yaml
from typing import Any, Dict, List 

from src.utils.exceptions import VulnhallaError, CodeQLError


def read_file(file_name: str) -> str:
    """
    Read text from a file (UTF-8).

    Args:
        file_name (str): The path to the file to be read.

    Returns:
        str: The contents of the file, decoded as UTF-8.
    
    Raises:
        VulnhallaError: If file cannot be read (not found, permission denied, encoding error).
    """
    try:
        with Path(file_name).open("r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError as e:
        raise VulnhallaError(f"File not found: {file_name}") from e
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied reading file: {file_name}") from e
    except UnicodeDecodeError as e:
        raise VulnhallaError(f"Failed to decode file as UTF-8: {file_name}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while reading file: {file_name}") from e


def write_file_text(file_name: str, data: str) -> None:
    """
    Write text data to a file (UTF-8).

    Args:
        file_name (str): The path to the file to be written.
        data (str): The string data to write to the file.
    
    Raises:
        VulnhallaError: If file cannot be written (permission denied, disk full, etc.).
    """
    try:
        with Path(file_name).open("w", encoding="utf-8") as f:
            f.write(data)
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied writing file: {file_name}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while writing file: {file_name}") from e


def write_file_ascii(file_name: str, data: str) -> None:
    """
    Write data to a file in ASCII mode (ignores errors).
    Useful for contexts similar to the original 'wb' approach
    where non-ASCII characters are simply dropped.

    Args:
        file_name (str): The path to the file to be written.
        data (str): The string data to write (non-ASCII chars ignored).
    
    Raises:
        VulnhallaError: If file cannot be written (permission denied, disk full, etc.).
    """
    try:
        with Path(file_name).open("wb") as f:
            f.write(data.encode("ascii", "ignore"))
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied writing file: {file_name}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while writing file: {file_name}") from e


def get_all_dbs(dbs_folder: str) -> List[str]:
    """
    Return a list of all CodeQL database paths under `dbs_folder`.

    Args:
        dbs_folder (str): The folder containing CodeQL databases.

    Returns:
        List[str]: A list of file-system paths pointing to valid CodeQL databases.
    
    Raises:
        CodeQLError: If database folder cannot be accessed (permission denied, not found, etc.).
    """
    try:
        dbs_path = []
        dbs_folder_path = Path(dbs_folder)
        for folder in dbs_folder_path.iterdir():
            if folder.is_dir():
                for sub_folder in folder.iterdir():
                    curr_db_path = sub_folder
                    if (curr_db_path / "codeql-database.yml").exists():
                        dbs_path.append(str(curr_db_path))
        return dbs_path
    except PermissionError as e:
        raise CodeQLError(f"Permission denied accessing database folder: {dbs_folder}") from e
    except OSError as e:
        raise CodeQLError(f"OS error while accessing database folder: {dbs_folder}") from e


def read_file_lines_from_zip(zip_path: str, file_path_in_zip: str) -> str:
    # 路径自愈逻辑
    processed_path = file_path_in_zip.replace("\\", "/")
    
    # 如果路径以 :/ 开头，说明盘符丢失，尝试恢复或清理
    if processed_path.startswith(":/"):
        # 移除前面的 :/，使其变为 Code_Audit/...
        processed_path = processed_path.lstrip(":/")
        # 如果能从 zip_path 猜到盘符（通常是 F_ 或 D_），可以补全，
        # 但 CodeQL ZIP 内部通常是 [盘符]_/ 开头，所以直接补 F_ 是最常见的
        processed_path = "F_/" + processed_path
    
    # 核心：确保冒号转为下划线以匹配 Windows 版 CodeQL ZIP 结构
    if ":" in processed_path:
        processed_path = processed_path.replace(":", "_", 1)

    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            # 尝试直接读取
            try:
                with z.open(processed_path) as file:
                    return file.read().decode('utf-8')
            except KeyError:
                # 备选：如果还是找不到，尝试去掉所有前导斜杠
                alt_path = processed_path.lstrip("/")
                with z.open(alt_path) as file:
                    return file.read().decode('utf-8')
    except Exception as e:
        # 这里会抛出包含实际尝试路径的错误，配合增强后的 Logger 非常好定位
        raise CodeQLError(f"ZIP Error: Could not find {processed_path} in {zip_path}. Inner error: {str(e)}")

def read_yml(file_path: str) -> Dict[str, Any]:
    """
    Read and parse a YAML file, returning its data as a Python dictionary.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        Dict[str, Any]: The YAML data as a dictionary.
    
    Raises:
        VulnhallaError: If file cannot be read or YAML parsing fails.
    """
    try:
        with Path(file_path).open('r', encoding="utf-8") as file:
            return yaml.safe_load(file)
    except FileNotFoundError as e:
        raise VulnhallaError(f"YAML file not found: {file_path}") from e
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied reading YAML file: {file_path}") from e
    except yaml.YAMLError as e:
        raise VulnhallaError(f"Failed to parse YAML file: {file_path}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while reading YAML file: {file_path}") from e