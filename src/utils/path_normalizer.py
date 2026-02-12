"""
统一的路径标准化工具模块。

提供跨平台（Windows/Linux）的路径处理功能，用于处理CodeQL数据库中的
sourceLocationPrefix和文件路径，确保在各种操作系统环境下正确解析文件。
"""

from pathlib import Path, PurePosixPath
from typing import Tuple, Optional
import re


class PathNormalizer:
    """统一的路径标准化工具类"""

    # Windows 盘符正则
    DRIVE_LETTER_PATTERN = re.compile(r'^([A-Za-z]):[/\\]')

    @staticmethod
    def extract_path_scheme(file_path: str) -> Tuple[str, str]:
        """
        提取并移除路径前缀（relative:// 或 file://）。

        Args:
            file_path: 原始路径

        Returns:
            Tuple[str, str]: (scheme, stripped_path)
        """
        if not file_path:
            return "", ""

        for scheme in ("relative://", "file://"):
            if file_path.startswith(scheme):
                return scheme, file_path[len(scheme):]

        return "", file_path

    @staticmethod
    def normalize_source_location_prefix(source_location_prefix: str) -> str:
        """
        标准化CodeQL数据库的sourceLocationPrefix。

        处理场景：
        - Linux: /absolute/path → absolute/path (去掉前导斜杠)
        - Windows: C:\path → C_/path (冒号转下划线，统一斜杠)
        - 带 scheme: file:///... 或 relative:///...

        Args:
            source_location_prefix: 原始的sourceLocationPrefix值

        Returns:
            标准化后的路径字符串
        """
        if not source_location_prefix:
            return ""

        normalized = PathNormalizer.normalize_file_path(source_location_prefix)
        _, normalized = PathNormalizer.extract_path_scheme(normalized)

        if ":" in normalized:
            normalized = normalized.replace(":", "_", 1)
        else:
            if normalized.startswith("/"):
                normalized = normalized[1:]

        return normalized

    @staticmethod
    def normalize_file_path(file_path: str) -> str:
        """
        标准化文件路径（去掉引号，统一分隔符）。

        Args:
            file_path: 原始文件路径

        Returns:
            标准化后的文件路径
        """
        if not file_path:
            return ""

        normalized = file_path.replace("\"", "")
        normalized = normalized.replace("\\", "/")
        return normalized

    @staticmethod
    def normalize_reference_path(file_path: str, path_type: Optional[str] = None) -> Tuple[str, str]:
        """
        标准化CodeQL引用路径（issues.csv或bracket reference）。

        Args:
            file_path: 原始路径
            path_type: 可能的scheme（relative:// 或 file://）

        Returns:
            Tuple[str, str]: (normalized_path, effective_scheme)
        """
        normalized = PathNormalizer.normalize_file_path(file_path)
        inferred_scheme, normalized = PathNormalizer.extract_path_scheme(normalized)
        effective_scheme = path_type or inferred_scheme

        if effective_scheme == "relative://":
            normalized = normalized.lstrip("/")

        return normalized, effective_scheme

    @staticmethod
    def extract_drive_letter(source_location_prefix: str) -> str:
        """
        从sourceLocationPrefix中提取盘符。

        Args:
            source_location_prefix: 原始的sourceLocationPrefix值

        Returns:
            盘符字母（如 "C"），如果没有盘符则返回空字符串
        """
        if not source_location_prefix:
            return ""

        match = PathNormalizer.DRIVE_LETTER_PATTERN.match(source_location_prefix)
        if match:
            return match.group(1).upper()

        return ""

    @staticmethod
    def is_windows_absolute(path: str) -> bool:
        """判断是否为Windows绝对路径。"""
        if not path:
            return False
        return bool(PathNormalizer.DRIVE_LETTER_PATTERN.match(path))

    @staticmethod
    def build_zip_path(source_location_prefix: str, file_path: str, path_type: Optional[str] = None) -> Tuple[str, str]:
        """
        构建用于从ZIP文件读取的路径。

        同时返回两种路径版本：
        1. 冒号版本（colon）：用于FunctionTree.csv等使用冒号的场景
        2. 下划线版本（underscore）：用于Windows ZIP内部路径

        Args:
            source_location_prefix: 数据库的sourceLocationPrefix
            file_path: 文件路径（可能包含relative:// 或 file://）
            path_type: 显式路径类型（可选）

        Returns:
            Tuple[str, str]: (path_version_colon, path_version_underscore)
        """
        normalized_file, effective_scheme = PathNormalizer.normalize_reference_path(file_path, path_type)

        # 如果是绝对路径，直接处理
        if PathNormalizer.is_windows_absolute(normalized_file):
            path_version_colon = normalized_file
            path_version_underscore = PathNormalizer.normalize_zip_path(normalized_file)
            return path_version_colon, path_version_underscore

        is_absolute_unix = normalized_file.startswith("/")
        if is_absolute_unix:
            normalized_file = normalized_file.lstrip("/")

        normalized_prefix = PathNormalizer.normalize_source_location_prefix(source_location_prefix)

        if normalized_prefix and effective_scheme == "relative://":
            full_logical_path = f"{normalized_prefix}/{normalized_file}".replace("//", "/")
        elif normalized_prefix and not PathNormalizer.is_windows_absolute(normalized_file) and not normalized_file.startswith(normalized_prefix):
            # issues.csv可能没有带scheme，但仍是相对路径
            full_logical_path = f"{normalized_prefix}/{normalized_file}".replace("//", "/")
        else:
            full_logical_path = normalized_file


        drive_letter = PathNormalizer.extract_drive_letter(source_location_prefix)
        if drive_letter and full_logical_path.startswith(f"{drive_letter}_/"):
            path_version_colon = full_logical_path.replace("_", ":", 1)
        else:
            path_version_colon = full_logical_path

        path_version_underscore = PathNormalizer.normalize_zip_path(full_logical_path)

        return path_version_colon, path_version_underscore

    @staticmethod
    def build_function_tree_lookup_path(file_path: str) -> Tuple[str, str]:
        """
        构建用于在FunctionTree.csv中查找的路径。

        Args:
            file_path: 原始文件路径（可能包含Windows或Linux格式）

        Returns:
            Tuple[str, str]: (relative_path, filename) - 用于匹配的路径和纯文件名
        """
        normalized = PathNormalizer.normalize_file_path(file_path)
        _, normalized = PathNormalizer.extract_path_scheme(normalized)

        filename = PurePosixPath(normalized).name

        if ":" in normalized:
            parts = normalized.split(":/", 1)
            relative_path = parts[1] if len(parts) > 1 else ""
        elif normalized.startswith("/"):
            relative_path = normalized[1:]
        else:
            relative_path = normalized

        return relative_path, filename

    @staticmethod
    def normalize_zip_path(file_path_in_zip: str) -> str:
        """
        标准化ZIP文件内部的路径。

        处理场景：
        - 统一斜杠方向
        - 处理丢失盘符的情况
        - 去掉前导斜杠
        - 冒号转下划线（Windows ZIP格式）

        Args:
            file_path_in_zip: ZIP文件内部的原始路径

        Returns:
            标准化后的路径
        """
        if not file_path_in_zip:
            return ""

        processed_path = file_path_in_zip.replace("\\", "/")

        if processed_path.startswith("/"):
            processed_path = processed_path.lstrip("/")

        if processed_path.startswith(":/"):
            processed_path = "F_/" + processed_path.lstrip(":/")

        if ":" in processed_path:
            processed_path = processed_path.replace(":", "_", 1)

        return processed_path


def extract_function_lines_path(file_path: str) -> str:
    """
    从FunctionTree.csv的file字段提取可用于ZIP读取的路径。

    这个函数专门处理FunctionTree.csv中存储的路径格式，
    移除引号并处理前导斜杠问题。

    Args:
        file_path: FunctionTree.csv中的file字段值

    Returns:
        可用于read_file_lines_from_zip的路径
    """
    if not file_path:
        return ""

    cleaned = file_path.replace("\"", "").strip()

    if cleaned.startswith("/"):
        cleaned = cleaned[1:]

    return PathNormalizer.normalize_zip_path(cleaned)
