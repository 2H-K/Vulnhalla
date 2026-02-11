"""
统一的路径标准化工具模块。

提供跨平台（Windows/Linux）的路径处理功能，用于处理CodeQL数据库中的
sourceLocationPrefix和文件路径，确保在各种操作系统环境下正确解析文件。
"""

from pathlib import Path, PurePosixPath
from typing import Tuple
import re


class PathNormalizer:
    """统一的路径标准化工具类"""
    
    # Windows 盘符正则
    DRIVE_LETTER_PATTERN = re.compile(r'^([A-Za-z]):[/\\]')
    
    @staticmethod
    def normalize_source_location_prefix(source_location_prefix: str) -> str:
        """
        标准化CodeQL数据库的sourceLocationPrefix。
        
        处理场景：
        - Linux: /absolute/path → absolute/path (去掉前导斜杠)
        - Windows: C:\path → C_/path (冒号转下划线，统一斜杠)
        
        Args:
            source_location_prefix: 原始的sourceLocationPrefix值
            
        Returns:
            标准化后的路径字符串
        """
        if not source_location_prefix:
            return ""
        
        # 统一斜杠方向
        normalized = source_location_prefix.replace("\\", "/")
        
        # 检测是否为Windows路径（包含盘符）
        if ":" in normalized:
            # Windows路径：将冒号替换为下划线
            normalized = normalized.replace(":", "_", 1)
        else:
            # Linux/Unix路径：去掉前导斜杠
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
        
        # 去掉引号
        normalized = file_path.replace("\"", "")
        
        # 统一斜杠方向
        normalized = normalized.replace("\\", "/")
        
        return normalized
    
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
    def build_zip_path(source_location_prefix: str, file_path: str) -> Tuple[str, str]:
        """
        构建用于从ZIP文件读取的路径。
        
        同时返回两种路径版本：
        1. 冒号版本（colon）：用于FunctionTree.csv等使用冒号的场景
        2. 下划线版本（underscore）：用于Windows ZIP内部路径
        
        Args:
            source_location_prefix: 数据库的sourceLocationPrefix
            file_path: 相对文件路径
            
        Returns:
            Tuple[str, str]: (path_version_colon, path_version_underscore)
        """
        # 标准化路径
        normalized_prefix = PathNormalizer.normalize_source_location_prefix(source_location_prefix)
        normalized_file = PathNormalizer.normalize_file_path(file_path)
        
        # 提取原始盘符
        drive_letter = PathNormalizer.extract_drive_letter(source_location_prefix)
        
        # 构建完整逻辑路径
        full_logical_path = f"{normalized_prefix}/{normalized_file}".replace("//", "/")
        
        # 冒号版本：保留冒号（用于FunctionTree.csv匹配）
        path_version_colon = full_logical_path
        
        # 下划线版本：冒号转下划线（用于ZIP文件读取）
        if drive_letter:
            # 确保盘符正确：移除可能的前导斜杠，然后添加盘符
            clean_path = full_logical_path.lstrip("/")
            path_version_underscore = f"{drive_letter}_/{clean_path}"
        else:
            path_version_underscore = full_logical_path.replace(":", "_", 1)
        
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
        
        # 提取纯文件名
        filename = PurePosixPath(file_path).name
        
        # 尝试提取相对路径（去掉可能的盘符前缀）
        if ":" in normalized:
            # Windows路径：提取冒号后面的部分
            parts = normalized.split(":/", 1)
            relative_path = parts[1] if len(parts) > 1 else ""
        elif normalized.startswith("/"):
            # Linux绝对路径：去掉前导斜杠
            relative_path = normalized[1:]
        else:
            # 已经是相对路径
            relative_path = normalized
        
        return relative_path, filename
    
    @staticmethod
    def normalize_zip_path(file_path_in_zip: str) -> str:
        """
        标准化ZIP文件内部的路径。
        
        处理场景：
        - 统一斜杠方向
        - 处理丢失盘符的情况
        - 冒号转下划线（Windows ZIP格式）
        
        Args:
            file_path_in_zip: ZIP文件内部的原始路径
            
        Returns:
            标准化后的路径
        """
        if not file_path_in_zip:
            return ""
        
        # 统一斜杠方向
        processed_path = file_path_in_zip.replace("\\", "/")
        
        # 如果路径以 :/ 开头，说明盘符丢失，尝试恢复
        if processed_path.startswith(":/"):
            # 移除前面的 :/，添加默认盘符 F
            processed_path = "F_/" + processed_path.lstrip(":/")
        
        # 确保冒号转为下划线以匹配 Windows 版 CodeQL ZIP 结构
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
    
    # 去掉引号
    cleaned = file_path.replace("\"", "").strip()
    
    # 如果是绝对路径（以/开头），去掉前导斜杠
    # 注意：这个逻辑可能需要根据实际情况调整
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    
    # 返回标准化后的路径
    return PathNormalizer.normalize_zip_path(cleaned)
