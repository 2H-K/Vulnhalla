#!/usr/bin/env python3
"""
Centralized logging configuration for Vulnhalla using loguru.
"""

import sys
import os
from pathlib import Path
from typing import Optional

from loguru import logger

_logging_initialized = False


def reset_logging() -> None:
    """Reset logging state."""
    global _logging_initialized
    logger.remove()
    _logging_initialized = False


def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
    json_format: bool = False,
    simple_format: bool = False
) -> None:
    """Configure logging using loguru."""
    global _logging_initialized
    
    if _logging_initialized:
        return
    
    logger.remove()
    
    level = log_level or os.getenv("LOG_LEVEL", "INFO").upper()
    log_file_path = log_file or os.getenv("LOG_FILE")
    log_format_str = log_format or os.getenv("LOG_FORMAT", "default")
    use_verbose = os.getenv("LOG_VERBOSE_CONSOLE", "false").lower() == "true"
    use_simple = simple_format or os.getenv("LOG_SIMPLE_FORMAT", "false").lower() == "true"
    
    # 定义第三方库的过滤逻辑
    tp_level = os.getenv("THIRD_PARTY_LOG_LEVEL", "ERROR").upper()
    def main_filter(record):
        # 排除掉干扰较大的第三方库，除非达到 ERROR 级别
        tp_modules = ["LiteLLM", "urllib3", "requests", "openai"]
        if any(record["name"].startswith(m) for m in tp_modules):
            return record["level"].no >= logger.level(tp_level).no
        return True

    # 1. Console Handler 配置
    if json_format or log_format_str.lower() == "json":
        logger.add(sys.stdout, level=level, serialize=True, filter=main_filter)
    
    elif use_verbose:
        # 详细模式：显示时间、级别、源码位置
        fmt = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
        logger.add(sys.stdout, format=fmt, level=level, colorize=True, filter=main_filter)
        
    elif use_simple:
        # 极简模式：只显示消息本身
        logger.add(sys.stdout, format="<level>{message}</level>", level=level, colorize=True, filter=main_filter)
        
    else:
        # 默认模式：INFO 级别简洁，WARNING 以上带前缀
        logger.add(
            sys.stdout,
            format="<level>{message}</level>",
            level="INFO",
            filter=main_filter,
            colorize=True
        )
        logger.add(
            sys.stdout,
            format="<level>{level: <8}</level> | <level>{message}</level>",
            level="WARNING",
            filter=main_filter,
            colorize=True
        )   
    # 2. File Handler 配置
    if log_file_path:
        try:
            Path(log_file_path).parent.mkdir(parents=True, exist_ok=True)
            logger.add(
                log_file_path,
                format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
                level="DEBUG",
                rotation="10 MB",
                retention="10 days",
                encoding="utf-8",
                filter=main_filter
            )
        except Exception as e:
            # 此时 Console 已经配置好，可以使用 logger 发出警告
            logger.warning(f"Failed to set up file logging: {e}")
    
    _logging_initialized = True


def get_logger(name: str):
    """Get a logger instance for a module."""
    if not _logging_initialized:
        setup_logging()
    # 使用 bind 为该模块的日志打上特定的 'name' 标签
    return logger.bind(name=name)


# 自动初始化逻辑
if os.getenv("VULNHALLA_AUTO_SETUP_LOGGING", "true").lower() == "true":
    setup_logging()