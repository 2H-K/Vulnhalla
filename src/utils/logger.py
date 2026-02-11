import sys
import os
from pathlib import Path
from typing import Optional
from loguru import logger

_logging_initialized = False

def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
    json_format: bool = False,
    simple_format: bool = False,
    force: bool = False  # 新增：允许强制重置配置
) -> None:
    global _logging_initialized
    
    # 如果已经初始化且不是强制重置，则直接返回
    if _logging_initialized and not force:
        return
    
    # 清除之前所有的 handler，防止日志重复输出
    logger.remove()
    
    # 确定日志级别：优先使用显式传入的参数，其次是环境变量，最后默认 DEBUG
    level = log_level or os.getenv("LOG_LEVEL", "DEBUG").upper()
    
    def main_filter(record):
        # 允许查看 LiteLLM 的核心错误，但过滤掉冗余的连接信息
        tp_modules = ["urllib3", "requests", "openai", "asyncio"]
        # 如果是 DEBUG 模式，我们可能希望看到 LiteLLM 的一些关键信息
        if level == "DEBUG":
            return not any(record["name"].startswith(m) for m in tp_modules)
        # 非 DEBUG 模式下也过滤 LiteLLM
        return not any(record["name"].startswith(m) for m in ["LiteLLM"] + tp_modules)

    # 移除时间，仅保留级别、位置和消息
    fmt = (
        "<level>{level: <8}</level> | "
        "<cyan>{name}:{function}:{line}</cyan> - <level>{message}</level>"
    )
    
    # 添加控制台处理器
    logger.add(
        sys.stdout, 
        format=fmt, 
        level=level, 
        colorize=True, 
        filter=main_filter, 
        backtrace=True, 
        diagnose=True
    )
    
    _logging_initialized = True
    logger.debug(f"Logging initialized with level: {level}")

def get_logger(name: str):
    if not _logging_initialized:
        setup_logging()
    return logger.bind(module_name=name)

# 默认自动初始化一次（保持原有行为）
setup_logging()