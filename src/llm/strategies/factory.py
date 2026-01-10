#!/usr/bin/env python3
"""
Strategy Factory for Vulnhalla Language Strategies.

This module implements the Factory Pattern to create language-specific strategy
instances based on the input language code. It provides a centralized way to
instantiate the appropriate strategy without direct coupling to concrete classes.

Usage:
    from src.llm.strategies.factory import StrategyFactory
    
    factory = StrategyFactory()
    strategy = factory.get_strategy(lang="java", config={})
    result = strategy.extract_function_code(...)
"""
import sys
import os
from typing import Any, Dict, Optional, Type
from pathlib import Path

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.llm.strategies.base import BaseStrategy
from src.llm.strategies.language_config import (
    get_language_config,
    normalize_language,
    LanguageConfig
)
from src.utils.logger import get_logger
logger=get_logger(__name__)
# Import all concrete strategies (lazy loading to avoid circular imports)
# These will be imported only when needed
_STRATEGY_IMPORTS: Dict[str, str] = {
    "c": "src.llm.strategies.cpp_strategy.CppStrategy",
    "cpp": "src.llm.strategies.cpp_strategy.CppStrategy",
    "java": "src.llm.strategies.java_strategy.JavaStrategy",
    "javascript": "src.llm.strategies.javascript_strategy.JavaScriptStrategy",
    "js": "src.llm.strategies.javascript_strategy.JavaScriptStrategy",
    "typescript": "src.llm.strategies.default_strategy.DefaultStrategy",
    "ts": "src.llm.strategies.default_strategy.DefaultStrategy",
    "python": "src.llm.strategies.default_strategy.DefaultStrategy",
    "py": "src.llm.strategies.default_strategy.DefaultStrategy",
    "go": "src.llm.strategies.go_strategy.GoStrategy",
    "csharp": "src.llm.strategies.csharp_strategy.CsharpStrategy",
    "c#": "src.llm.strategies.csharp_strategy.CsharpStrategy",
}

# Default strategy class for unsupported languages
_DEFAULT_STRATEGY_CLASS: str = "src.llm.strategies.default_strategy.DefaultStrategy"


class StrategyFactory:
    """
    Factory class for creating language-specific strategy instances.
    
    This factory:
    1. Normalizes language names to internal codes
    2. Loads appropriate strategy class based on language
    3. Applies language-specific configuration
    4. Returns configured strategy instance
    
    Example:
        factory = StrategyFactory()
        strategy = factory.get_strategy(lang="java", config={"code_size_limit": 15000})
        code = strategy.extract_function_code(code_file, function_dict)
    """
    
    def __init__(self) -> None:
        """Initialize the strategy factory with empty cache."""
        self._strategy_cache: Dict[str, Type[BaseStrategy]] = {}
        self._instance_cache: Dict[str, BaseStrategy] = {}
    
    def get_strategy(
        self, 
        lang: str, 
        config: Optional[Dict[str, Any]] = None
    ) -> BaseStrategy:
        """
        Get a strategy instance for the specified language.
        
        This method:
        1. Normalizes the language name
        2. Gets language configuration
        3. Loads the appropriate strategy class
        4. Creates and returns a configured instance
        
        Args:
            lang (str): Programming language code (e.g., 'java', 'javascript')
            config (Dict, optional): Additional configuration overrides
        
        Returns:
            BaseStrategy: Configured strategy instance for the language
        
        Raises:
            ValueError: If language is not supported
            ImportError: If strategy module cannot be imported
        """
        # Normalize language code
        normalized_lang = normalize_language(lang)
        
        # Get language configuration
        lang_config = get_language_config(normalized_lang)
        
        # Merge configurations
        final_config = self._merge_config(lang_config, config)
        
        # Create cache key
        cache_key = f"{normalized_lang}_{id(config)}"
        
        # Check instance cache
        if cache_key in self._instance_cache:
            return self._instance_cache[cache_key]
        
        # Get strategy class
        strategy_class = self._load_strategy_class(normalized_lang)
        
        # Create instance
        strategy_instance = strategy_class(config=final_config)
        
        # Cache instance
        self._instance_cache[cache_key] = strategy_instance
        
        return strategy_instance
    
    def _merge_config(
        self, 
        lang_config: Optional[LanguageConfig], 
        user_config: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Merge language config with user-provided config.
        
        User config takes precedence over language defaults.
        
        Args:
            lang_config: Language-specific configuration
            user_config: User-provided configuration overrides
        
        Returns:
            Dict: Merged configuration dictionary
        """
        # Start with language defaults
        merged = {}
        if lang_config:
            merged = lang_config.to_dict()
        
        # Override with user config
        if user_config:
            merged.update(user_config)
        
        return merged
    
    def _load_strategy_class(self, lang: str) -> Type[BaseStrategy]:
        """
        Load and return the strategy class for a language.
        
        Uses lazy import to avoid circular dependencies.
        
        Args:
            lang (str): Normalized language code
        
        Returns:
            Type[BaseStrategy]: Strategy class for the language
        
        Raises:
            ImportError: If strategy module cannot be imported
            ValueError: If no strategy is available for the language
        """
        # Check class cache
        if lang in self._strategy_cache:
            return self._strategy_cache[lang]
        
        # Get import path
        import_path = _STRATEGY_IMPORTS.get(lang, _DEFAULT_STRATEGY_CLASS)
        
        # Lazy import
        try:
            module_path, class_name = import_path.rsplit('.', 1)
            module = __import__(module_path, fromlist=[class_name])
            strategy_class = getattr(module, class_name)
        except (ImportError, AttributeError) as e:
            # Fall back to default strategy
            logger.warning(f"Could not load strategy for '{lang}': {e}")
            logger.info(f"Falling back to default strategy for '{lang}'")
            
            try:
                module_path, class_name = _DEFAULT_STRATEGY_CLASS.rsplit('.', 1)
                module = __import__(module_path, fromlist=[class_name])
                strategy_class = getattr(module, class_name)
            except (ImportError, AttributeError) as e2:
                raise ImportError(
                    f"Failed to load strategy for language '{lang}': {e2}"
                ) from e2
        
        # Cache and return
        self._strategy_cache[lang] = strategy_class
        return strategy_class
    
    def get_supported_languages(self) -> list:
        """Get list of supported language codes."""
        return list(_STRATEGY_IMPORTS.keys())
    
    def clear_cache(self) -> None:
        """Clear the strategy cache (useful for testing)."""
        self._strategy_cache.clear()
        self._instance_cache.clear()


# Global factory instance for convenience
_factory_instance: Optional[StrategyFactory] = None


def get_strategy(lang: str, config: Optional[Dict[str, Any]] = None) -> BaseStrategy:
    """
    Convenience function to get a strategy instance.
    
    Args:
        lang (str): Programming language code
        config (Dict, optional): Configuration overrides
    
    Returns:
        BaseStrategy: Configured strategy instance
    """
    global _factory_instance
    if _factory_instance is None:
        _factory_instance = StrategyFactory()
    return _factory_instance.get_strategy(lang, config)


# For backwards compatibility and easier imports
__all__ = [
    "StrategyFactory",
    "get_strategy",
    "BaseStrategy",
]
