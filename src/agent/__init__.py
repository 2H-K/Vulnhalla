#!/usr/bin/env python3
"""
Agent module for Vulnhalla AI Agent.

This module contains:
- Reflection mechanism for multi-round analysis
- RAG context enhancement for cross-file code search
- Code search utilities using CodeQL indexes
"""

# Phase 2: Reflection Mechanism
try:
    from src.agent.reflection import ReflectionAgent, ReflectionConfig
    __all__ = ['ReflectionAgent', 'ReflectionConfig']
except ImportError:
    pass

# Phase 3: RAG Context Enhancement
try:
    from src.agent.rag_context import (
        RAGContextEnhancer,
        RAGContextBuilder,
        RAGConfig
    )
    from src.agent.code_search import (
        CodeSearcher,
        CodeSearchIndex,
        KeywordExtractor
    )
    __all__.extend([
        'RAGContextEnhancer',
        'RAGContextBuilder',
        'RAGConfig',
        'CodeSearcher',
        'CodeSearchIndex',
        'KeywordExtractor'
    ])
except ImportError:
    pass

__version__ = "1.0.0"
