#!/usr/bin/env python3
"""
RAG Context Enhancement Module.

This module provides context enhancement for LLM analysis by:
1. Extracting keywords from issue and code
2. Searching for related symbols across the codebase
3. Merging retrieved context with the original code
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.utils.common_functions import read_file_lines_from_zip
from src.utils.logger import get_logger
from src.utils.path_normalizer import PathNormalizer, extract_function_lines_path

from src.agent.code_search import CodeSearcher, KeywordExtractor

logger = get_logger(__name__)


class RAGConfig:
    """
    Configuration for RAG Context Enhancement.
    """

    def __init__(
        self,
        enabled: bool = True,
        search_depth: int = 5,
        max_context_tokens: int = 8000,
        max_results_per_keyword: int = 3,
        prioritize_types: Optional[Set[str]] = None
    ):
        """
        Initialize RAG configuration.

        Args:
            enabled: Whether RAG enhancement is enabled.
            search_depth: Number of keywords to search for.
            max_context_tokens: Maximum tokens for enhanced context.
            max_results_per_keyword: Maximum results to retrieve per keyword.
            prioritize_types: Symbol types to prioritize in search.
        """
        self.enabled = enabled
        self.search_depth = search_depth
        self.max_context_tokens = max_context_tokens
        self.max_results_per_keyword = max_results_per_keyword
        self.prioritize_types = prioritize_types or {'function', 'class', 'global_var'}


class RAGContextEnhancer:
    """
    RAG Context Enhancer for improving LLM analysis with cross-file context.
    
    This enhancer addresses the "can't see global information" problem by:
    1. Extracting searchable keywords from the issue and code
    2. Searching for related definitions (functions, classes, variables, macros)
    3. Merging the retrieved context with the original code
    """

    def __init__(
        self,
        db_path: str,
        config: Optional[RAGConfig] = None
    ):
        """
        Initialize the RAG context enhancer.

        Args:
            db_path: Path to the CodeQL database folder.
            config: RAG configuration. Uses defaults if not provided.
        """
        self.db_path = db_path
        self.config = config or RAGConfig()
        
        # Initialize code searcher
        self.searcher = CodeSearcher(
            db_path=db_path,
            max_results=self.config.max_results_per_keyword
        )
        
        # Keyword extractor
        self.keyword_extractor = KeywordExtractor()

    def enhance_context(
        self,
        issue: Dict[str, str],
        current_code: str,
        current_function: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Enhance the context by searching for related code across the codebase.

        Args:
            issue: Issue dictionary containing issue information.
            current_code: Current code snippet.
            current_function: Current function dictionary (optional).

        Returns:
            Enhanced context string with related code appended.
        """
        if not self.config.enabled:
            logger.debug("RAG enhancement is disabled, returning original code")
            return current_code

        logger.debug("Starting RAG context enhancement...")
        
        # Step 1: Extract keywords
        keywords = self._extract_keywords(issue, current_code)
        
        if not keywords:
            logger.debug("No keywords extracted, returning original code")
            return current_code
        
        logger.debug(f"Extracted {len(keywords)} keywords: {keywords[:5]}...")
        
        # Step 2: Search for related code
        related_code = self._search_related_code(keywords)
        
        if not related_code:
            logger.debug("No related code found, returning original code")
            return current_code
        
        logger.debug(f"Found {len(related_code)} related code snippets")
        
        # Step 3: Merge and limit context
        enhanced_context = self._merge_context(current_code, related_code)
        
        logger.debug(f"Enhanced context length: {len(enhanced_context)} chars")
        
        return enhanced_context

    def _extract_keywords(
        self,
        issue: Dict[str, str],
        code: str
    ) -> List[str]:
        """
        Extract searchable keywords from issue and code.

        Args:
            issue: Issue dictionary.
            code: Current code snippet.

        Returns:
            List of ranked keywords.
        """
        # Get keywords from issue
        issue_name = issue.get('name', issue.get('issue_name', ''))
        issue_message = issue.get('message', '')
        issue_keywords = self.keyword_extractor.extract_from_issue(issue_name, issue_message)
        
        # Get keywords from code
        code_keywords = self.keyword_extractor.extract_from_code(code)
        
        # Combine and deduplicate
        all_keywords = list(set(issue_keywords + code_keywords))
        
        # Rank by relevance
        ranked = self.keyword_extractor.rank_keywords(
            all_keywords,
            code,
            self.config.prioritize_types
        )
        
        # Take top keywords based on search depth
        top_keywords = [kw for kw, _ in ranked[:self.config.search_depth]]
        
        return top_keywords

    def _search_related_code(
        self,
        keywords: List[str]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Search for code related to the keywords.

        Args:
            keywords: List of keywords to search for.

        Returns:
            List of (description, code_snippet) tuples.
        """
        related_code = []
        
        for keyword in keywords:
            # Search for the symbol
            results = self.searcher.search_symbol(
                keyword,
                search_types=self.config.prioritize_types
            )
            
            for result in results:
                # Skip if it's the same as current function
                if self._is_current_function(result, keyword):
                    continue
                
                # Get the actual code
                code_snippet = self._get_code_snippet(result)
                
                if code_snippet:
                    description = self._format_result_description(result)
                    related_code.append((description, code_snippet))
                    
                    if len(related_code) >= self.config.search_depth * self.config.max_results_per_keyword:
                        break
            
            if len(related_code) >= self.config.search_depth * self.config.max_results_per_keyword:
                break
        
        return related_code

    def _is_current_function(
        self,
        result: Dict[str, Any],
        keyword: str
    ) -> bool:
        """
        Check if the search result is the same as the current function.

        Args:
            result: Search result dictionary.
            keyword: Keyword being searched.

        Returns:
            True if it's the same function.
        """
        # Simple heuristic: if the function name matches the keyword exactly
        result_name = result.get('name', '').lower()
        keyword_lower = keyword.lower()
        
        return result_name == keyword_lower or result_name.endswith('::' + keyword_lower)

    def _get_code_snippet(
        self,
        result: Dict[str, Any]
    ) -> Optional[str]:
        """
        Get the actual code snippet for a search result.

        Args:
            result: Search result dictionary.

        Returns:
            Code snippet string, or None if not available.
        """
        try:
            result_type = result.get('type', '')
            file_path = result.get('file', '')
            start_line = result.get('start_line', 0)
            end_line = result.get('end_line', 0)
            
            if not file_path or not start_line:
                # For macros, we might have body directly
                if result_type == 'macro':
                    body = result.get('body', '')
                    if body:
                        return f"#define {result.get('name', 'MACRO')} {body}"
                return None
            
            # Convert to proper path for ZIP reading
            zip_path, _ = PathNormalizer.build_zip_path(
                self.db_path,
                file_path
            )
            
            src_zip_path = str(Path(self.db_path) / "src.zip")
            
            # Try to read from ZIP
            try:
                code_content = read_file_lines_from_zip(src_zip_path, zip_path)
            except Exception:
                # Try alternative path
                try:
                    alt_path = file_path.replace('\\', '/').lstrip('/')
                    code_content = read_file_lines_from_zip(src_zip_path, alt_path)
                except Exception as e:
                    logger.debug(f"Could not read file {file_path}: {e}")
                    return None
            
            if not code_content:
                return None
            
            lines = code_content.split('\n')
            
            # Extract the relevant portion
            start = max(0, int(start_line) - 1)
            end = min(len(lines), int(end_line))
            
            snippet_lines = lines[start:end]
            snippet = '\n'.join(f"{start + i + 1}: {line}" for i, line in enumerate(snippet_lines))
            
            # Truncate if too long
            max_chars = 2000
            if len(snippet) > max_chars:
                snippet = snippet[:max_chars] + "\n... (truncated)"
            
            return f"file: {file_path}\n{snippet}"
            
        except Exception as e:
            logger.debug(f"Error getting code snippet: {e}")
            return None

    def _format_result_description(self, result: Dict[str, Any]) -> str:
        """
        Format a human-readable description for a search result.

        Args:
            result: Search result dictionary.

        Returns:
            Formatted description string.
        """
        result_type = result.get('type', 'unknown')
        name = result.get('name', 'unknown')
        file_path = result.get('file', 'unknown')
        start_line = result.get('start_line', '?')
        
        return f"[{result_type}] {name} at {file_path}:{start_line}"

    def _merge_context(
        self,
        original_code: str,
        related_code: List[Tuple[str, str]]
    ) -> str:
        """
        Merge original code with related code, respecting token limits.

        Args:
            original_code: The original code snippet.
            related_code: List of (description, code) tuples.

        Returns:
            Merged context string.
        """
        # Estimate max chars (rough: 1 token ≈ 4 chars)
        max_chars = self.config.max_context_tokens * 4
        
        # Start with original code
        merged = original_code
        
        # Add related code if space permits
        for description, code in related_code:
            # Check if adding this would exceed limit
            if len(merged) + len(code) + 50 > max_chars:  # 50 for separators
                # Try to add a shorter version
                short_code = code[:500] + "\n... (truncated)" if len(code) > 500 else code
                if len(merged) + len(short_code) + 50 > max_chars:
                    break
                merged += f"\n\n--- Additional Context ---\n{short_code}"
            else:
                merged += f"\n\n--- Additional Context ---\n{code}"
        
        # Final truncation check
        if len(merged) > max_chars:
            merged = merged[:max_chars] + "\n... (context truncated due to length limits)"
        
        return merged


class RAGContextBuilder:
    """
    Builder class for creating enhanced prompts with RAG context.
    """

    def __init__(
        self,
        db_path: str,
        config: Optional[RAGConfig] = None
    ):
        """
        Initialize the RAG context builder.

        Args:
            db_path: Path to the CodeQL database folder.
            config: RAG configuration.
        """
        self.db_path = db_path
        self.config = config or RAGConfig()
        
        # Lazy initialization of enhancer
        self._enhancer: Optional[RAGContextEnhancer] = None

    @property
    def enhancer(self) -> RAGContextEnhancer:
        """Get or create the RAG enhancer."""
        if self._enhancer is None:
            self._enhancer = RAGContextEnhancer(self.db_path, self.config)
        return self._enhancer

    def build_enhanced_prompt(
        self,
        base_prompt: str,
        issue: Dict[str, str],
        current_code: str,
        current_function: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Build an enhanced prompt with RAG context.

        Args:
            base_prompt: The original prompt.
            issue: Issue dictionary.
            current_code: Current code snippet.
            current_function: Current function dictionary.

        Returns:
            Enhanced prompt with additional context.
        """
        if not self.config.enabled:
            return base_prompt
        
        # Enhance the code context
        enhanced_code = self.enhancer.enhance_context(
            issue=issue,
            current_code=current_code,
            current_function=current_function
        )
        
        # Replace the code placeholder in the prompt
        # This assumes the prompt has a {code} placeholder
        if '{code}' in base_prompt:
            return base_prompt.format(code=enhanced_code)
        
        # If no placeholder, append context
        return base_prompt + f"\n\n=== Additional Code Context ===\n{enhanced_code}"
