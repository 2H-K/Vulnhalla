#!/usr/bin/env python3
"""
Code Search Module for RAG Context Enhancement.

This module provides code search capabilities using CodeQL database indexes
(FunctionTree.csv, Classes.csv, GlobalVars.csv) to enable cross-file context
retrieval for the LLM agent.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.utils.csv_parser import parse_csv_row
from src.utils.exceptions import CodeQLError
from src.utils.logger import get_logger
from src.utils.path_normalizer import PathNormalizer

logger = get_logger(__name__)


class CodeSearchIndex:
    """
    In-memory index built from CodeQL database CSV files.
    Enables fast symbol lookup across the entire codebase.
    """

    def __init__(self, db_path: str):
        """
        Initialize the search index from a CodeQL database.

        Args:
            db_path: Path to the CodeQL database folder.
        """
        self.db_path = db_path
        self.db_path_obj = Path(db_path)
        
        # Index storage
        self.function_index: Dict[str, List[Dict[str, str]]] = {}  # name -> list of functions
        self.class_index: Dict[str, List[Dict[str, str]]] = {}      # name -> list of classes
        self.global_var_index: Dict[str, List[Dict[str, str]]] = {} # name -> list of global vars
        self.macro_index: Dict[str, List[Dict[str, str]]] = {}      # name -> list of macros
        
        self._built = False

    def build(self) -> None:
        """
        Build all indexes from CodeQL database CSV files.
        """
        if self._built:
            logger.debug("Index already built, skipping")
            return
        
        logger.info("Building search index from CodeQL database...")
        
        # Build each index
        self._build_function_index()
        self._build_class_index()
        self._build_global_var_index()
        self._build_macro_index()
        
        self._built = True
        logger.info(
            f"Search index built: {len(self.function_index)} functions, "
            f"{len(self.class_index)} classes, {len(self.global_var_index)} global vars, "
            f"{len(self.macro_index)} macros"
        )

    def _read_csv_file(self, filename: str, keys: List[str]) -> List[Dict[str, str]]:
        """
        Read and parse a CSV file from the database.

        Args:
            filename: Name of the CSV file in the database folder.
            keys: List of column names.

        Returns:
            List of parsed rows as dictionaries.
        """
        file_path = self.db_path_obj / filename
        if not file_path.exists():
            logger.debug(f"CSV file not found: {filename}")
            return []
        
        results = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    row = parse_csv_row(line, keys)
                    if row:
                        results.append(row)
        except (FileNotFoundError, PermissionError, OSError) as e:
            logger.warning(f"Error reading {filename}: {e}")
        
        return results

    def _build_function_index(self) -> None:
        """Build function index from FunctionTree.csv."""
        functions = self._read_csv_file("FunctionTree.csv", 
            ["function_name", "file_path", "start_line", "end_line", "function_id", "caller_ids"])
        
        for func in functions:
            func_name = func.get("function_name", "").replace('"', '').strip()
            if not func_name:
                continue
            
            # Index by full name
            if func_name not in self.function_index:
                self.function_index[func_name] = []
            self.function_index[func_name].append(func)
            
            # Also index by simple name (after :: or last part)
            simple_name = func_name.split("::")[-1]
            if simple_name != func_name and simple_name:
                if simple_name not in self.function_index:
                    self.function_index[simple_name] = []
                self.function_index[simple_name].append(func)

    def _build_class_index(self) -> None:
        """Build class/struct index from Classes.csv."""
        classes = self._read_csv_file("Classes.csv",
            ["type", "class_name", "simple_name", "file", "start_line", "end_line", "class_id"])
        
        for cls in classes:
            class_name = cls.get("class_name", "").replace('"', '').strip()
            simple_name = cls.get("simple_name", "").replace('"', '').strip()
            
            if not class_name:
                continue
            
            # Index by full name
            if class_name not in self.class_index:
                self.class_index[class_name] = []
            self.class_index[class_name].append(cls)
            
            # Also index by simple name
            if simple_name and simple_name != class_name:
                if simple_name not in self.class_index:
                    self.class_index[simple_name] = []
                self.class_index[simple_name].append(cls)

    def _build_global_var_index(self) -> None:
        """Build global variable index from GlobalVars.csv."""
        global_vars = self._read_csv_file("GlobalVars.csv",
            ["global_var_name", "file", "start_line", "end_line"])
        
        for gvar in global_vars:
            var_name = gvar.get("global_var_name", "").replace('"', '').strip()
            if not var_name:
                continue
            
            if var_name not in self.global_var_index:
                self.global_var_index[var_name] = []
            self.global_var_index[var_name].append(gvar)

    def _build_macro_index(self) -> None:
        """Build macro index from Macros.csv."""
        macros = self._read_csv_file("Macros.csv", ["macro_name", "body"])
        
        for macro in macros:
            macro_name = macro.get("macro_name", "").replace('"', '').strip()
            if not macro_name:
                continue
            
            if macro_name not in self.macro_index:
                self.macro_index[macro_name] = []
            self.macro_index[macro_name].append(macro)


class CodeSearcher:
    """
    Code search interface that uses CodeSearchIndex to find relevant code context.
    """

    def __init__(self, db_path: str, max_results: int = 5):
        """
        Initialize the code searcher.

        Args:
            db_path: Path to the CodeQL database folder.
            max_results: Maximum number of results to return per search.
        """
        self.db_path = db_path
        self.max_results = max_results
        self.index = CodeSearchIndex(db_path)
        
        # Lazy build
        self._index_built = False

    def _ensure_index(self) -> None:
        """Ensure the index is built."""
        if not self._index_built:
            self.index.build()
            self._index_built = True

    def search_symbol(
        self,
        symbol_name: str,
        search_types: Optional[Set[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for a symbol (function, class, variable, macro) in the index.

        Args:
            symbol_name: Name of the symbol to search for.
            search_types: Types to search in ('function', 'class', 'global_var', 'macro').
                         If None, searches all.

        Returns:
            List of matching symbols with their definitions.
        """
        self._ensure_index()
        
        if search_types is None:
            search_types = {'function', 'class', 'global_var', 'macro'}
        
        results = []
        symbol_name_clean = symbol_name.replace('"', '').strip()
        
        # Search functions
        if 'function' in search_types:
            functions = self.index.function_index.get(symbol_name_clean, [])
            for func in functions[:self.max_results]:
                results.append({
                    'type': 'function',
                    'name': func.get('function_name', ''),
                    'file': func.get('file_path', ''),
                    'start_line': func.get('start_line', ''),
                    'end_line': func.get('end_line', '')
                })
        
        # Search classes
        if 'class' in search_types:
            classes = self.index.class_index.get(symbol_name_clean, [])
            for cls in classes[:self.max_results]:
                results.append({
                    'type': 'class',
                    'name': cls.get('class_name', ''),
                    'class_type': cls.get('type', ''),
                    'file': cls.get('file', ''),
                    'start_line': cls.get('start_line', ''),
                    'end_line': cls.get('end_line', '')
                })
        
        # Search global variables
        if 'global_var' in search_types:
            gvars = self.index.global_var_index.get(symbol_name_clean, [])
            for gvar in gvars[:self.max_results]:
                results.append({
                    'type': 'global_var',
                    'name': gvar.get('global_var_name', ''),
                    'file': gvar.get('file', ''),
                    'start_line': gvar.get('start_line', ''),
                    'end_line': gvar.get('end_line', '')
                })
        
        # Search macros
        if 'macro' in search_types:
            macros = self.index.macro_index.get(symbol_name_clean, [])
            for macro in macros[:self.max_results]:
                results.append({
                    'type': 'macro',
                    'name': macro.get('macro_name', ''),
                    'body': macro.get('body', ''),
                    'file': ''  # Macros.csv may not have file info
                })
        
        return results

    def search_by_pattern(
        self,
        pattern: str,
        search_in: Optional[Set[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for symbols matching a pattern (partial match).

        Args:
            pattern: Pattern to match against symbol names.
            search_in: Types to search in. If None, searches all.

        Returns:
            List of matching symbols.
        """
        self._ensure_index()
        
        results = []
        pattern_lower = pattern.lower()
        
        if search_in is None:
            search_in = {'function', 'class', 'global_var', 'macro'}
        
        # Search in functions
        if 'function' in search_in:
            for name, funcs in self.index.function_index.items():
                if pattern_lower in name.lower():
                    for func in funcs[:2]:  # Limit per match
                        results.append({
                            'type': 'function',
                            'name': name,
                            'file': func.get('file_path', ''),
                            'start_line': func.get('start_line', ''),
                            'end_line': func.get('end_line', '')
                        })
                        if len(results) >= self.max_results * 3:
                            break
            if len(results) >= self.max_results * 3:
                return results[:self.max_results]
        
        # Search in classes
        if 'class' in search_in:
            for name, classes in self.index.class_index.items():
                if pattern_lower in name.lower():
                    for cls in classes[:2]:
                        results.append({
                            'type': 'class',
                            'name': name,
                            'class_type': cls.get('type', ''),
                            'file': cls.get('file', ''),
                            'start_line': cls.get('start_line', ''),
                            'end_line': cls.get('end_line', '')
                        })
                        if len(results) >= self.max_results * 3:
                            break
            if len(results) >= self.max_results * 3:
                return results[:self.max_results]
        
        # Search in global variables
        if 'global_var' in search_in:
            for name, gvars in self.index.global_var_index.items():
                if pattern_lower in name.lower():
                    for gvar in gvars[:2]:
                        results.append({
                            'type': 'global_var',
                            'name': name,
                            'file': gvar.get('file', ''),
                            'start_line': gvar.get('start_line', ''),
                            'end_line': gvar.get('end_line', '')
                        })
                        if len(results) >= self.max_results * 3:
                            break
            if len(results) >= self.max_results * 3:
                return results[:self.max_results]
        
        return results[:self.max_results]


class KeywordExtractor:
    """
    Extracts searchable keywords from code and issue information.
    """

    # Common vulnerability-related keywords
    VULN_KEYWORDS = {
        'buffer_overflow': ['memcpy', 'strcpy', 'strcat', 'sprintf', 'strlen', 'malloc', 'free', 'buffer'],
        'sql_injection': ['sql', 'query', 'execute', 'prepare', 'statement', 'database', 'cursor'],
        'command_injection': ['exec', 'system', 'popen', 'runtime', 'command', 'shell', 'process'],
        'path_traversal': ['path', 'file', 'directory', 'open', 'read', 'write', 'filename'],
        'xss': ['html', 'innerHTML', 'document', 'eval', 'script', 'alert', 'cookie'],
        'deserialization': ['deserialize', 'unserialize', 'readObject', 'pickle', 'yaml'],
        'information_disclosure': ['password', 'secret', 'token', 'key', 'credential', 'auth'],
        'use_after_free': ['malloc', 'free', 'pointer', 'reference', 'null', 'dereference'],
        'race_condition': ['lock', 'mutex', 'thread', 'async', 'concurrent', 'race', 'sync'],
    }

    @staticmethod
    def extract_from_code(code: str) -> List[str]:
        """
        Extract potential keywords from code snippet.

        Args:
            code: Code snippet to analyze.

        Returns:
            List of extracted keywords.
        """
        keywords = []
        
        # Extract function calls
        func_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        matches = re.findall(func_pattern, code)
        keywords.extend(matches)
        
        # Extract variable names (simple heuristic)
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;,\)]'
        matches = re.findall(var_pattern, code)
        keywords.extend(matches)
        
        # Extract type names
        type_pattern = r'\b(struct|class|enum|union)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(type_pattern, code)
        for _, type_name in matches:
            keywords.append(type_name)
        
        # Remove duplicates and common words
        common_words = {
            'if', 'else', 'for', 'while', 'switch', 'case', 'return', 'break', 
            'continue', 'goto', 'sizeof', 'typedef', 'static', 'const', 'void',
            'int', 'char', 'float', 'double', 'long', 'short', 'unsigned', 'signed',
            'public', 'private', 'protected', 'class', 'struct', 'enum', 'union',
            'true', 'false', 'null', 'nil', 'None', 'this', 'self', 'new', 'delete',
            'try', 'catch', 'throw', 'throws', 'finally', 'import', 'export',
            'function', 'var', 'let', 'const', 'async', 'await', 'yield'
        }
        
        keywords = [k for k in keywords if k not in common_words and len(k) > 2]
        
        # Return unique keywords, sorted by length (longer = more specific)
        unique_keywords = list(set(keywords))
        unique_keywords.sort(key=len, reverse=True)
        
        return unique_keywords[:20]  # Limit to top 20

    @staticmethod
    def extract_from_issue(issue_name: str, message: str = "") -> List[str]:
        """
        Extract keywords from issue information.

        Args:
            issue_name: Name/type of the issue.
            message: Additional issue message.

        Returns:
            List of extracted keywords.
        """
        keywords = []
        
        # Add issue name words
        words = re.findall(r'[a-zA-Z][a-zA-Z0-9]*', issue_name)
        keywords.extend(words)
        
        # Add message words
        if message:
            words = re.findall(r'[a-zA-Z][a-zA-Z0-9]*', message)
            keywords.extend(words)
        
        # Add related keywords based on issue type
        issue_lower = issue_name.lower()
        for vuln_type, related_words in KeywordExtractor.VULN_KEYWORDS.items():
            if any(w in issue_lower for w in [vuln_type.replace('_', ' '), vuln_type]):
                keywords.extend(related_words)
        
        # Remove duplicates
        unique_keywords = list(set(keywords))
        
        return unique_keywords[:15]

    @staticmethod
    def rank_keywords(
        keywords: List[str],
        code_context: str,
        priority_types: Optional[Set[str]] = None
    ) -> List[Tuple[str, float]]:
        """
        Rank keywords by relevance to the current code context.

        Args:
            keywords: List of candidate keywords.
            code_context: Current code context for comparison.
            priority_types: Symbol types to prioritize ('function', 'class', etc.).

        Returns:
            List of (keyword, score) tuples, sorted by score descending.
        """
        if priority_types is None:
            priority_types = {'function', 'class'}
        
        code_lower = code_context.lower()
        scored = []
        
        for kw in keywords:
            score = 0.0
            
            # Base score for keyword length (longer = more specific)
            score += len(kw) * 0.1
            
            # Boost if keyword appears in code context
            if kw.lower() in code_lower:
                score += 2.0
            
            # Boost if it's a known vulnerability-related keyword
            for vuln_words in KeywordExtractor.VULN_KEYWORDS.values():
                if kw.lower() in [w.lower() for w in vuln_words]:
                    score += 1.5
                    break
            
            scored.append((kw, score))
        
        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)
        
        return scored
