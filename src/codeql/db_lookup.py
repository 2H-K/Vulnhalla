"""
CodeQL database lookup utilities.

This module provides functions to query CodeQL CSV files (FunctionTree.csv,
Macros.csv, GlobalVars.csv, Classes.csv) and extract code snippets from
the source archive.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import re

from src.utils.exceptions import CodeQLError
from src.utils.common_functions import read_file_lines_from_zip
from src.utils.csv_parser import parse_csv_row
from src.utils.logger import get_logger
from src.utils.cache_manager import CacheManager
from src.utils.path_normalizer import PathNormalizer, extract_function_lines_path

logger = get_logger(__name__)


class CodeQLDBLookup:
    """
    Encapsulates CodeQL database lookup operations for functions, macros,
    global variables, classes, and caller relationships.
    """

    def __init__(self, cache_enabled: Optional[bool] = None, cache_dir: Optional[str] = None) -> None:
        """
        Initialize the CodeQLDBLookup with optional caching support.

        Args:
            cache_enabled: Whether to enable caching. If None, reads from config.
            cache_dir: Custom cache directory. If None, uses default.
        """
        # Initialize cache manager
        if cache_enabled is None:
            # Load from config if not specified
            from src.utils.llm_config import load_llm_config
            temp_config = load_llm_config()
            cache_enabled = temp_config.get("cache_enabled", True)
            cache_dir = temp_config.get("cache_dir", "output/cache")

        self.cache_manager = CacheManager(
            cache_dir=cache_dir or "output/cache",
            enabled=cache_enabled
        )

    def _iter_csv_lines(
        self,
        file_path: Union[str, Path],
        file_type_name: str
    ):
        """
        Generator that yields lines from a CSV file, handling file I/O errors.

        This helper centralizes CSV file opening, line iteration, and error handling.
        Each method can iterate over the yielded lines and apply method-specific logic.

        Args:
            file_path: Path to the CSV file to read.
            file_type_name: Descriptive name for the file type (e.g., "Function tree file",
                           "Macros CSV", "GlobalVars CSV") for error messages.

        Yields:
            str: Each line from the CSV file (including newline characters).

        Raises:
            CodeQLError: If file cannot be read (not found, permission denied, etc.).
        """
        try:
            with Path(file_path).open("r", encoding="utf-8") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    yield line
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise self._convert_csv_file_error(e, file_path, file_type_name) from e

    @staticmethod
    def _convert_csv_file_error(
        error: Exception,
        file_path: Union[str, Path],
        file_type_name: str
    ) -> CodeQLError:
        """
        Convert file I/O exceptions to CodeQLError with consistent messaging.

        Args:
            error: The original exception (FileNotFoundError, PermissionError, or OSError).
            file_path: Path to the CSV file that caused the error.
            file_type_name: Descriptive name for the file type (e.g., "Function tree file",
                           "Macros CSV", "GlobalVars CSV") for error messages.

        Returns:
            CodeQLError: Converted exception with appropriate message.
        """
        file_path_str = str(file_path)
        if isinstance(error, FileNotFoundError):
            return CodeQLError(f"{file_type_name} not found: {file_path_str}")
        elif isinstance(error, PermissionError):
            return CodeQLError(f"Permission denied reading {file_type_name}: {file_path_str}")
        elif isinstance(error, OSError):
            return CodeQLError(f"OS error while reading {file_type_name}: {file_path_str}")
        else:
            # Fallback for unexpected exception types
            return CodeQLError(f"Error reading {file_type_name}: {file_path_str}")

    @staticmethod
    def _strip_quotes(value: str) -> str:
        return value.replace("\"", "").strip()

    @staticmethod
    def _is_int(value: str) -> bool:
        try:
            int(value)
            return True
        except (TypeError, ValueError):
            return False

    def _normalize_function_tree_row(self, row_dict: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if not row_dict:
            return row_dict

        # Normalize whitespace early
        for key, val in row_dict.items():
            if val is not None:
                row_dict[key] = str(val).strip()

        start_line = self._strip_quotes(row_dict.get("start_line", ""))
        end_line = self._strip_quotes(row_dict.get("end_line", ""))
        function_id = self._strip_quotes(row_dict.get("function_id", ""))

        # Some CodeQL exports use: name,file,start_line,function_id,end_line,caller_ids
        if (not self._is_int(end_line)) and self._is_int(function_id):
            row_dict["end_line"], row_dict["function_id"] = row_dict["function_id"], row_dict["end_line"]

        for key in ["function_name", "file_path", "start_line", "end_line", "function_id", "caller_ids"]:
            if key in row_dict and row_dict[key] is not None:
                row_dict[key] = self._strip_quotes(str(row_dict[key]))

        return row_dict


    def get_function_by_line(
        self,
        function_tree_file: str,
        file: str,
        line: int
    ) -> Optional[Dict[str, str]]:
        """
        Retrieve the function dictionary from a CSV (FunctionTree.csv) that matches
        the specified file and line coverage.

        Uses greedy selection to find the most specific (smallest range) function
        containing the target line.

        Args:
            function_tree_file (str): Path to the FunctionTree.csv file.
            file (str): Name of the file as it appears in the CSV row.
            line (int): A line number within the function's start_line and end_line range.

        Returns:
            Optional[Dict[str, str]]: The matching function row as a dict, or None if not found.

        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        # 使用路径标准化模块提取用于查找的路径
        relative_path, filename = PathNormalizer.build_function_tree_lookup_path(file)
        
        logger.debug(f"get_function_by_line called with file={file}, line={line}")
        logger.debug(f"  -> lookup paths: relative={relative_path}, filename={filename}")

        keys = ["function_name", "file_path", "start_line", "end_line", "function_id", "caller_ids"]

        # Initialize tracking variables for greedy selection
        smallest_range = float('inf')
        best_function = None

        for function in self._iter_csv_lines(function_tree_file, "Function tree file"):
            # 尝试多种匹配策略
            match_found = False
            
            # 策略1: 相对路径匹配
            if relative_path and relative_path in function:
                match_found = True
            # 策略2: 纯文件名匹配
            elif filename in function:
                match_found = True
            
            if not match_found:
                continue
                
            row_dict = parse_csv_row(function, keys)
            row_dict = self._normalize_function_tree_row(row_dict)
            if row_dict and row_dict.get("start_line") and row_dict.get("end_line"):
                start = int(row_dict["start_line"])
                end = int(row_dict["end_line"])
                logger.debug(f"Checking line range: start={start}, end={end}, target_line={line}")


                if start <= line <= end:
                    # 检查路径匹配（使用多种策略）
                    function_file = row_dict.get("file_path", "")
                    row_dict["file"] = function_file
                    path_match = False
                    
                    # 策略1: 相对路径精确匹配
                    if relative_path and relative_path in function_file:
                        path_match = True
                    # 策略2: 纯文件名匹配
                    elif filename in function_file:
                        path_match = True
                    
                    if path_match:
                        # Greedy selection: track function with smallest range
                        # (most specific/nested function containing the line)
                        size = end - start
                        logger.debug(f"Found matching function with size={size}, current smallest={smallest_range}")
                        if size < smallest_range:
                            smallest_range = size
                            best_function = row_dict
                            logger.debug(f"Updated best_function: {best_function}")

        return best_function

    def get_function_by_name(
            self,
            function_tree_file: str,
            function_name: str,
            all_function: List[Dict[str, Any]],
            less_strict: bool = False
        ) -> Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
            """
            Retrieve a function by searching function_name in FunctionTree.csv.
            If not found, tries partial match if less_strict is True.

            Args:
                function_tree_file (str): Path to FunctionTree.csv.
                function_name (str): Desired function name (e.g., 'MyClass::MyFunc').
                all_function (List[Dict[str, Any]]): A list of known function dictionaries.
                less_strict (bool, optional): If True, use partial matching. Defaults to False.

            Returns:
                Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
                    - The found function (dict) or an error message (str).
                    - The "parent function" that references it, if relevant.
            
            Raises:
                CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
            """
            keys = ["function_name", "file_path", "start_line", "end_line", "function_id", "caller_ids"]
            function_name_only = function_name.split("::")[-1]

            for current_function in all_function:
                try:
                    with Path(function_tree_file).open("r", encoding="utf-8") as f:
                        while True:
                            row = f.readline()
                            if not row:
                                break
                            if current_function["function_id"] in row:
                                row_dict = parse_csv_row(row, keys)
                                row_dict = self._normalize_function_tree_row(row_dict)
                                if not row_dict:
                                    continue
                                row_dict["file"] = row_dict.get("file_path", "")

                                candidate_name = row_dict["function_name"].replace("\"", "")

                                if (candidate_name == function_name_only
                                        or (less_strict and function_name_only in candidate_name)):
                                    return row_dict, current_function
                except (FileNotFoundError, PermissionError, OSError) as e:
                    raise self._convert_csv_file_error(e, function_tree_file, "Function tree file") from e

            # Try partial matching if less_strict is False
            if not less_strict:
                return self.get_function_by_name(function_tree_file, function_name, all_function, True)
            else:
                err = (
                    f"Function '{function_name}' not found. Make sure you're using "
                    "the correct tool and args."
                )
                return err, None

    def get_macro(
        self,
        curr_db: str,
        macro_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return macro info from Macros.csv for the given macro_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to the current CodeQL database folder.
            macro_name (str): Macro name to search for.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with 'macro_name' and 'body' if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Macros CSV file cannot be read (not found, permission denied, etc.).
        """
        macro_file = Path(curr_db) / "Macros.csv"
        keys = ["macro_name", "body"]

        for macro in self._iter_csv_lines(macro_file, "Macros CSV"):
            if macro_name in macro:
                row_dict = parse_csv_row(macro, keys)
                if not row_dict:
                    continue

                actual_name = row_dict["macro_name"].replace("\"", "")
                if (actual_name == macro_name
                        or (less_strict and macro_name in actual_name)):
                    return row_dict

        if not less_strict:
            return self.get_macro(curr_db, macro_name, True)
        else:
            return (
                f"Macro '{macro_name}' not found. Make sure you're using the correct tool "
                "with correct args."
            )

    def get_global_var(
        self,
        curr_db: str,
        global_var_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return a global variable from GlobalVars.csv matching global_var_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            global_var_name (str): The name of the global variable to find.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with ['global_var_name','file','start_line','end_line'] if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If GlobalVars CSV file cannot be read (not found, permission denied, etc.).
        """
        global_var_file = Path(curr_db) / "GlobalVars.csv"
        keys = ["global_var_name", "file", "start_line", "end_line"]
        var_name_only = global_var_name.split("::")[-1]

        for line in self._iter_csv_lines(global_var_file, "GlobalVars CSV"):
            if var_name_only in line:
                data_dict = parse_csv_row(line, keys)
                if not data_dict:
                    continue

                actual_name = data_dict["global_var_name"].replace("\"", "")
                if (actual_name == var_name_only
                        or (less_strict and var_name_only in actual_name)):
                    return data_dict

        if not less_strict:
            return self.get_global_var(curr_db, global_var_name, True)
        else:
            return (
                f"Global var '{global_var_name}' not found. "
                "Could it be a macro or should you use another tool?"
            )

    def get_class(
        self,
        curr_db: str,
        class_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return class info (type, class_name, file, start_line, end_line, simple_name)
        from Classes.csv for class_name. If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            class_name (str): The name of the class/struct/union to find.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with keys ['type','class_name','file','start_line','end_line','simple_name']
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Classes CSV file cannot be read (not found, permission denied, etc.).
        """
        classes_file = Path(curr_db) / "Classes.csv"
        keys = ["type", "class_name", "simple_name", "file", "start_line", "end_line", "class_id"]
        class_name_only = class_name.split("::")[-1]

        for row in self._iter_csv_lines(classes_file, "Classes CSV"):
            if class_name_only in row:
                row_dict = parse_csv_row(row, keys)
                if not row_dict:
                    continue

                actual_class = row_dict["class_name"].replace("\"", "")
                simple_class = row_dict["simple_name"].replace("\"", "")
                if (
                    actual_class == class_name_only
                    or simple_class == class_name_only
                    or (less_strict and class_name_only in actual_class)
                    or (less_strict and class_name_only in simple_class)
                ):
                    return row_dict

        if not less_strict:
            return self.get_class(curr_db, class_name, True)
        else:
            return f"Class '{class_name}' not found. Could it be a Namespace?"

    def get_caller_function(
        self,
        function_tree_file: str,
        current_function: Dict[str, str]
    ) -> Union[str, Dict[str, str]]:
        """
        Return the caller function from function_tree_file that calls current_function.

        Args:
            function_tree_file (str): Path to FunctionTree.csv.
            current_function (Dict[str, str]): The function dictionary whose caller we want.

        Returns:
            Union[str, Dict[str, str]]:
                - Dict describing the caller if found
                - or an error string if the caller wasn't found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file_path", "start_line", "end_line", "function_id", "caller_ids"]
        caller_ids_raw = (
            current_function.get("caller_id")
            or current_function.get("caller_ids")
            or ""
        )
        caller_ids_raw = caller_ids_raw.replace("\"", "").strip()
        caller_ids = [cid for cid in caller_ids_raw.split("|") if cid and cid != "NONE"]

        for caller_id in caller_ids:
            for line in self._iter_csv_lines(function_tree_file, "Function tree file"):
                if caller_id in line:
                    data_dict = parse_csv_row(line, keys)
                    if not data_dict:
                        continue
                    if data_dict["function_id"].replace("\"", "").strip() == caller_id:
                        data_dict["file"] = data_dict.get("file_path", "")
                        return data_dict

            # Fallback if 'caller_id' is in format file:line
            caller_id_clean = caller_id.strip().strip("\"")
            if ":" in caller_id_clean:
                file_part, line_part = caller_id_clean.rsplit(":", 1)
                line_part = line_part.strip().strip("\"")
                if line_part.isdigit():
                    function = self.get_function_by_line(
                        function_tree_file,
                        file_part.lstrip("/"),
                        int(line_part)
                    )
                    if function:
                        return function


        return (
            "Caller function was not found. "
            "Make sure you are using the correct tool with the correct args."
        )

    def extract_function_lines_from_db(
        self,
        db_path: str,
        current_function: Dict[str, str],
        max_chars: Optional[int] = None
    ) -> Tuple[str, int, int, List[str]]:
        """
        Extract function lines from the CodeQL database source archive.

        Args:
            db_path (str): Path to the CodeQL database directory.
            current_function (Dict[str, str]): The function dictionary.
            max_chars (Optional[int]): Maximum characters to extract. If None, no limit.

        Returns:
            Tuple[str, int, int, List[str]]:
                - file_path (str): The file path (standardized for ZIP reading)
                - start_line (int): Starting line number
                - end_line (int): Ending line number
                - all_lines (List[str]): Full file splitlines

        Raises:
            CodeQLError: If ZIP file cannot be read or file not found in archive.
        """
        src_zip = Path(db_path) / "src.zip"
        # 使用路径标准化模块处理路径，避免 [1:] 的问题
        file_path = extract_function_lines_path(current_function["file"])
        code_file = read_file_lines_from_zip(str(src_zip), file_path)
        lines = code_file.split("\n")

        start_line = int(current_function["start_line"])
        end_line = int(current_function["end_line"])

        # Truncate if max_chars is specified
        if max_chars:
            snippet_lines = lines[start_line - 1:end_line]
            snippet = "\n".join(
                f"{start_line - 1 + i}: {text}" for i, text in enumerate(snippet_lines)
            )
            if len(snippet) > max_chars:
                snippet = snippet[:max_chars] + "\n... (truncated due to length limits)"
                logger.warning(f"Function code truncated to {max_chars} chars for {file_path}")
                # Return truncated lines
                truncated_lines = snippet.split("\n")[1:]  # Remove "file: path" prefix
                return file_path, start_line, end_line, truncated_lines

        return file_path, start_line, end_line, lines

    def format_numbered_snippet(
        self,
        file_path: str,
        start_line: int,
        snippet_lines: List[str],
        max_chars: Optional[int] = None
    ) -> str:
        """
        Format a code snippet with line numbers.

        Args:
            file_path (str): Path to the source file.
            start_line (int): Starting line number (1-indexed).
            snippet_lines (List[str]): The code lines to format.
            max_chars (Optional[int]): Maximum characters to return. If None, no limit.

        Returns:
            str: Formatted snippet with line numbers.
        """
        snippet = "\n".join(
            f"{start_line - 1 + i}: {text}" for i, text in enumerate(snippet_lines)
        )

        # Token fuse: Truncate if too long
        if max_chars and len(snippet) > max_chars:
            snippet = snippet[:max_chars] + "\n... (truncated due to length limits)"
            logger.warning(f"Function code truncated to {max_chars} chars for {file_path}")

        return f"file: {file_path}\n{snippet}"

    def clear_cache(self, older_than_days: int = 30) -> int:
        """
        Clear cache entries older than specified days.

        Args:
            older_than_days: Delete entries older than this many days. Defaults to 30.

        Returns:
            Number of entries deleted.
        """
        return self.cache_manager.clear(older_than_days)

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics (total_entries, hit_rate, etc.).
        """
        return self.cache_manager.get_stats()

    # ============================================================================
    # Phase 1: Enhanced Agent Tools
    # ============================================================================

    def search_code_pattern(
        self,
        db_path: str,
        pattern: str,
        file_filter: Optional[str] = None,
        max_results: int = 10
    ) -> Union[str, List[Dict[str, Any]]]:
        """
        Search for code patterns using regex in the source archive.

        Args:
            db_path: Path to the CodeQL database folder.
            pattern: Regex pattern to search for.
            file_filter: Optional file filter (e.g., '*.c', '*.java').
            max_results: Maximum number of results to return.

        Returns:
            Union[str, List[Dict]]: List of matches with file, line, and snippet,
                                   or error message string if nothing found.
        """
        import re

        src_zip = Path(db_path) / "src.zip"
        if not src_zip.exists():
            return "Source archive not found in database."

        import zipfile
        matches = []

        try:
            with zipfile.ZipFile(str(src_zip), 'r') as zf:
                file_list = zf.namelist()

                # Apply file filter if provided
                if file_filter:
                    import fnmatch
                    file_list = [f for f in file_list if fnmatch.fnmatch(f, file_filter)]

                for file_path in file_list:
                    if not file_path.endswith(('.c', '.cpp', '.h', '.java', '.js', '.ts', '.py', '.go', '.cs')):
                        continue

                    try:
                        content = zf.read(file_path).decode('utf-8', errors='ignore')
                        lines = content.split('\n')

                        for line_num, line in enumerate(lines, 1):
                            if re.search(pattern, line):
                                # Get context (3 lines before and after)
                                start_ctx = max(0, line_num - 4)
                                end_ctx = min(len(lines), line_num + 3)
                                context = '\n'.join(f"{i}: {lines[i-1]}" for i in range(start_ctx + 1, end_ctx + 1))

                                matches.append({
                                    'file': file_path,
                                    'line': line_num,
                                    'match': line.strip(),
                                    'context': context
                                })

                                if len(matches) >= max_results:
                                    break

                    except Exception:
                        continue

                    if len(matches) >= max_results:
                        break

        except zipfile.BadZipFile:
            return "Invalid ZIP archive in database."
        except Exception as e:
            return f"Error searching code: {str(e)}"

        if not matches:
            return f"No matches found for pattern: {pattern}"

        return matches

    def get_callee_functions(
        self,
        function_tree_file: str,
        current_function: Dict[str, str]
    ) -> Union[str, List[Dict[str, str]]]:
        """
        Get the list of functions that are called by the current function.

        Args:
            function_tree_file: Path to FunctionTree.csv.
            current_function: The function dictionary.

        Returns:
            Union[str, List[Dict]]: List of callee functions or error message.
        """
        keys = ["function_name", "file_path", "start_line", "end_line", "function_id", "caller_ids"]

        # Get the function_id to find callees
        current_func_id = current_function.get("function_id", "")
        if not current_func_id:
            return "Current function has no function_id."

        callees = []

        try:
            with Path(function_tree_file).open("r", encoding="utf-8") as f:
                while True:
                    row = f.readline()
                    if not row:
                        break

                    # Check if this function is called by current function
                    # by searching for current_func_id in the row
                    if current_func_id in row:
                        row_dict = parse_csv_row(row, keys)
                        row_dict = self._normalize_function_tree_row(row_dict)
                        if not row_dict:
                            continue

                        # Check if it's actually a callee (not the function itself)
                        if row_dict.get("function_id") != current_func_id:
                            row_dict["file"] = row_dict.get("file_path", "")
                            callees.append(row_dict)

        except (FileNotFoundError, PermissionError, OSError) as e:
            return f"Error reading function tree: {str(e)}"

        if not callees:
            # Try alternative approach: search for function calls in the code
            return "No direct callees found in function tree. Try analyzing the source code directly."

        return callees[:10]  # Limit to top 10

    def analyze_data_flow(
        self,
        db_path: str,
        function_tree_file: str,
        variable_name: str,
        current_function: Dict[str, str],
        max_depth: int = 3
    ) -> Union[str, Dict[str, Any]]:
        """
        Analyze the data flow of a variable within a function.

        Args:
            db_path: Path to the CodeQL database folder.
            function_tree_file: Path to FunctionTree.csv.
            variable_name: Name of the variable to trace.
            current_function: The function dictionary.
            max_depth: Maximum depth to trace.

        Returns:
            Union[str, Dict]: Data flow analysis results or error message.
        """
        # This is a simplified implementation
        # Full implementation would require CodeQL data flow queries

        src_zip = Path(db_path) / "src.zip"
        if not src_zip.exists():
            return "Source archive not found."

        # Extract the function code
        try:
            file_path, start_line, end_line, lines = self.extract_function_lines_from_db(
                db_path, current_function, max_chars=50000
            )

            function_code = '\n'.join(lines[start_line-1:end_line])

            # Simple analysis: find variable definitions and usages
            import re

            # Find variable declarations/definitions
            var_definitions = []
            var_usages = []

            for line_num, line in enumerate(lines[start_line-1:end_line], start=start_line):
                # Check for assignment (definition)
                if re.search(rf'\b{variable_name}\s*=', line):
                    var_definitions.append({
                        'line': line_num,
                        'code': line.strip()
                    })
                # Check for usage
                if re.search(rf'\b{variable_name}\b', line):
                    var_usages.append({
                        'line': line_num,
                        'code': line.strip()
                    })

            return {
                'variable': variable_name,
                'function': current_function.get('function_name', 'unknown'),
                'definitions': var_definitions,
                'usages': var_usages,
                'note': 'This is a static analysis. For full data flow, use CodeQL SARIF output.'
            }

        except Exception as e:
            return f"Error analyzing data flow: {str(e)}"

    def get_file_dependencies(
        self,
        db_path: str,
        file_path: str
    ) -> Union[str, List[str]]:
        """
        Get the list of files that the given file depends on (imports/includes).

        Args:
            db_path: Path to the CodeQL database folder.
            file_path: Path to the file (relative to source root).

        Returns:
            Union[str, List[str]]: List of dependencies or error message.
        """
        src_zip = Path(db_path) / "src.zip"
        if not src_zip.exists():
            return "Source archive not found."

        import zipfile
        import re

        try:
            with zipfile.ZipFile(str(src_zip), 'r') as zf:
                # Normalize the file path for ZIP
                normalized_path = file_path.replace('\\', '/')

                try:
                    content = zf.read(normalized_path).decode('utf-8', errors='ignore')
                except KeyError:
                    # Try alternative path formats
                    alt_paths = [
                        normalized_path.lstrip('/'),
                        normalized_path.replace('/', '\\'),
                    ]
                    content = None
                    for alt in alt_paths:
                        try:
                            content = zf.read(alt).decode('utf-8', errors='ignore')
                            normalized_path = alt
                            break
                        except KeyError:
                            continue

                    if content is None:
                        return f"File not found in archive: {file_path}"

                # Extract includes/imports based on language
                dependencies = []

                # C/C++ #include
                for match in re.finditer(r'#include\s*[<\"]([^>\"]+)[>\"]', content):
                    dependencies.append({
                        'type': 'include',
                        'target': match.group(1)
                    })

                # Java import
                for match in re.finditer(r'import\s+([\w.]+);', content):
                    dependencies.append({
                        'type': 'import',
                        'target': match.group(1)
                    })

                # JavaScript/TypeScript import/require
                for match in re.finditer(r'(?:import|require)\s*[(|\']?([\w.@/-]+)', content):
                    deps = match.group(1)
                    if not deps.startswith('.'):
                        dependencies.append({
                            'type': 'module',
                            'target': deps
                        })

                if not dependencies:
                    return "No dependencies found in file."

                return dependencies[:20]  # Limit

        except zipfile.BadZipFile:
            return "Invalid ZIP archive."
        except Exception as e:
            return f"Error analyzing dependencies: {str(e)}"
