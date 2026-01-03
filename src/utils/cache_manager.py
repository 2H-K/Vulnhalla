#!/usr/bin/env python3
"""
Cache manager for LLM API calls.
Provides local caching using SQLite to avoid redundant API calls and reduce costs.
"""
import sqlite3
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

from src.utils.logger import get_logger

logger = get_logger(__name__)


class CacheManager:
    """
    Manages LLM response caching using SQLite database.
    Suitable for personal computer environments with minimal dependencies.
    """
    
    def __init__(self, cache_dir: str = "output/cache", enabled: bool = True):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory to store cache database. Defaults to "output/cache".
            enabled: Whether caching is enabled. Defaults to True.
        """
        self.cache_dir = Path(cache_dir)
        self.enabled = enabled
        self.cache_file = self.cache_dir / "llm_cache.db"
        
        # Initialize cache database
        if self.enabled:
            self._init_cache_db()
    
    def _init_cache_db(self) -> None:
        """Initialize SQLite database for caching."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self.cache_file))
        cursor = conn.cursor()
        
        # Create cache table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS llm_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prompt_hash TEXT UNIQUE NOT NULL,
                prompt TEXT NOT NULL,
                response TEXT NOT NULL,
                model TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count INTEGER DEFAULT 1,
                last_hit TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create index for faster lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_prompt_hash ON llm_cache(prompt_hash)")
        
        conn.commit()
        conn.close()
        
        logger.info(f"Cache database initialized at: {self.cache_file}")
    
    def _hash_prompt(self, prompt: str) -> str:
        """
        Generate SHA-256 hash of the prompt for cache key.
        
        Args:
            prompt: The prompt text to hash.
        
        Returns:
            SHA-256 hash string.
        """
        return hashlib.sha256(prompt.encode('utf-8')).hexdigest()
    
    def get(self, prompt: str, model: str) -> Optional[str]:
        """
        Retrieve cached response for given prompt and model.
        
        Args:
            prompt: The prompt text.
            model: The model name used.
        
        Returns:
            Cached response if found and valid, None otherwise.
        """
        if not self.enabled:
            return None
        
        prompt_hash = self._hash_prompt(prompt)
        
        try:
            conn = sqlite3.connect(str(self.cache_file))
            cursor = conn.cursor()
            
            # Query cache with hash and model match
            cursor.execute("""
                SELECT response FROM llm_cache
                WHERE prompt_hash = ? AND model = ?
                ORDER BY last_hit DESC
                LIMIT 1
            """, (prompt_hash, model))
            
            result = cursor.fetchone()
            
            if result:
                # Update hit count and last hit time
                cursor.execute("""
                    UPDATE llm_cache
                    SET hit_count = hit_count + 1, last_hit = CURRENT_TIMESTAMP
                    WHERE prompt_hash = ? AND model = ?
                """, (prompt_hash, model))
                conn.commit()
                
                logger.debug(f"Cache HIT for model {model} (hash: {prompt_hash[:16]}...)")
                return result[0]
            else:
                logger.debug(f"Cache MISS for model {model} (hash: {prompt_hash[:16]}...)")
                return None
                
        except sqlite3.Error as e:
            logger.error(f"Cache database error: {e}")
            return None
        finally:
            conn.close()
    
    def set(self, prompt: str, response: str, model: str) -> None:
        """
        Store response in cache.
        
        Args:
            prompt: The prompt text.
            response: The LLM response to cache.
            model: The model name used.
        """
        if not self.enabled:
            return
        
        prompt_hash = self._hash_prompt(prompt)
        
        try:
            conn = sqlite3.connect(str(self.cache_file))
            cursor = conn.cursor()
            
            # Insert or replace existing cache entry
            cursor.execute("""
                INSERT OR REPLACE INTO llm_cache (prompt_hash, prompt, response, model, hit_count)
                VALUES (?, ?, ?, ?, 1)
            """, (prompt_hash, prompt, response, model))
            
            conn.commit()
            logger.debug(f"Cached response for model {model} (hash: {prompt_hash[:16]}...)")
            
        except sqlite3.Error as e:
            logger.error(f"Failed to cache response: {e}")
        finally:
            conn.close()
    
    def clear(self, older_than_days: int = 30) -> int:
        """
        Clear cache entries older than specified days.
        
        Args:
            older_than_days: Delete entries older than this many days. Defaults to 30.
        
        Returns:
            Number of entries deleted.
        """
        if not self.enabled:
            return 0
        
        cutoff_date = datetime.now() - timedelta(days=older_than_days)
        
        try:
            conn = sqlite3.connect(str(self.cache_file))
            cursor = conn.cursor()
            
            # Delete old entries
            cursor.execute("""
                DELETE FROM llm_cache WHERE created_at < ?
            """, (cutoff_date.isoformat(),))
            
            deleted = cursor.rowcount
            conn.commit()
            
            logger.info(f"Cleared {deleted} cache entries older than {older_than_days} days")
            return deleted
            
        except sqlite3.Error as e:
            logger.error(f"Failed to clear cache: {e}")
            return 0
        finally:
            conn.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics (total_entries, hit_rate, etc.).
        """
        if not self.enabled:
            return {"enabled": False}
        
        try:
            conn = sqlite3.connect(str(self.cache_file))
            cursor = conn.cursor()
            
            # Get total entries
            cursor.execute("SELECT COUNT(*) as total FROM llm_cache")
            total = cursor.fetchone()[0]
            
            # Get total hits
            cursor.execute("SELECT SUM(hit_count) as total_hits FROM llm_cache")
            total_hits = cursor.fetchone()[0] or 0
            
            # Get oldest and newest entries
            cursor.execute("SELECT MIN(created_at) as oldest, MAX(created_at) as newest FROM llm_cache")
            oldest_newest = cursor.fetchone()
            
            conn.close()
            
            return {
                "enabled": True,
                "total_entries": total,
                "total_hits": total_hits,
                "cache_file": str(self.cache_file),
                "oldest_entry": oldest_newest[0] if oldest_newest else None,
                "newest_entry": oldest_newest[1] if oldest_newest else None
            }
            
        except sqlite3.Error as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"enabled": False, "error": str(e)}
