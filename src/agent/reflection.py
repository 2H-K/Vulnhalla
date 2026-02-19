#!/usr/bin/env python3
"""
Reflection Mechanism for Vulnhalla AI Agent.

This module implements the reflection (self-correction) mechanism for the LLM agent.
It provides:
1. Confidence assessment - determines if the LLM should reflect on its answer
2. Reflection prompt generation - generates prompts for self-correction
3. Iteration control - prevents infinite loops

Phase 2: Multi-turn Dialogue and Reflection Mechanism
"""

import re
from typing import Any, Dict, List, Optional, Tuple


class ReflectionConfig:
    """Configuration for reflection mechanism."""
    
    def __init__(
        self,
        enabled: bool = True,
        max_iterations: int = 3,
        confidence_threshold: float = 0.7,
        low_confidence_keywords: Optional[List[str]] = None,
        reflection_prompts: Optional[Dict[str, str]] = None
    ):
        """
        Initialize reflection configuration.
        
        Args:
            enabled: Whether reflection is enabled.
            max_iterations: Maximum number of reflection iterations.
            confidence_threshold: Threshold for confidence assessment (0-1).
            low_confidence_keywords: Keywords that indicate low confidence.
            reflection_prompts: Custom reflection prompts.
        """
        self.enabled = enabled
        self.max_iterations = max_iterations
        self.confidence_threshold = confidence_threshold
        self.low_confidence_keywords = low_confidence_keywords or [
            "uncertain", "not sure", "cannot determine", "insufficient information",
            "need more", "may be", "possibly", "probably", "might"
        ]
        self.reflection_prompts = reflection_prompts or self._default_reflection_prompts()
    
    def _default_reflection_prompts(self) -> Dict[str, str]:
        """Get default reflection prompts."""
        return {
            "general": (
                "Please reconsider your previous analysis with the following considerations:\n"
                "1. Are there any business logic validation points you might have missed?\n"
                "2. Are there any edge cases or boundary conditions that could affect this issue?\n"
                "3. Is there any sanitization or validation that might prevent this from being exploitable?\n"
                "4. Consider the context: who controls the input, where does it flow, what is the impact?\n"
            ),
            "false_positive": (
                "You previously marked this as a security issue. Please re-examine carefully:\n"
                "1. Is there any input validation or sanitization before the sink?\n"
                "2. Are there any security checks (authentication, authorization) that protect this code path?\n"
                "3. Is the data source trusted or already validated?\n"
                "4. Could this be a false positive due to incomplete context?\n"
            ),
            "true_positive": (
                "You previously marked this as safe. Please reconsider:\n"
                "1. Could an attacker control the input to this sink?\n"
                "2. Is there any path from user input to this point without proper validation?\n"
                "3. What is the potential impact if this is exploited?\n"
                "4. Are you confident there are no bypasses for any existing checks?\n"
            ),
            "need_more_data": (
                "You indicated more data is needed. Before requesting more tools:\n"
                "1. Can you make a reasonable determination with the current context?\n"
                "2. If you must use tools, prioritize the most critical ones.\n"
                "3. Consider: is this a clear true positive or false positive?\n"
                "4. Remember: it's better to make a decision than to always ask for more data.\n"
            )
        }


class ReflectionAgent:
    """
    Reflection mechanism for the Vulnhalla agent.
    
    This class handles:
    - Assessing whether the LLM should reflect on its answer
    - Generating reflection prompts for self-correction
    - Tracking iteration count to prevent infinite loops
    """
    
    def __init__(self, config: Optional[ReflectionConfig] = None):
        """
        Initialize the reflection agent.
        
        Args:
            config: Reflection configuration. If None, uses defaults.
        """
        self.config = config or ReflectionConfig()
        self.iteration = 0
        self.context_history: List[Dict[str, Any]] = []
        self.reflection_history: List[str] = []
    
    def reset(self) -> None:
        """Reset the reflection state for a new issue."""
        self.iteration = 0
        self.context_history = []
        self.reflection_history = []
    
    def should_reflect(self, llm_response: str) -> bool:
        """
        Determine if the LLM should reflect on its response.
        
        Args:
            llm_response: The LLM's response to evaluate.
            
        Returns:
            bool: True if reflection is needed, False otherwise.
        """
        if not self.config.enabled:
            return False
        
        # Check for "need more data" status codes
        if "7331" in llm_response:
            return True
        
        # Check for low confidence keywords
        response_lower = llm_response.lower()
        keyword_count = sum(
            1 for keyword in self.config.low_confidence_keywords
            if keyword in response_lower
        )
        
        # If multiple low confidence keywords, suggest reflection
        if keyword_count >= 2:
            return True
        
        # Check for hedging language
        hedging_patterns = [
            r"\bmight\b", r"\bmay\b", r"\bcould\b", r"\bpossibly\b",
            r"\bprobably\b", r"\bperhaps\b", r"\bi think\b", r"\bi believe\b"
        ]
        
        hedging_count = sum(
            len(re.findall(pattern, response_lower))
            for pattern in hedging_patterns
        )
        
        if hedging_count >= 2:
            return True
        
        return False
    
    def assess_confidence(self, llm_response: str) -> float:
        """
        Assess the confidence level of the LLM's response.
        
        Args:
            llm_response: The LLM's response to evaluate.
            
        Returns:
            float: Confidence score between 0 and 1.
        """
        # Start with base confidence
        confidence = 0.8
        
        # Check for definitive status codes
        if "1337" in llm_response or "1007" in llm_response:
            confidence += 0.1
        
        # Check for "need more data" - lower confidence
        if "7331" in llm_response:
            confidence -= 0.2
        
        # Deduct for hedging language
        response_lower = llm_response.lower()
        hedging_patterns = [
            r"\bmight\b", r"\bmay\b", r"\bcould\b", r"\bpossibly\b",
            r"\bprobably\b", r"\bperhaps\b", r"\bi think\b", r"\bi believe\b"
        ]
        
        hedging_count = sum(
            len(re.findall(pattern, response_lower))
            for pattern in hedging_patterns
        )
        
        confidence -= (hedging_count * 0.05)
        
        # Deduct for low confidence keywords
        keyword_count = sum(
            1 for keyword in self.config.low_confidence_keywords
            if keyword in response_lower
        )
        
        confidence -= (keyword_count * 0.08)
        
        # Ensure confidence stays within bounds
        return max(0.0, min(1.0, confidence))
    
    def generate_reflection_prompt(
        self,
        llm_response: str,
        issue_info: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Generate a reflection prompt for the LLM.
        
        Args:
            llm_response: The LLM's response that triggered reflection.
            issue_info: Optional issue information for context.
            
        Returns:
            str: The reflection prompt to send to the LLM.
        """
        self.iteration += 1
        
        # Determine the type of reflection needed
        if "7331" in llm_response:
            reflection_type = "need_more_data"
        elif "1337" in llm_response:
            reflection_type = "false_positive"  # Reconsider if it's really a vulnerability
        elif "1007" in llm_response:
            reflection_type = "true_positive"  # Reconsider if it's really safe
        else:
            reflection_type = "general"
        
        # Get the base reflection prompt
        base_prompt = self.config.reflection_prompts.get(
            reflection_type,
            self.config.reflection_prompts["general"]
        )
        
        # Add iteration context
        iteration_context = (
            f"\n\n[Reflection Round {self.iteration}/{self.config.max_iterations}]\n"
            f"This is iteration {self.iteration} of analysis. "
        )
        
        if self.iteration >= self.config.max_iterations:
            iteration_context += (
                "You have reached the maximum number of reflection rounds. "
                "Please provide your best final determination now. "
                "Use status code 1337 (vulnerable) or 1007 (safe) as your final answer.\n"
            )
        else:
            iteration_context += (
                f"You have {self.config.max_iterations - self.iteration} "
                "more round(s) if needed. Please provide your analysis.\n"
            )
        
        # Add issue context if available
        issue_context = ""
        if issue_info:
            issue_context = (
                f"\n\nIssue Context:\n"
                f"- Type: {issue_info.get('name', 'Unknown')}\n"
                f"- File: {issue_info.get('file', 'Unknown')}\n"
                f"- Line: {issue_info.get('start_line', 'Unknown')}\n"
            )
        
        # Combine all parts
        reflection_prompt = (
            f"{base_prompt}\n"
            f"{iteration_context}\n"
            f"{issue_context}\n"
            f"Previous analysis:\n{llm_response[:500]}...\n\n"
            "Please provide your refined analysis with a clear status code:\n"
            "- 1337: Confirmed vulnerability (true positive)\n"
            "- 1007: Confirmed safe (false positive)\n"
            "- 7331: Still need more data (only if absolutely necessary)\n"
        )
        
        # Track reflection
        self.reflection_history.append(reflection_prompt)
        
        return reflection_prompt
    
    def can_continue(self) -> bool:
        """
        Check if reflection can continue (hasn't exceeded max iterations).
        
        Returns:
            bool: True if more reflection is allowed, False otherwise.
        """
        return self.iteration < self.config.max_iterations
    
    def add_context(self, context: Dict[str, Any]) -> None:
        """
        Add context information to the history.
        
        Args:
            context: Context information to add.
        """
        self.context_history.append(context)
    
    def get_context_summary(self) -> str:
        """
        Get a summary of the context history.
        
        Returns:
            str: Summary of context history.
        """
        if not self.context_history:
            return "No previous context."
        
        summary_parts = []
        for i, ctx in enumerate(self.context_history, 1):
            tool_used = ctx.get("tool_used", "unknown")
            result_preview = str(ctx.get("result", ""))[:100]
            summary_parts.append(f"{i}. {tool_used}: {result_preview}...")
        
        return "\n".join(summary_parts)
    
    def is_confident_enough(self, llm_response: str) -> Tuple[bool, float]:
        """
        Check if the response is confident enough to accept.
        
        Args:
            llm_response: The LLM's response to evaluate.
            
        Returns:
            Tuple[bool, float]: (is_confident, confidence_score).
        """
        confidence = self.assess_confidence(llm_response)
        is_confident = confidence >= self.config.confidence_threshold
        return is_confident, confidence


def create_reflection_agent(
    enabled: bool = True,
    max_iterations: int = 3,
    **kwargs
) -> ReflectionAgent:
    """
    Convenience function to create a reflection agent.
    
    Args:
        enabled: Whether reflection is enabled.
        max_iterations: Maximum number of iterations.
        **kwargs: Additional configuration options.
        
    Returns:
        ReflectionAgent: Configured reflection agent.
    """
    config = ReflectionConfig(
        enabled=enabled,
        max_iterations=max_iterations,
        **kwargs
    )
    return ReflectionAgent(config)
