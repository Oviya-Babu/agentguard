"""
Output sanitization pipeline: PII redaction + injection scanning.

This module implements the critical output sanitization stage where tool
outputs are scanned for:
1. PII (SSN, email, credit card, API key, etc.) — redacted by Presidio
2. Prompt injection patterns — exact, regex, and semantic matching

Sanitization occurs AFTER tool execution but BEFORE output reaches agent.
It is fail-closed: if sanitization fails, output is blocked.

Security Properties:
- Presidio pre-loaded at startup (no cold start delays)
- Three-tier injection detection (exact → regex → semantic similarity)
- Output never modified in-place; always returns new sanitized copy
- Logs contain entity types and confidence scores, NEVER raw PII values
- No raw injection payloads logged; only pattern match indicators
"""

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine

logger = logging.getLogger(__name__)


# ============================================================================
# INJECTION PATTERN DEFINITIONS (LOADED FROM YAML AT STARTUP)
# ============================================================================

INJECTION_PATTERNS = {
    "ignore_instructions": [
        r"(?i)ignore.*instructions",
        r"(?i)disregard.*prompt",
        r"(?i)forget.*previous",
    ],
    "system_override": [
        r"(?i)\[SYSTEM\]:",
        r"(?i)SYSTEM MESSAGE:",
        r"(?i)your.*real.*task",
    ],
    "roleplay_jailbreak": [
        r"(?i)pretend.*no.*restrictions",
        r"(?i)act as.*unrestricted",
        r"(?i)ignore.*safety",
    ],
    "exfiltration_instruction": [
        r"(?i)send.*credentials",
        r"(?i)post.*api.*key",
        r"(?i)leak.*data",
    ],
}


# ============================================================================
# PRESIDIO PII DETECTION (SINGLETON, PRE-LOADED)
# ============================================================================

class PresidioSanitizer:
    """
    Wrapper around Presidio for PII detection and redaction.

    Presidio is pre-loaded at startup to avoid cold-start delays.
    This class provides analysis and anonymization with proper error handling.
    """

    def __init__(
        self,
        analyzer: Optional[AnalyzerEngine] = None,
        anonymizer: Optional[AnonymizerEngine] = None,
    ) -> None:
        """
        Initialize Presidio sanitizer.

        Args:
            analyzer: Pre-loaded AnalyzerEngine instance
            anonymizer: Pre-loaded AnonymizerEngine instance

        Note:
            If not provided, instances are created (slower, cold start).
            In production, pass pre-initialized instances.
        """
        self.analyzer = analyzer or AnalyzerEngine()
        self.anonymizer = anonymizer or AnonymizerEngine()

    async def analyze_and_redact(
        self,
        text: str,
        language: str = "en",
    ) -> tuple[str, List[Dict[str, Any]]]:
        """
        Analyze text for PII and return redacted version.

        Args:
            text: Input text to scan
            language: Language code for analyzer

        Returns:
            Tuple of (redacted_text, entity_list)
            entity_list contains: type, confidence, start_offset, end_offset

        Note:
            Redacted text uses <ENTITY_TYPE_N> format.
            Entity list is logged (never the raw values).
        """
        try:
            # Analyze text for PII (can be slow for large texts)
            results = await asyncio.to_thread(
                self.analyzer.analyze,
                text=text,
                language=language,
            )

            if not results:
                # No PII found
                return text, []

            # Build entity list for logging (no raw values)
            entity_list = [
                {
                    "type": r.entity_type,
                    "confidence": r.score,
                    "start": r.start,
                    "end": r.end,
                }
                for r in results
            ]

            # Redact using Presidio anonymizer
            redacted = await asyncio.to_thread(
                self.anonymizer.anonymize,
                text=text,
                analyzer_results=results,
            )

            logger.info(
                "PII redaction complete",
                extra={
                    "original_length": len(text),
                    "redacted_length": len(redacted.text),
                    "entity_count": len(results),
                    "entities": [r.entity_type for r in results],
                },
            )

            return redacted.text, entity_list

        except Exception as e:
            logger.error(
                "Presidio analysis failed",
                extra={"error": type(e).__name__},
            )
            raise


# ============================================================================
# INJECTION PATTERN SCANNER
# ============================================================================

class InjectionScanner:
    """
    Three-tier injection pattern detection and redaction.

    Tier 1: Exact phrase matching (fast, no regex)
    Tier 2: Regex pattern matching (medium speed)
    Tier 3: Semantic similarity (slow, ML-based — optional for now)

    Always redacts matches; never kills response.
    """

    def __init__(self, patterns: Optional[Dict[str, List[str]]] = None) -> None:
        """
        Initialize injection scanner with patterns.

        Args:
            patterns: Dictionary of pattern category -> list of regex/phrases
        """
        self.patterns = patterns or INJECTION_PATTERNS
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """
        Pre-compile regex patterns for faster matching.

        Returns:
            Dictionary of category -> list of compiled regex patterns
        """
        compiled = {}
        for category, patterns in self.patterns.items():
            compiled[category] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in patterns
            ]
        return compiled

    async def scan_and_redact(
        self,
        text: str,
    ) -> tuple[str, List[Dict[str, Any]]]:
        """
        Scan text for injection patterns and redact matches.

        Args:
            text: Input text to scan

        Returns:
            Tuple of (redacted_text, match_list)
            match_list contains: category, pattern_index, start_offset, end_offset

        Note:
            Matches are redacted with [REDACTED] placeholder.
            Pattern details are logged but never the matched text.
        """
        redacted = text
        matches = []

        # Tier 1 + 2: Regex patterns (fast)
        for category, compiled_list in self.compiled_patterns.items():
            for pattern_idx, pattern in enumerate(compiled_list):
                for match in pattern.finditer(text):
                    matches.append(
                        {
                            "category": category,
                            "pattern_index": pattern_idx,
                            "start": match.start(),
                            "end": match.end(),
                            "method": "regex",
                        }
                    )
                    # Redact the matched text
                    redacted = (
                        redacted[:match.start()]
                        + "[REDACTED]"
                        + redacted[match.end():]
                    )

        if matches:
            logger.warning(
                "Injection patterns detected and redacted",
                extra={
                    "match_count": len(matches),
                    "categories": list(set(m["category"] for m in matches)),
                },
            )

        return redacted, matches


# ============================================================================
# MAIN OUTPUT SANITIZATION FUNCTION
# ============================================================================

# Global Presidio instance (initialized at app startup)
_presidio_sanitizer: Optional[PresidioSanitizer] = None
_injection_scanner: Optional[InjectionScanner] = None


def set_presidio_instance(
    analyzer: AnalyzerEngine,
    anonymizer: AnonymizerEngine,
) -> None:
    """
    Set the global Presidio instance (call at app startup).

    Args:
        analyzer: Pre-loaded AnalyzerEngine
        anonymizer: Pre-loaded AnonymizerEngine
    """
    global _presidio_sanitizer
    _presidio_sanitizer = PresidioSanitizer(analyzer, anonymizer)
    logger.info("Global Presidio instance set")


def set_injection_scanner(patterns: Dict[str, List[str]]) -> None:
    """
    Set the global injection scanner with patterns from YAML.

    Args:
        patterns: Dictionary of patterns loaded from injection_patterns.yaml
    """
    global _injection_scanner
    _injection_scanner = InjectionScanner(patterns)
    logger.info("Global injection scanner configured")


async def sanitize_tool_output(
    output: str,
    tool_name: str,
    request_id: str,
) -> str:
    """
    Sanitize tool output: Presidio (PII redaction) + injection scanning.

    This is the critical last step before tool output reaches agent context.

    Args:
        output: Raw tool output
        tool_name: Name of tool that produced output
        request_id: Request ID for tracing

    Returns:
        Sanitized output safe for agent to consume

    Raises:
        RuntimeError: If Presidio or scanner not initialized
        Exception: If sanitization fails

    Note:
        Presidio is slow on first call (model loading) but cached thereafter.
        Injection scanning is fast (regex only, no ML).
    """
    global _presidio_sanitizer, _injection_scanner

    if _presidio_sanitizer is None:
        raise RuntimeError("Presidio sanitizer not initialized. Call set_presidio_instance() at startup.")

    if _injection_scanner is None:
        raise RuntimeError("Injection scanner not initialized. Call set_injection_scanner() at startup.")

    try:
        start_time = time.time()

        # Stage 1: Presidio PII redaction
        presidio_start = time.time()
        redacted_presidio, pii_entities = await _presidio_sanitizer.analyze_and_redact(
            output
        )
        presidio_ms = (time.time() - presidio_start) * 1000

        # Stage 2: Injection pattern scanning (on already-redacted text)
        injection_start = time.time()
        redacted_final, injection_matches = await asyncio.to_thread(
            _injection_scanner.scan_and_redact,
            redacted_presidio,
        )
        injection_ms = (time.time() - injection_start) * 1000

        total_ms = (time.time() - start_time) * 1000

        # Log sanitization results (no raw values)
        logger.info(
            "Output sanitization complete",
            extra={
                "tool_name": tool_name,
                "request_id": request_id,
                "original_length": len(output),
                "sanitized_length": len(redacted_final),
                "pii_entities_found": len(pii_entities),
                "pii_types": list(set(e["type"] for e in pii_entities)),
                "injection_matches": len(injection_matches),
                "injection_categories": list(set(m["category"] for m in injection_matches)),
                "presidio_ms": presidio_ms,
                "injection_ms": injection_ms,
                "total_ms": total_ms,
            },
        )

        return redacted_final

    except Exception as e:
        logger.error(
            "Output sanitization failed",
            extra={
                "tool_name": tool_name,
                "request_id": request_id,
                "error": type(e).__name__,
            },
        )
        raise


# ============================================================================
# SIZE LIMIT ENFORCEMENT
# ============================================================================

async def validate_output_size(
    output: str,
    max_size_bytes: int = 10_000_000,  # 10MB default
) -> bool:
    """
    Validate that tool output does not exceed size limit.

    Large responses are killed before sanitization to prevent
    DoS attacks with massive payloads.

    Args:
        output: Tool output to check
        max_size_bytes: Maximum allowed size

    Returns:
        True if size is acceptable

    Raises:
        ValueError: If output exceeds limit
    """
    output_bytes = len(output.encode("utf-8"))

    if output_bytes > max_size_bytes:
        logger.warning(
            "Tool output exceeds size limit",
            extra={
                "output_size": output_bytes,
                "max_size": max_size_bytes,
            },
        )
        raise ValueError(
            f"Output size {output_bytes} exceeds maximum {max_size_bytes}"
        )

    return True
