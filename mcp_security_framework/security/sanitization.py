"""
Context Sanitization Middleware for MCP Security Framework

Strips hidden instructions and malicious payloads from incoming tool data
before it reaches the orchestrating LLM.
"""

from typing import Any, Dict, List, Union
import re


class PayloadSanitizer:
    """
    Sanitizes text and JSON payloads to prevent indirect prompt injections.
    """
    def __init__(self):
        # Common prompt injection patterns
        self.suspicious_patterns = [
            re.compile(r"(?i)(ignore previous instructions)"),
            re.compile(r"(?i)(system prompt)"),
            re.compile(r"(?i)(you are now)"),
            re.compile(r"\[/?hidden\]")
        ]
        
    def sanitize_text(self, text: str) -> str:
        """Sanitize a text string by neutralizing known injection patterns."""
        if not isinstance(text, str):
            return text

        sanitized = text
        for pattern in self.suspicious_patterns:
            # Replace suspicious patterns with a neutral string
            sanitized = pattern.sub("[REDACTED_INSTRUCTION]", sanitized)
            
        return sanitized

    def sanitize_text_with_report(self, text: str) -> Dict[str, Any]:
        """Sanitize text and return redaction metadata for enforcement."""
        if not isinstance(text, str):
            return {"text": text, "redactions": 0, "matches": []}

        sanitized = text
        matches = []
        for pattern in self.suspicious_patterns:
            if pattern.search(sanitized):
                matches.append(pattern.pattern)
            sanitized = pattern.sub("[REDACTED_INSTRUCTION]", sanitized)

        return {
            "text": sanitized,
            "redactions": len(matches),
            "matches": matches
        }
        
    def sanitize_payload(self, payload: Union[Dict, List, str, Any]) -> Union[Dict, List, str, Any]:
        """Recursively sanitize a payload dictionary or list."""
        if isinstance(payload, str):
            return self.sanitize_text(payload)
        elif isinstance(payload, dict):
            return {k: self.sanitize_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.sanitize_payload(item) for item in payload]
        return payload

    def sanitize_payload_with_report(
        self,
        payload: Union[Dict, List, str, Any]
    ) -> Dict[str, Any]:
        """Recursively sanitize a payload and return a report with redaction counts."""
        if isinstance(payload, str):
            result = self.sanitize_text_with_report(payload)
            return {"payload": result["text"], "redactions": result["redactions"], "matches": result["matches"]}

        if isinstance(payload, dict):
            redactions = 0
            matches: List[str] = []
            sanitized_payload: Dict[str, Any] = {}
            for key, value in payload.items():
                result = self.sanitize_payload_with_report(value)
                sanitized_payload[key] = result["payload"]
                redactions += result["redactions"]
                matches.extend(result["matches"])
            return {"payload": sanitized_payload, "redactions": redactions, "matches": matches}

        if isinstance(payload, list):
            redactions = 0
            matches = []
            sanitized_list: List[Any] = []
            for item in payload:
                result = self.sanitize_payload_with_report(item)
                sanitized_list.append(result["payload"])
                redactions += result["redactions"]
                matches.extend(result["matches"])
            return {"payload": sanitized_list, "redactions": redactions, "matches": matches}

        return {"payload": payload, "redactions": 0, "matches": []}
