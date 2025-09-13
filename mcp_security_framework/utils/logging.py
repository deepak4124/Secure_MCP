"""
Logging utilities for MCP Security Framework

This module provides logging setup, audit logging, and security event logging
for the MCP Security Framework.
"""

import logging
import logging.handlers
import json
import time
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path


class SecurityAuditLogger:
    """Security audit logger for tracking security events"""
    
    def __init__(self, log_file: str = "logs/audit.log"):
        """
        Initialize security audit logger
        
        Args:
            log_file: Path to audit log file
        """
        self.log_file = log_file
        self.logger = self._setup_audit_logger()
    
    def _setup_audit_logger(self) -> logging.Logger:
        """Setup audit logger"""
        logger = logging.getLogger("mcp_security_audit")
        logger.setLevel(logging.INFO)
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        # JSON formatter for structured logging
        formatter = logging.Formatter(
            '%(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.propagate = False
        
        return logger
    
    def log_security_event(
        self,
        event_type: str,
        agent_id: str,
        details: Dict[str, Any],
        severity: str = "INFO"
    ) -> None:
        """
        Log a security event
        
        Args:
            event_type: Type of security event
            agent_id: Agent identifier
            details: Event details
            severity: Event severity level
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "agent_id": agent_id,
            "severity": severity,
            "details": details
        }
        
        self.logger.info(json.dumps(log_entry))
    
    def log_authentication(
        self,
        agent_id: str,
        success: bool,
        method: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authentication event
        
        Args:
            agent_id: Agent identifier
            success: Whether authentication was successful
            method: Authentication method used
            details: Additional details
        """
        self.log_security_event(
            event_type="authentication",
            agent_id=agent_id,
            details={
                "success": success,
                "method": method,
                **(details or {})
            },
            severity="WARNING" if not success else "INFO"
        )
    
    def log_tool_access(
        self,
        agent_id: str,
        tool_id: str,
        operation: str,
        allowed: bool,
        reason: Optional[str] = None
    ) -> None:
        """
        Log tool access event
        
        Args:
            agent_id: Agent identifier
            tool_id: Tool identifier
            operation: Operation attempted
            allowed: Whether access was allowed
            reason: Reason for denial (if applicable)
        """
        self.log_security_event(
            event_type="tool_access",
            agent_id=agent_id,
            details={
                "tool_id": tool_id,
                "operation": operation,
                "allowed": allowed,
                "reason": reason
            },
            severity="WARNING" if not allowed else "INFO"
        )
    
    def log_trust_event(
        self,
        agent_id: str,
        event_type: str,
        trust_change: float,
        new_trust_score: float,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log trust event
        
        Args:
            agent_id: Agent identifier
            event_type: Type of trust event
            trust_change: Change in trust score
            new_trust_score: New trust score
            details: Additional details
        """
        self.log_security_event(
            event_type="trust_update",
            agent_id=agent_id,
            details={
                "trust_event_type": event_type,
                "trust_change": trust_change,
                "new_trust_score": new_trust_score,
                **(details or {})
            },
            severity="INFO"
        )
    
    def log_policy_violation(
        self,
        agent_id: str,
        policy_id: str,
        violation_type: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log policy violation
        
        Args:
            agent_id: Agent identifier
            policy_id: Policy identifier
            violation_type: Type of violation
            details: Additional details
        """
        self.log_security_event(
            event_type="policy_violation",
            agent_id=agent_id,
            details={
                "policy_id": policy_id,
                "violation_type": violation_type,
                **(details or {})
            },
            severity="ERROR"
        )
    
    def log_sybil_detection(
        self,
        agent_id: str,
        sybil_score: float,
        related_agents: List[str],
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log sybil attack detection
        
        Args:
            agent_id: Agent identifier
            sybil_score: Sybil detection score
            related_agents: List of related agent IDs
            details: Additional details
        """
        self.log_security_event(
            event_type="sybil_detection",
            agent_id=agent_id,
            details={
                "sybil_score": sybil_score,
                "related_agents": related_agents,
                **(details or {})
            },
            severity="CRITICAL"
        )


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    audit_file: Optional[str] = None,
    console_output: bool = True
) -> Dict[str, logging.Logger]:
    """
    Setup logging for MCP Security Framework
    
    Args:
        log_level: Logging level
        log_file: Path to main log file
        audit_file: Path to audit log file
        console_output: Whether to output to console
        
    Returns:
        Dictionary of configured loggers
    """
    # Create logs directory
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Setup specific loggers
    loggers = {
        "root": root_logger,
        "identity": logging.getLogger("mcp_security.identity"),
        "trust": logging.getLogger("mcp_security.trust"),
        "gateway": logging.getLogger("mcp_security.gateway"),
        "policy": logging.getLogger("mcp_security.policy"),
        "registry": logging.getLogger("mcp_security.registry"),
        "adapters": logging.getLogger("mcp_security.adapters")
    }
    
    # Setup audit logger
    if audit_file:
        audit_logger = SecurityAuditLogger(audit_file)
        loggers["audit"] = audit_logger
    
    return loggers


def get_audit_logger(audit_file: str = "logs/audit.log") -> SecurityAuditLogger:
    """
    Get security audit logger instance
    
    Args:
        audit_file: Path to audit log file
        
    Returns:
        Security audit logger instance
    """
    return SecurityAuditLogger(audit_file)


class SecurityMetrics:
    """Security metrics collection and reporting"""
    
    def __init__(self):
        """Initialize security metrics"""
        self.metrics = {
            "authentication_attempts": 0,
            "authentication_successes": 0,
            "authentication_failures": 0,
            "tool_access_attempts": 0,
            "tool_access_granted": 0,
            "tool_access_denied": 0,
            "trust_events": 0,
            "policy_violations": 0,
            "sybil_detections": 0,
            "security_alerts": 0
        }
        self.start_time = time.time()
    
    def increment(self, metric_name: str, value: int = 1) -> None:
        """
        Increment a metric
        
        Args:
            metric_name: Name of the metric
            value: Value to increment by
        """
        if metric_name in self.metrics:
            self.metrics[metric_name] += value
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current metrics
        
        Returns:
            Dictionary of current metrics
        """
        uptime = time.time() - self.start_time
        
        return {
            **self.metrics,
            "uptime_seconds": uptime,
            "uptime_hours": uptime / 3600,
            "authentication_success_rate": (
                self.metrics["authentication_successes"] / 
                max(1, self.metrics["authentication_attempts"])
            ),
            "tool_access_grant_rate": (
                self.metrics["tool_access_granted"] / 
                max(1, self.metrics["tool_access_attempts"])
            )
        }
    
    def reset_metrics(self) -> None:
        """Reset all metrics to zero"""
        for key in self.metrics:
            self.metrics[key] = 0
        self.start_time = time.time()


# Global metrics instance
_security_metrics = SecurityMetrics()


def get_security_metrics() -> SecurityMetrics:
    """
    Get global security metrics instance
    
    Returns:
        Security metrics instance
    """
    return _security_metrics
