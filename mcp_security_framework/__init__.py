"""
MCP Security Framework

A comprehensive security framework for Model Context Protocol (MCP) in Multi-Agent Systems (MAS).
Provides identity management, trust calculation, tool verification, and secure execution
across multiple MAS frameworks including LangGraph, AutoGen, CrewAI, and Semantic Kernel.

Key Features:
- Identity & Authentication Management
- Trust-aware Task Allocation
- MCP Tool Verification & Registry
- Secure Execution Gateway
- Multi-MAS Framework Support
- Comprehensive Audit Logging

Author: Secure MCP Research Team
License: MIT
Version: 0.1.0
"""

__version__ = "0.1.0"
__author__ = "Secure MCP Research Team"
__license__ = "MIT"

# Core framework imports
from .core.identity import IdentityManager, AgentType, IdentityStatus
from .core.trust import TrustCalculator, TrustEvent, TrustEventType
from .core.gateway import MCPSecurityGateway, MCPTool, MCPToolStatus, MCPToolRisk
from .core.policy import PolicyEngine, AccessPolicy, PolicyDecision
from .core.registry import ToolRegistry, ToolManifest, ToolAttestation

# MAS Adapters (optional imports)
try:
    from .adapters.langgraph import LangGraphSecurityAdapter
except ImportError:
    LangGraphSecurityAdapter = None

try:
    from .adapters.autogen import AutoGenSecurityAdapter
except ImportError:
    AutoGenSecurityAdapter = None

try:
    from .adapters.crewai import CrewAISecurityAdapter
except ImportError:
    CrewAISecurityAdapter = None

# Utilities
from .utils.config import SecurityConfig, load_config
from .utils.logging import setup_logging, get_audit_logger
from .utils.crypto import generate_keypair, sign_data, verify_signature

__all__ = [
    # Core
    "IdentityManager",
    "AgentType", 
    "IdentityStatus",
    "TrustCalculator",
    "TrustEvent",
    "TrustEventType",
    "MCPSecurityGateway",
    "MCPTool",
    "MCPToolStatus", 
    "MCPToolRisk",
    "PolicyEngine",
    "AccessPolicy",
    "PolicyDecision",
    "ToolRegistry",
    "ToolManifest",
    "ToolAttestation",
    
    # Adapters
    "LangGraphSecurityAdapter",
    "AutoGenSecurityAdapter", 
    "CrewAISecurityAdapter",
    
    # Utils
    "SecurityConfig",
    "load_config",
    "setup_logging",
    "get_audit_logger",
    "generate_keypair",
    "sign_data",
    "verify_signature",
    
    # Metadata
    "__version__",
    "__author__",
    "__license__"
]
