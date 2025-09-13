"""
MAS Adapters for MCP Security Framework

This module provides adapters for integrating the MCP Security Framework
with various Multi-Agent System (MAS) frameworks.
"""

from .base import BaseSecurityAdapter, SecurityContext, AgentInfo
from .langgraph import LangGraphSecurityAdapter
from .autogen import AutoGenSecurityAdapter
from .crewai import CrewAISecurityAdapter

__all__ = [
    "BaseSecurityAdapter",
    "SecurityContext", 
    "AgentInfo",
    "LangGraphSecurityAdapter",
    "AutoGenSecurityAdapter",
    "CrewAISecurityAdapter"
]
