"""
Environment Configuration for LangGraph MAS

This module handles environment variables and configuration for the LangGraph-based MAS.
"""

import os
from typing import Optional


class EnvironmentConfig:
    """Environment configuration manager"""
    
    def __init__(self):
        """Initialize environment configuration"""
        # Gemini API Configuration
        self.GOOGLE_API_KEY = "AIzaSyByiCJd2FNGLHnIcB-w1rOd6jDAF0MV0E8"
        
        # MCP Server Configuration
        self.MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:3000")
        
        # Security Configuration
        self.SECURITY_LEVEL = os.getenv("SECURITY_LEVEL", "high")
        self.TRUST_THRESHOLD = float(os.getenv("TRUST_THRESHOLD", "0.3"))
        self.MIN_TRUST_EVENTS = int(os.getenv("MIN_TRUST_EVENTS", "1"))
        
        # Document Processing Configuration
        self.MAX_FILE_SIZE = os.getenv("MAX_FILE_SIZE", "10MB")
        self.SUPPORTED_FORMATS = os.getenv("SUPPORTED_FORMATS", "pdf,jpg,png,txt,docx,json").split(",")
        self.OUTPUT_FORMAT = os.getenv("OUTPUT_FORMAT", "json")
        
        # Logging Configuration
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
        self.AUDIT_ENABLED = os.getenv("AUDIT_ENABLED", "true").lower() == "true"
    
    def get_gemini_api_key(self) -> str:
        """Get Gemini API key"""
        return self.GOOGLE_API_KEY
    
    def get_mcp_server_url(self) -> str:
        """Get MCP server URL"""
        return self.MCP_SERVER_URL
    
    def is_audit_enabled(self) -> bool:
        """Check if audit logging is enabled"""
        return self.AUDIT_ENABLED


# Global configuration instance
config = EnvironmentConfig()
