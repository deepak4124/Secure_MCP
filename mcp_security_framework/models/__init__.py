"""
Real Models Integration for MCP Security Framework

This package provides integration with real Hugging Face models for
trust calculation, security analysis, and behavioral assessment.
"""

from .real_models import RealTrustModel, RealSecurityModel

__all__ = [
    'RealTrustModel',
    'RealSecurityModel'
]
