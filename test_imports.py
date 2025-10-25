#!/usr/bin/env python3
"""
Test imports for MCP Security Framework
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test all imports"""
    print("🔄 Testing imports...")
    
    try:
        print("Testing basic imports...")
        from typing import Dict, List, Optional, Any
        print("✅ Basic typing imports successful")
        
        print("Testing framework core imports...")
        from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
        print("✅ Core framework imports successful")
        
        print("Testing gateway imports...")
        from mcp_security_framework.core.gateway import MCPSecurityGateway, RequestContext, ResponseContext
        print("✅ Gateway imports successful")
        
        print("Testing real gateway imports...")
        from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
        print("✅ Real gateway imports successful")
        
        print("Testing real models imports...")
        from mcp_security_framework.models.real_models import RealTrustModel, RealSecurityModel
        print("✅ Real models imports successful")
        
        print("Testing benchmarking imports...")
        from mcp_security_framework.benchmarking.real_benchmarker import RealBenchmarkRunner
        print("✅ Benchmarking imports successful")
        
        print("🎉 All imports successful!")
        return True
        
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
