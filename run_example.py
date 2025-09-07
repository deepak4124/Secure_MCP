#!/usr/bin/env python3
"""
Run the Secure Multi-Agent MCP System Example

This script demonstrates the basic functionality of the secure multi-agent system
including agent registration, trust calculation, and task allocation.
"""

import asyncio
import sys
import os

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from examples.fixed_secure_agent_example import main


if __name__ == "__main__":
    print("Starting Secure Multi-Agent MCP System Example...")
    print("=" * 60)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExample interrupted by user")
    except Exception as e:
        print(f"\nError running example: {e}")
        import traceback
        traceback.print_exc()
    
    print("\nExample completed.")
