#!/usr/bin/env python3
"""
Run LangGraph Document Processing MAS

This script runs the complete LangGraph-based multi-agent system for document processing
with MCP integration, trust-aware allocation, and security monitoring.
"""

import asyncio
import sys
import os
import signal
from typing import Optional

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from examples.langgraph_document_processing_demo import LangGraphDocumentProcessingDemo


class LangGraphMASRunner:
    """
    Runner for the LangGraph Document Processing MAS
    """
    
    def __init__(self):
        self.demo: Optional[LangGraphDocumentProcessingDemo] = None
    
    async def run_demo(self):
        """Run the LangGraph MAS demo"""
        print("🚀 LangGraph Document Processing MAS")
        print("=" * 60)
        print("This system demonstrates:")
        print("✅ Real LangGraph agents with Gemini API")
        print("✅ MCP server integration with 8 tools")
        print("✅ Trust-aware task allocation")
        print("✅ Security monitoring and audit logs")
        print("✅ Document processing pipeline")
        print("✅ Trust score evolution")
        print("=" * 60)
        
        try:
            self.demo = LangGraphDocumentProcessingDemo()
            await self.demo.run_demo()
        except KeyboardInterrupt:
            print("\n🛑 Demo interrupted by user")
        except Exception as e:
            print(f"\n❌ Demo error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.demo:
                await self.demo.cleanup()


async def main():
    """Main function"""
    runner = LangGraphMASRunner()
    
    # Set up signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        if runner.demo:
            asyncio.create_task(runner.demo.cleanup())
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the demo
    await runner.run_demo()


if __name__ == "__main__":
    print("🎯 LangGraph Document Processing MAS")
    print("Real Multi-Agent System with MCP Integration")
    print("\nFeatures:")
    print("• LangGraph agents with Gemini API")
    print("• MCP server with 8 processing tools")
    print("• Trust-aware task allocation")
    print("• Security monitoring and audit logs")
    print("• Document processing pipeline")
    print("• Trust score evolution")
    print("\nPress Ctrl+C to stop at any time\n")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"\n💥 Demo failed: {e}")
        import traceback
        traceback.print_exc()
