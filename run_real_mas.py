#!/usr/bin/env python3
"""
Run the Real Multi-Agent System Prototype

This script starts a simple MCP server and then runs the real MAS prototype
that connects to it and executes actual tasks.
"""

import asyncio
import subprocess
import sys
import os
import time
import signal
from typing import Optional

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from examples.simple_mcp_server import SimpleMCPServer
from examples.real_mas_prototype import main as run_mas_prototype


class RealMASRunner:
    """
    Runner for the real MAS prototype with MCP server
    """
    
    def __init__(self):
        self.mcp_server: Optional[SimpleMCPServer] = None
        self.server_task: Optional[asyncio.Task] = None
    
    async def start_mcp_server(self, port: int = 3000):
        """Start the MCP server"""
        print(f"Starting MCP server on port {port}...")
        self.mcp_server = SimpleMCPServer(port=port)
        self.server_task = asyncio.create_task(self.mcp_server.start())
        
        # Wait a moment for server to start
        await asyncio.sleep(2)
        print("MCP server started successfully!")
    
    async def stop_mcp_server(self):
        """Stop the MCP server"""
        if self.server_task:
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
        print("MCP server stopped.")
    
    async def run_real_mas(self):
        """Run the real MAS prototype"""
        print("\n" + "="*60)
        print("Starting Real Multi-Agent System Prototype")
        print("="*60)
        
        try:
            # Run the MAS prototype
            await run_mas_prototype()
        except Exception as e:
            print(f"Error running MAS prototype: {e}")
            import traceback
            traceback.print_exc()
    
    async def run_full_demo(self):
        """Run the complete demo with MCP server and MAS"""
        print("🚀 Starting Real MAS Demo with MCP Integration")
        print("="*60)
        
        try:
            # Start MCP server
            await self.start_mcp_server()
            
            # Wait a bit for server to be ready
            await asyncio.sleep(3)
            
            # Run MAS prototype
            await self.run_real_mas()
            
        except KeyboardInterrupt:
            print("\n🛑 Demo interrupted by user")
        except Exception as e:
            print(f"\n❌ Error in demo: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Clean up
            await self.stop_mcp_server()
            print("\n✅ Demo completed and cleaned up")


async def main():
    """Main function"""
    runner = RealMASRunner()
    
    # Set up signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        asyncio.create_task(runner.stop_mcp_server())
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the full demo
    await runner.run_full_demo()


if __name__ == "__main__":
    print("🔧 Real Multi-Agent System with MCP Integration")
    print("This demo will:")
    print("1. Start a simple MCP server")
    print("2. Create real agents with security features")
    print("3. Execute real tasks using MCP tools")
    print("4. Demonstrate trust-aware task allocation")
    print("5. Show security monitoring and audit logs")
    print("\nPress Ctrl+C to stop at any time\n")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"\n💥 Demo failed: {e}")
        import traceback
        traceback.print_exc()
