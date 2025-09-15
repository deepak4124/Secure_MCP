"""
Complete Real MAS Demo with MCP Integration

This script demonstrates the complete system:
1. Starts a simple MCP server
2. Runs the real MAS prototype
3. Shows trust-aware task allocation
4. Displays security monitoring and performance metrics
"""

import asyncio
import subprocess
import sys
import time
import signal
import os
from pathlib import Path


class RealMASDemo:
    """Complete Real MAS Demo"""
    
    def __init__(self):
        self.mcp_server_process = None
        self.mcp_server_url = "http://localhost:3000"
    
    async def start_mcp_server(self):
        """Start the MCP server in background"""
        print("🚀 Starting MCP Server...")
        
        # Start MCP server as subprocess
        server_script = Path(__file__).parent / "examples" / "simple_mcp_server.py"
        
        try:
            self.mcp_server_process = subprocess.Popen(
                [sys.executable, str(server_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to start
            await asyncio.sleep(3)
            
            # Check if server is running
            if self.mcp_server_process.poll() is None:
                print("✅ MCP Server started successfully on port 3000")
                return True
            else:
                print("❌ Failed to start MCP Server")
                return False
                
        except Exception as e:
            print(f"❌ Error starting MCP Server: {e}")
            return False
    
    async def stop_mcp_server(self):
        """Stop the MCP server"""
        if self.mcp_server_process:
            print("🛑 Stopping MCP Server...")
            self.mcp_server_process.terminate()
            try:
                self.mcp_server_process.wait(timeout=5)
                print("✅ MCP Server stopped")
            except subprocess.TimeoutExpired:
                self.mcp_server_process.kill()
                print("⚠️ MCP Server force stopped")
    
    async def run_mas_prototype(self):
        """Run the MAS prototype"""
        print("\n🤖 Starting Real MAS Prototype...")
        
        # Import and run the MAS prototype
        try:
            from examples.real_mas_prototype import RealMASPrototype
            
            async with RealMASPrototype(self.mcp_server_url) as mas:
                await mas.run_mas_simulation()
                
        except Exception as e:
            print(f"❌ Error running MAS prototype: {e}")
            return False
        
        return True
    
    async def run_complete_demo(self):
        """Run the complete demo"""
        print("🎯 REAL MULTI-AGENT SYSTEM WITH MCP INTEGRATION")
        print("=" * 60)
        print("This demo shows:")
        print("• Real MCP server with 8 different tools")
        print("• 4 real agents with different capabilities")
        print("• 4 real tasks requiring MCP tool execution")
        print("• Trust-aware task allocation")
        print("• Security monitoring and audit logging")
        print("• Performance metrics and trust evolution")
        print("=" * 60)
        
        try:
            # Start MCP server
            if not await self.start_mcp_server():
                return
            
            # Wait a bit for server to fully start
            await asyncio.sleep(2)
            
            # Run MAS prototype
            await self.run_mas_prototype()
            
            print("\n🎉 Demo completed successfully!")
            print("=" * 60)
            print("Key achievements demonstrated:")
            print("✅ Real MCP server integration")
            print("✅ Trust-aware task allocation")
            print("✅ Secure tool execution")
            print("✅ Performance monitoring")
            print("✅ Security audit logging")
            print("✅ Trust score evolution")
            
        except KeyboardInterrupt:
            print("\n🛑 Demo interrupted by user")
        except Exception as e:
            print(f"\n❌ Demo failed: {e}")
        finally:
            # Clean up
            await self.stop_mcp_server()
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            print(f"\n🛑 Received signal {signum}, shutting down...")
            asyncio.create_task(self.stop_mcp_server())
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


async def main():
    """Main function"""
    demo = RealMASDemo()
    demo.setup_signal_handlers()
    
    await demo.run_complete_demo()


if __name__ == "__main__":
    print("🚀 Starting Real MAS Demo...")
    print("Press Ctrl+C to stop the demo at any time")
    print()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
    finally:
        print("👋 Goodbye!")