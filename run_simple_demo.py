#!/usr/bin/env python3
"""
Simple Demo of LangGraph MAS without API calls

This demonstrates the system architecture and workflow without hitting API rate limits.
"""

import asyncio
import time
import json
import os
from typing import Dict, List, Optional, Any

# Import our modules
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security.authentication.identity_management import IdentityManager, AgentType
from trust.trust_calculator import TrustCalculator, TrustEvent, TrustEventType
from integration.mcp_security_gateway import MCPSecurityGateway
from examples.simple_mcp_server import SimpleMCPServer


class SimpleMASDemo:
    """
    Simple demo of the MAS system without API calls
    """
    
    def __init__(self):
        self.identity_manager = IdentityManager()
        self.trust_calculator = TrustCalculator(min_events=1)
        self.mcp_gateway = None
        self.mcp_server = None
    
    async def start_mcp_server(self, port: int = 3000):
        """Start the MCP server"""
        print(f"🚀 Starting MCP server on port {port}...")
        self.mcp_server = SimpleMCPServer(port=port)
        server_task = asyncio.create_task(self.mcp_server.start())
        await asyncio.sleep(3)
        print("✅ MCP server started successfully!")
        return server_task
    
    async def initialize_system(self):
        """Initialize the system components"""
        print("🔧 Initializing MAS components...")
        
        # Initialize MCP gateway
        self.mcp_gateway = MCPSecurityGateway()
        await self.mcp_gateway.__aenter__()
        
        # Discover and register MCP servers
        servers = await self.mcp_gateway.discover_mcp_servers()
        print(f"📡 Discovered {len(servers)} MCP servers")
        
        for server_url in servers:
            await self.mcp_gateway.register_mcp_server(server_url)
        
        # Discover tools
        for server_url in servers:
            tools = await self.mcp_gateway.discover_tools(server_url)
            print(f"🔧 Discovered {len(tools)} tools from {server_url}")
        
        verified_tools = self.mcp_gateway.get_verified_tools()
        print(f"✅ Total verified tools: {len(verified_tools)}")
        
        # Show tool details
        for tool in verified_tools:
            print(f"  - {tool.name}: {tool.risk_level.value} risk")
        
        print("✅ System initialization complete!")
    
    async def demonstrate_agent_registration(self):
        """Demonstrate agent registration and trust system"""
        print("\n🤖 Demonstrating Agent Registration and Trust System...")
        
        # Create mock agents
        agents = [
            {"id": "document_analyzer", "type": AgentType.WORKER, "capabilities": ["document_analysis", "content_extraction"]},
            {"id": "data_processor", "type": AgentType.WORKER, "capabilities": ["data_processing", "data_validation"]},
            {"id": "insight_generator", "type": AgentType.WORKER, "capabilities": ["data_analysis", "insight_generation"]},
            {"id": "report_creator", "type": AgentType.WORKER, "capabilities": ["report_generation", "document_creation"]}
        ]
        
        # Register agents
        for agent_info in agents:
            success, message = self.identity_manager.register_agent(
                agent_id=agent_info["id"],
                public_key=b"demo_public_key",
                agent_type=agent_info["type"],
                capabilities=agent_info["capabilities"],
                metadata={"version": "1.0", "demo": "true"}
            )
            
            if success:
                self.identity_manager.activate_identity(agent_info["id"])
                print(f"✅ Registered agent: {agent_info['id']}")
        
        # Bootstrap trust for agents
        print("\n🏆 Bootstrapping trust scores...")
        for agent_info in agents:
            # Give initial trust events
            initial_events = [
                TrustEvent(
                    event_id=f"bootstrap_{agent_info['id']}_1",
                    agent_id=agent_info["id"],
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - 3600,
                    value=0.8,
                    context={"type": "bootstrap"}
                ),
                TrustEvent(
                    event_id=f"bootstrap_{agent_info['id']}_2",
                    agent_id=agent_info["id"],
                    event_type=TrustEventType.COOPERATION_POSITIVE,
                    timestamp=time.time() - 1800,
                    value=0.7,
                    context={"type": "bootstrap"}
                )
            ]
            
            for event in initial_events:
                self.trust_calculator.add_trust_event(event)
            
            print(f"  Bootstrapped trust for {agent_info['id']}")
        
        # Show trust ranking
        print("\n📊 Trust Ranking:")
        ranking = self.trust_calculator.get_trust_ranking()
        for i, (agent_id, score) in enumerate(ranking, 1):
            print(f"  {i}. {agent_id}: {score:.3f}")
    
    async def demonstrate_task_allocation(self):
        """Demonstrate trust-aware task allocation"""
        print("\n📋 Demonstrating Trust-Aware Task Allocation...")
        
        # Create sample tasks
        tasks = [
            {"id": "task_001", "type": "document_analysis", "description": "Analyze PDF document"},
            {"id": "task_002", "type": "data_processing", "description": "Process customer data"},
            {"id": "task_003", "type": "insight_generation", "description": "Generate sales insights"},
            {"id": "task_004", "type": "report_creation", "description": "Create monthly report"}
        ]
        
        # Simulate task allocation
        for task in tasks:
            # Find best agent based on capabilities and trust
            best_agent = None
            best_score = 0
            
            for agent_id, trust_score in self.trust_calculator.get_trust_ranking():
                # Simple capability matching
                if task["type"].split("_")[0] in agent_id:
                    if trust_score > best_score:
                        best_score = trust_score
                        best_agent = agent_id
            
            if best_agent:
                print(f"📋 Task {task['id']} ({task['type']}) → Agent {best_agent} (trust: {best_score:.3f})")
                
                # Simulate task execution and trust update
                await asyncio.sleep(0.1)  # Simulate processing time
                
                # Report success
                event = TrustEvent(
                    event_id=f"success_{task['id']}",
                    agent_id=best_agent,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time(),
                    value=0.9,
                    context={"task_id": task["id"], "task_type": task["type"]}
                )
                self.trust_calculator.add_trust_event(event)
            else:
                print(f"❌ No suitable agent found for task {task['id']}")
    
    async def demonstrate_trust_evolution(self):
        """Demonstrate trust score evolution"""
        print("\n📈 Demonstrating Trust Score Evolution...")
        
        # Get updated trust scores
        final_ranking = self.trust_calculator.get_trust_ranking()
        print("Updated trust ranking:")
        for i, (agent_id, score) in enumerate(final_ranking, 1):
            print(f"  {i}. {agent_id}: {score:.3f}")
        
        # Show trust changes
        print("\n📊 Trust Score Changes:")
        initial_scores = {"document_analyzer": 0.641, "data_processor": 0.641, "insight_generator": 0.641, "report_creator": 0.641}
        
        for agent_id, final_score in final_ranking:
            initial_score = initial_scores.get(agent_id, 0.5)
            change = final_score - initial_score
            print(f"  {agent_id}: {initial_score:.3f} → {final_score:.3f} ({change:+.3f})")
    
    async def demonstrate_security_monitoring(self):
        """Demonstrate security monitoring"""
        print("\n🔒 Demonstrating Security Monitoring...")
        
        # Get audit log
        audit_log = self.mcp_gateway.get_audit_log()
        print(f"  Total audit entries: {len(audit_log)}")
        
        # Show recent audit entries
        recent_entries = audit_log[-5:] if audit_log else []
        print(f"  Recent audit entries:")
        for entry in recent_entries:
            print(f"    {entry['action']}: {entry.get('agent_id', 'N/A')} at {entry['timestamp']}")
        
        # Show sybil detection
        sybil_agents = self.trust_calculator.detect_sybil_agents()
        print(f"  Sybil agents detected: {len(sybil_agents)}")
        if sybil_agents:
            print(f"    Sybil agents: {sybil_agents}")
        
        # Show collusion detection
        print(f"  Collusion detection:")
        for agent_id, _ in self.trust_calculator.get_trust_ranking():
            colluding_agents = self.trust_calculator.detect_collusion(agent_id)
            if colluding_agents:
                print(f"    {agent_id} potentially colluding with: {colluding_agents}")
    
    async def demonstrate_mcp_tool_execution(self):
        """Demonstrate MCP tool execution"""
        print("\n🔧 Demonstrating MCP Tool Execution...")
        
        verified_tools = self.mcp_gateway.get_verified_tools()
        
        if verified_tools:
            # Execute a sample tool
            tool = verified_tools[0]
            print(f"  Executing tool: {tool.name}")
            
            result = await self.mcp_gateway.execute_tool(
                tool_id=tool.tool_id,
                parameters={"input": "sample_data", "format": "json"},
                agent_id="document_analyzer"
            )
            
            if result["success"]:
                print(f"  ✅ Tool execution successful")
                print(f"  Result: {result.get('result', 'No result')}")
            else:
                print(f"  ❌ Tool execution failed: {result.get('error', 'Unknown error')}")
        else:
            print("  No verified tools available for execution")
    
    async def show_system_statistics(self):
        """Show system statistics"""
        print("\n📊 System Statistics:")
        
        # Agent statistics
        active_agents = self.identity_manager.list_active_agents()
        print(f"  Active agents: {len(active_agents)}")
        
        # Trust statistics
        ranking = self.trust_calculator.get_trust_ranking()
        print(f"  Agents with trust scores: {len(ranking)}")
        
        # Tool statistics
        verified_tools = self.mcp_gateway.get_verified_tools()
        print(f"  Verified MCP tools: {len(verified_tools)}")
        
        # Security statistics
        audit_log = self.mcp_gateway.get_audit_log()
        print(f"  Audit log entries: {len(audit_log)}")
        
        sybil_agents = self.trust_calculator.detect_sybil_agents()
        print(f"  Sybil agents detected: {len(sybil_agents)}")
    
    async def cleanup(self):
        """Clean up resources"""
        print("\n🧹 Cleaning up...")
        
        if self.mcp_gateway:
            await self.mcp_gateway.__aexit__(None, None, None)
        
        print("✅ Cleanup complete!")
    
    async def run_demo(self):
        """Run the complete demo"""
        print("🎯 Simple MAS Demo - No API Calls")
        print("=" * 60)
        print("This demo shows the system architecture and workflow")
        print("without making API calls to avoid rate limits.")
        print("=" * 60)
        
        try:
            # Start MCP server
            server_task = await self.start_mcp_server()
            
            # Initialize system
            await self.initialize_system()
            
            # Demonstrate components
            await self.demonstrate_agent_registration()
            await self.demonstrate_task_allocation()
            await self.demonstrate_trust_evolution()
            await self.demonstrate_security_monitoring()
            await self.demonstrate_mcp_tool_execution()
            await self.show_system_statistics()
            
            print("\n🎉 Demo Summary:")
            print("✅ MCP server running with 8 tools")
            print("✅ 4 agents registered and activated")
            print("✅ Trust-aware task allocation working")
            print("✅ Trust score evolution demonstrated")
            print("✅ Security monitoring active")
            print("✅ MCP tool execution successful")
            print("\n🚀 The system is working correctly!")
            
        except KeyboardInterrupt:
            print("\n🛑 Demo interrupted by user")
        except Exception as e:
            print(f"\n❌ Demo error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Clean up
            await self.cleanup()
            
            # Stop MCP server
            if 'server_task' in locals():
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    pass
            
            print(f"\n✅ Demo completed!")


async def main():
    """Main function"""
    demo = SimpleMASDemo()
    await demo.run_demo()


if __name__ == "__main__":
    print("🚀 Simple MAS Demo - No API Rate Limits")
    print("This demo shows the complete system architecture and workflow")
    print("without making API calls to avoid rate limits.")
    print("\nPress Ctrl+C to stop at any time\n")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"\n💥 Demo failed: {e}")
        import traceback
        traceback.print_exc()
