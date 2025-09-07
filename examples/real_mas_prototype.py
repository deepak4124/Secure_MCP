"""
Real Multi-Agent System Prototype with MCP Integration

This example demonstrates a real working MAS that:
- Connects to actual MCP servers
- Manages real agent communication
- Executes real tasks using MCP tools
- Provides measurable security improvements
"""

import asyncio
import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import aiohttp
import yaml

# Import our security modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.authentication.identity_management import (
    IdentityManager, AgentType, IdentityStatus
)
from trust.trust_calculator import (
    TrustCalculator, TrustEvent, TrustEventType
)
from integration.mcp_security_gateway import (
    MCPSecurityGateway, MCPTool, MCPToolStatus, MCPToolRisk
)


@dataclass
class RealTask:
    """Real task that can be executed using MCP tools"""
    task_id: str
    task_type: str
    description: str
    required_tools: List[str]
    parameters: Dict[str, Any]
    priority: str = "normal"
    created_at: float = 0.0
    assigned_agent: Optional[str] = None
    status: str = "pending"  # pending, in_progress, completed, failed


class RealSecureAgent:
    """
    Real secure agent that can execute actual MCP tools
    """
    
    def __init__(self, agent_id: str, agent_type: AgentType, capabilities: List[str]):
        """Initialize real secure agent"""
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.capabilities = capabilities
        
        # Agent state
        self.is_registered = False
        self.trust_score = 0.5
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.last_activity = time.time()
        
        # MCP integration
        self.available_tools: List[MCPTool] = []
        self.tool_usage_stats: Dict[str, Dict[str, Any]] = {}
        
        # Communication
        self.message_queue = asyncio.Queue()
        self.peers = {}
    
    async def register_with_system(
        self, 
        identity_manager: IdentityManager,
        mcp_gateway: MCPSecurityGateway
    ) -> bool:
        """Register agent with the system"""
        # Register with identity manager
        success, message = identity_manager.register_agent(
            agent_id=self.agent_id,
            public_key=b"demo_public_key",  # In real system, use actual key
            agent_type=self.agent_type,
            capabilities=self.capabilities,
            metadata={"version": "1.0", "mcp_enabled": "true"}
        )
        
        if success:
            self.is_registered = True
            identity_manager.activate_identity(self.agent_id)
            
            # Get available MCP tools
            self.available_tools = mcp_gateway.get_verified_tools()
            
            print(f"Agent {self.agent_id} registered with {len(self.available_tools)} MCP tools")
            return True
        
        return False
    
    async def execute_real_task(
        self, 
        task: RealTask, 
        mcp_gateway: MCPSecurityGateway,
        trust_calculator: TrustCalculator
    ) -> Dict[str, Any]:
        """Execute a real task using MCP tools"""
        print(f"Agent {self.agent_id} executing real task: {task.task_id}")
        
        task.status = "in_progress"
        start_time = time.time()
        
        try:
            # Find required tools
            required_tools = self._find_required_tools(task.required_tools)
            if not required_tools:
                raise Exception(f"No tools available for task: {task.task_id}")
            
            # Execute task using MCP tools
            result = await self._execute_with_mcp_tools(
                task, required_tools, mcp_gateway
            )
            
            # Update statistics
            self.tasks_completed += 1
            task.status = "completed"
            execution_time = time.time() - start_time
            
            # Report success to trust system
            await self._report_task_success(task, execution_time, trust_calculator)
            
            return {
                "success": True,
                "task_id": task.task_id,
                "agent_id": self.agent_id,
                "result": result,
                "execution_time": execution_time,
                "tools_used": [tool.tool_id for tool in required_tools]
            }
            
        except Exception as e:
            # Update statistics
            self.tasks_failed += 1
            task.status = "failed"
            execution_time = time.time() - start_time
            
            # Report failure to trust system
            await self._report_task_failure(task, str(e), trust_calculator)
            
            return {
                "success": False,
                "task_id": task.task_id,
                "agent_id": self.agent_id,
                "error": str(e),
                "execution_time": execution_time
            }
    
    def _find_required_tools(self, required_tool_names: List[str]) -> List[MCPTool]:
        """Find available tools for task requirements"""
        available_tools = []
        
        for tool_name in required_tool_names:
            for tool in self.available_tools:
                if tool_name.lower() in tool.name.lower() or tool_name.lower() in tool.description.lower():
                    available_tools.append(tool)
                    break
        
        return available_tools
    
    async def _execute_with_mcp_tools(
        self, 
        task: RealTask, 
        tools: List[MCPTool], 
        mcp_gateway: MCPSecurityGateway
    ) -> Any:
        """Execute task using MCP tools"""
        results = []
        
        for tool in tools:
            # Execute tool
            tool_result = await mcp_gateway.execute_tool(
                tool_id=tool.tool_id,
                parameters=task.parameters,
                agent_id=self.agent_id
            )
            
            if tool_result["success"]:
                results.append(tool_result["result"])
                
                # Update tool usage statistics
                if tool.tool_id not in self.tool_usage_stats:
                    self.tool_usage_stats[tool.tool_id] = {
                        "usage_count": 0,
                        "success_count": 0,
                        "total_time": 0.0
                    }
                
                stats = self.tool_usage_stats[tool.tool_id]
                stats["usage_count"] += 1
                stats["success_count"] += 1
                stats["total_time"] += tool_result.get("execution_time", 0.0)
            else:
                raise Exception(f"Tool {tool.tool_id} failed: {tool_result['error']}")
        
        return results
    
    async def _report_task_success(
        self, 
        task: RealTask, 
        execution_time: float, 
        trust_calculator: TrustCalculator
    ):
        """Report successful task completion"""
        event = TrustEvent(
            event_id=f"success_{task.task_id}_{int(time.time())}",
            agent_id=self.agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time(),
            value=min(1.0, 0.8 + (1.0 / execution_time) * 0.2),  # Faster = higher value
            context={
                "task_id": task.task_id,
                "task_type": task.task_type,
                "execution_time": execution_time,
                "tools_used": len(task.required_tools)
            }
        )
        
        trust_calculator.add_trust_event(event)
    
    async def _report_task_failure(
        self, 
        task: RealTask, 
        error: str, 
        trust_calculator: TrustCalculator
    ):
        """Report failed task completion"""
        event = TrustEvent(
            event_id=f"failure_{task.task_id}_{int(time.time())}",
            agent_id=self.agent_id,
            event_type=TrustEventType.TASK_FAILURE,
            timestamp=time.time(),
            value=0.1,
            context={
                "task_id": task.task_id,
                "task_type": task.task_type,
                "error": error
            }
        )
        
        trust_calculator.add_trust_event(event)


class RealTaskAllocator:
    """
    Real task allocator that works with actual MCP tools
    """
    
    def __init__(
        self, 
        identity_manager: IdentityManager, 
        trust_calculator: TrustCalculator,
        mcp_gateway: MCPSecurityGateway
    ):
        """Initialize real task allocator"""
        self.identity_manager = identity_manager
        self.trust_calculator = trust_calculator
        self.mcp_gateway = mcp_gateway
        self.pending_tasks = []
        self.allocated_tasks = {}
        self.completed_tasks = []
    
    async def add_real_task(self, task: RealTask) -> None:
        """Add a real task to the allocation queue"""
        task.created_at = time.time()
        self.pending_tasks.append(task)
        print(f"Added real task: {task.task_id} - {task.description}")
    
    async def allocate_real_tasks(self, agents: List[RealSecureAgent]) -> None:
        """Allocate real tasks to agents"""
        while self.pending_tasks:
            task = self.pending_tasks.pop(0)
            
            # Find best agent for task
            best_agent = await self._find_best_agent_for_task(task, agents)
            
            if best_agent:
                # Allocate task
                task.assigned_agent = best_agent.agent_id
                self.allocated_tasks[task.task_id] = task
                
                print(f"Allocated task {task.task_id} to agent {best_agent.agent_id}")
                
                # Execute task
                result = await best_agent.execute_real_task(
                    task, self.mcp_gateway, self.trust_calculator
                )
                
                # Handle completion
                await self._handle_task_completion(task, result)
            else:
                print(f"No suitable agent found for task: {task.task_id}")
                # Put task back in queue for later
                self.pending_tasks.append(task)
                break
    
    async def _find_best_agent_for_task(
        self, 
        task: RealTask, 
        agents: List[RealSecureAgent]
    ) -> Optional[RealSecureAgent]:
        """Find the best agent for a task"""
        suitable_agents = []
        
        for agent in agents:
            # Check if agent has required capabilities
            if not self._agent_has_capabilities(agent, task):
                continue
            
            # Check if agent has required tools
            if not self._agent_has_tools(agent, task):
                continue
            
            # Get trust score
            trust_score = self.trust_calculator.get_trust_score(agent.agent_id)
            if trust_score and trust_score.confidence > 0.3:
                suitable_agents.append((agent, trust_score.overall_score))
            else:
                # Use default score for agents without trust scores
                suitable_agents.append((agent, 0.5))
        
        if not suitable_agents:
            return None
        
        # Sort by trust score (highest first)
        suitable_agents.sort(key=lambda x: x[1], reverse=True)
        return suitable_agents[0][0]
    
    def _agent_has_capabilities(self, agent: RealSecureAgent, task: RealTask) -> bool:
        """Check if agent has required capabilities"""
        # Simple capability matching
        task_type_lower = task.task_type.lower()
        return any(cap.lower() in task_type_lower for cap in agent.capabilities)
    
    def _agent_has_tools(self, agent: RealSecureAgent, task: RealTask) -> bool:
        """Check if agent has required tools"""
        available_tool_names = [tool.name.lower() for tool in agent.available_tools]
        
        for required_tool in task.required_tools:
            if not any(required_tool.lower() in tool_name for tool_name in available_tool_names):
                return False
        
        return True
    
    async def _handle_task_completion(self, task: RealTask, result: Dict[str, Any]) -> None:
        """Handle task completion"""
        # Move from allocated to completed
        if task.task_id in self.allocated_tasks:
            del self.allocated_tasks[task.task_id]
        
        self.completed_tasks.append({
            "task": task,
            "result": result,
            "completed_at": time.time()
        })
        
        print(f"Task {task.task_id} completed: {result['success']}")


async def main():
    """
    Main function demonstrating real MAS with MCP integration
    """
    print("=== Real Multi-Agent System with MCP Integration ===\n")
    
    # Initialize system components
    identity_manager = IdentityManager()
    trust_calculator = TrustCalculator(min_events=1)
    
    async with MCPSecurityGateway() as mcp_gateway:
        # Discover and register MCP servers
        print("1. Discovering MCP servers...")
        servers = await mcp_gateway.discover_mcp_servers()
        print(f"   Found {len(servers)} MCP servers")
        
        for server_url in servers:
            await mcp_gateway.register_mcp_server(server_url)
        
        # Discover tools
        print("\n2. Discovering MCP tools...")
        for server_url in servers:
            tools = await mcp_gateway.discover_tools(server_url)
            print(f"   Found {len(tools)} tools from {server_url}")
        
        verified_tools = mcp_gateway.get_verified_tools()
        print(f"   Total verified tools: {len(verified_tools)}")
        
        # Create real agents
        print("\n3. Creating real agents...")
        agents = [
            RealSecureAgent("real_agent_001", AgentType.WORKER, ["data_processing", "analysis"]),
            RealSecureAgent("real_agent_002", AgentType.WORKER, ["data_processing", "visualization"]),
            RealSecureAgent("real_agent_003", AgentType.COORDINATOR, ["coordination", "monitoring"]),
            RealSecureAgent("real_agent_004", AgentType.WORKER, ["analysis", "reporting"]),
        ]
        
        # Register agents
        for agent in agents:
            await agent.register_with_system(identity_manager, mcp_gateway)
        
        # Bootstrap trust
        print("\n4. Bootstrapping trust scores...")
        for agent in agents:
            # Give initial trust events
            initial_events = [
                TrustEvent(
                    event_id=f"bootstrap_{agent.agent_id}_1",
                    agent_id=agent.agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - 3600,
                    value=0.8,
                    context={"type": "bootstrap"}
                ),
                TrustEvent(
                    event_id=f"bootstrap_{agent.agent_id}_2",
                    agent_id=agent.agent_id,
                    event_type=TrustEventType.COOPERATION_POSITIVE,
                    timestamp=time.time() - 1800,
                    value=0.7,
                    context={"type": "bootstrap"}
                )
            ]
            
            for event in initial_events:
                trust_calculator.add_trust_event(event)
        
        # Create real task allocator
        task_allocator = RealTaskAllocator(identity_manager, trust_calculator, mcp_gateway)
        
        # Create real tasks
        print("\n5. Creating real tasks...")
        real_tasks = [
            RealTask(
                task_id="real_task_001",
                task_type="data_processing",
                description="Process customer data for analysis",
                required_tools=["data_processor", "validator"],
                parameters={"input_file": "customers.csv", "output_format": "json"}
            ),
            RealTask(
                task_id="real_task_002",
                task_type="analysis",
                description="Analyze sales trends",
                required_tools=["analyzer", "calculator"],
                parameters={"data_source": "sales_db", "time_range": "last_quarter"}
            ),
            RealTask(
                task_id="real_task_003",
                task_type="visualization",
                description="Create sales dashboard",
                required_tools=["chart_generator", "dashboard_builder"],
                parameters={"chart_type": "line", "data_points": 100}
            ),
            RealTask(
                task_id="real_task_004",
                task_type="reporting",
                description="Generate monthly report",
                required_tools=["report_generator", "formatter"],
                parameters={"report_type": "monthly", "sections": ["sales", "inventory"]}
            )
        ]
        
        # Add tasks to allocator
        for task in real_tasks:
            await task_allocator.add_real_task(task)
        
        # Allocate and execute tasks
        print("\n6. Allocating and executing real tasks...")
        await task_allocator.allocate_real_tasks(agents)
        
        # Show results
        print("\n7. Results:")
        print(f"   Completed tasks: {len(task_allocator.completed_tasks)}")
        print(f"   Pending tasks: {len(task_allocator.pending_tasks)}")
        print(f"   Allocated tasks: {len(task_allocator.allocated_tasks)}")
        
        # Show trust scores
        print("\n8. Trust scores after real task execution:")
        for agent in agents:
            trust_score = trust_calculator.get_trust_score(agent.agent_id)
            if trust_score:
                print(f"   {agent.agent_id}: {trust_score.overall_score:.3f}")
        
        # Show agent statistics
        print("\n9. Agent statistics:")
        for agent in agents:
            print(f"   {agent.agent_id}: {agent.tasks_completed} completed, {agent.tasks_failed} failed")
            print(f"     Available tools: {len(agent.available_tools)}")
            print(f"     Tool usage: {len(agent.tool_usage_stats)} tools used")
        
        # Show audit log
        print("\n10. Security audit log:")
        audit_log = mcp_gateway.get_audit_log()
        print(f"    Total audit entries: {len(audit_log)}")
        
        for entry in audit_log[-5:]:  # Show last 5 entries
            print(f"    {entry['action']}: {entry.get('agent_id', 'N/A')} at {entry['timestamp']}")
    
    print("\n=== Real MAS Prototype completed successfully ===")


if __name__ == "__main__":
    asyncio.run(main())
