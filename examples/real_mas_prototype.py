"""
Real Multi-Agent System Prototype with MCP Integration
"""

import asyncio
import aiohttp
import time
import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Task:
    task_id: str
    description: str
    required_capabilities: List[str]
    parameters: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


@dataclass
class Agent:
    agent_id: str
    name: str
    capabilities: List[str]
    trust_score: float = 0.5
    tasks_completed: int = 0


class RealMASPrototype:
    """Real Multi-Agent System Prototype with MCP Integration"""
    
    def __init__(self, mcp_server_url: str = "http://localhost:3000"):
        self.mcp_server_url = mcp_server_url
        self.agents: Dict[str, Agent] = {}
        self.tasks: Dict[str, Task] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.audit_log: List[Dict[str, Any]] = []
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def initialize_agents(self) -> None:
        """Initialize real agents"""
        agents_data = [
            {"agent_id": "real_agent_001", "name": "Data Specialist", "capabilities": ["data_processing", "analysis"]},
            {"agent_id": "real_agent_002", "name": "Analytics Expert", "capabilities": ["data_analysis", "visualization"]},
            {"agent_id": "real_agent_003", "name": "System Admin", "capabilities": ["monitoring", "reporting"]},
            {"agent_id": "real_agent_004", "name": "QA Agent", "capabilities": ["validation", "processing"]}
        ]
        
        for agent_data in agents_data:
            agent = Agent(
                agent_id=agent_data["agent_id"],
                name=agent_data["name"],
                capabilities=agent_data["capabilities"],
                trust_score=random.uniform(0.4, 0.8)
            )
            self.agents[agent.agent_id] = agent
            print(f"✅ Initialized agent: {agent.name}")
    
    async def create_real_tasks(self) -> None:
        """Create real tasks"""
        tasks_data = [
            {
                "task_id": "real_task_001",
                "description": "Process customer dataset",
                "required_capabilities": ["data_processing"],
                "parameters": {"dataset": "customer_data.csv", "operation": "clean"}
            },
            {
                "task_id": "real_task_002", 
                "description": "Generate system report",
                "required_capabilities": ["monitoring"],
                "parameters": {"metrics": ["cpu", "memory"], "duration": 300}
            },
            {
                "task_id": "real_task_003",
                "description": "Analyze sales data",
                "required_capabilities": ["data_analysis"],
                "parameters": {"data": "sales_db", "analysis_type": "statistical"}
            },
            {
                "task_id": "real_task_004",
                "description": "Validate data quality",
                "required_capabilities": ["validation"],
                "parameters": {"data": "quality_data", "rules": ["completeness"]}
            }
        ]
        
        for task_data in tasks_data:
            task = Task(
                task_id=task_data["task_id"],
                description=task_data["description"],
                required_capabilities=task_data["required_capabilities"],
                parameters=task_data["parameters"]
            )
            self.tasks[task.task_id] = task
            print(f"📋 Created task: {task.description}")
    
    async def discover_mcp_tools(self) -> List[Dict[str, Any]]:
        """Discover MCP tools"""
        try:
            async with self.session.get(f"{self.mcp_server_url}/tools") as response:
                if response.status == 200:
                    data = await response.json()
                    tools = data.get("tools", [])
                    print(f"🔧 Discovered {len(tools)} MCP tools")
                    return tools
                else:
                    print(f"❌ Failed to discover tools: HTTP {response.status}")
                    return []
        except Exception as e:
            print(f"❌ Error discovering tools: {e}")
            return []
    
    async def allocate_task_to_agent(self, task: Task) -> Optional[str]:
        """Allocate task using trust-aware allocation"""
        available_agents = [
            agent for agent in self.agents.values()
            if all(cap in agent.capabilities for cap in task.required_capabilities)
        ]
        
        if not available_agents:
            return None
        
        # Trust-aware allocation
        best_agent = max(available_agents, key=lambda a: a.trust_score)
        task.assigned_agent = best_agent.agent_id
        task.status = TaskStatus.IN_PROGRESS
        
        print(f"📋 Task {task.task_id} allocated to {best_agent.agent_id} (trust: {best_agent.trust_score:.3f})")
        return best_agent.agent_id
    
    async def execute_task_with_mcp_tools(self, task: Task, agent: Agent) -> bool:
        """Execute task using MCP tools"""
        print(f"⚡ Agent {agent.agent_id} executing: {task.description}")
        
        # Map task to MCP tools
        tool_mappings = {
            "data_processing": "data_processor",
            "data_analysis": "analyzer", 
            "monitoring": "monitor",
            "validation": "validator"
        }
        
        tool_id = None
        for capability in task.required_capabilities:
            if capability in tool_mappings:
                tool_id = tool_mappings[capability]
                break
        
        if not tool_id:
            print(f"❌ No suitable MCP tool for task {task.task_id}")
            return False
        
        # Execute MCP tool
        result = await self._execute_mcp_tool(tool_id, task.parameters, agent.agent_id)
        
        if result.get("success"):
            task.result = result
            task.status = TaskStatus.COMPLETED
            agent.tasks_completed += 1
            agent.trust_score = min(1.0, agent.trust_score + 0.05)
            print(f"✅ Task {task.task_id} completed successfully")
            return True
        else:
            task.status = TaskStatus.FAILED
            agent.trust_score = max(0.0, agent.trust_score - 0.1)
            print(f"❌ Task {task.task_id} failed: {result.get('error')}")
            return False
    
    async def _execute_mcp_tool(self, tool_id: str, parameters: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        """Execute MCP tool"""
        try:
            request_data = {
                "tool_id": tool_id,
                "parameters": parameters,
                "context": {"agent_id": agent_id}
            }
            
            async with self.session.post(f"{self.mcp_server_url}/execute", json=request_data) as response:
                if response.status == 200:
                    result = await response.json()
                    self.audit_log.append({
                        "timestamp": time.time(),
                        "agent_id": agent_id,
                        "tool_id": tool_id,
                        "success": result.get("success", False)
                    })
                    return result
                else:
                    return {"success": False, "error": f"HTTP {response.status}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def run_mas_simulation(self) -> None:
        """Run MAS simulation"""
        print("🚀 Starting Real MAS Prototype")
        print("=" * 50)
        
        await self.initialize_agents()
        await self.create_real_tasks()
        
        tools = await self.discover_mcp_tools()
        if not tools:
            print("❌ No MCP tools available. Start MCP server first.")
            return
        
        print(f"\n📊 System: {len(self.agents)} agents, {len(self.tasks)} tasks, {len(tools)} tools")
        
        # Execute tasks
        completed = 0
        for task in self.tasks.values():
            agent_id = await self.allocate_task_to_agent(task)
            if agent_id:
                agent = self.agents[agent_id]
                if await self.execute_task_with_mcp_tools(task, agent):
                    completed += 1
            await asyncio.sleep(0.1)
        
        # Display results
        print(f"\n📊 Results: {completed}/{len(self.tasks)} tasks completed")
        print(f"🔒 Audit log: {len(self.audit_log)} entries")
        
        for agent in self.agents.values():
            print(f"  {agent.name}: trust={agent.trust_score:.3f}, tasks={agent.tasks_completed}")


async def main():
    async with RealMASPrototype() as mas:
        await mas.run_mas_simulation()


if __name__ == "__main__":
    asyncio.run(main())