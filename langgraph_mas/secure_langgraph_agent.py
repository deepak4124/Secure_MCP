"""
Secure LangGraph Agent Framework

This module provides secure LangGraph agents that integrate with the MCP security framework,
including identity management, trust calculation, and secure tool execution.
"""

import asyncio
import time
import json
from typing import Dict, List, Optional, Any, TypedDict, Annotated
from dataclasses import dataclass
from enum import Enum
import base64
import hashlib

# LangGraph imports
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

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
from integration.mcp_security_gateway import MCPSecurityGateway, MCPTool
from config.env_config import config


class AgentState(TypedDict):
    """State for LangGraph agent execution"""
    messages: Annotated[List[BaseMessage], add_messages]
    task_id: str
    task_type: str
    task_description: str
    parameters: Dict[str, Any]
    agent_id: str
    trust_score: float
    mcp_tools: List[str]
    execution_result: Optional[Dict[str, Any]]
    error: Optional[str]
    execution_time: float
    security_events: List[Dict[str, Any]]


class SecureLangGraphAgent:
    """
    Secure LangGraph agent that integrates with MCP security framework
    
    Features:
    - Real LLM reasoning with Gemini API
    - MCP tool integration with security verification
    - Trust-aware decision making
    - Identity management and authentication
    - Performance monitoring and trust reporting
    """
    
    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        capabilities: List[str],
        llm_model: str = "gemini-1.5-flash",
        system_prompt: Optional[str] = None
    ):
        """
        Initialize secure LangGraph agent
        
        Args:
            agent_id: Unique agent identifier
            agent_type: Type of agent (worker, coordinator, etc.)
            capabilities: List of agent capabilities
            llm_model: LLM model to use
            system_prompt: Custom system prompt
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.capabilities = capabilities
        self.llm_model = llm_model
        
        # Initialize LLM
        self.llm = ChatGoogleGenerativeAI(
            model=llm_model,
            google_api_key=config.get_gemini_api_key(),
            temperature=0.1,
            max_output_tokens=2048
        )
        
        # Agent state
        self.is_registered = False
        self.trust_score = 0.5
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.last_activity = time.time()
        
        # MCP integration
        self.available_tools: List[MCPTool] = []
        self.tool_usage_stats: Dict[str, Dict[str, Any]] = {}
        
        # System prompt
        self.system_prompt = system_prompt or self._get_default_system_prompt()
        
        # Create LangGraph workflow
        self.workflow = self._create_workflow()
    
    def _get_default_system_prompt(self) -> str:
        """Get default system prompt for the agent"""
        return f"""You are {self.agent_id}, a secure AI agent with the following capabilities: {', '.join(self.capabilities)}.

Your role is to:
1. Execute tasks using available MCP tools securely
2. Make decisions based on trust scores and security policies
3. Report your performance to maintain trust
4. Follow security protocols at all times

Available MCP tools: {[tool.name for tool in self.available_tools]}

Security guidelines:
- Only use verified MCP tools
- Report all tool executions for audit
- Maintain high trust scores through good performance
- Follow access control policies
- Report security incidents immediately

Current trust score: {self.trust_score}
Tasks completed: {self.tasks_completed}
Tasks failed: {self.tasks_failed}
"""
    
    def _create_workflow(self) -> StateGraph:
        """Create LangGraph workflow for the agent"""
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("analyze_task", self._analyze_task)
        workflow.add_node("select_tools", self._select_tools)
        workflow.add_node("execute_tools", self._execute_tools)
        workflow.add_node("validate_results", self._validate_results)
        workflow.add_node("report_performance", self._report_performance)
        
        # Add edges
        workflow.set_entry_point("analyze_task")
        workflow.add_edge("analyze_task", "select_tools")
        workflow.add_edge("select_tools", "execute_tools")
        workflow.add_edge("execute_tools", "validate_results")
        workflow.add_edge("validate_results", "report_performance")
        workflow.add_edge("report_performance", END)
        
        return workflow.compile()
    
    async def register_with_system(
        self,
        identity_manager: IdentityManager,
        mcp_gateway: MCPSecurityGateway
    ) -> bool:
        """Register agent with the security system"""
        # Register with identity manager
        success, message = identity_manager.register_agent(
            agent_id=self.agent_id,
            public_key=b"langgraph_public_key",  # In real system, use actual key
            agent_type=self.agent_type,
            capabilities=self.capabilities,
            metadata={
                "version": "1.0",
                "framework": "langgraph",
                "llm_model": self.llm_model,
                "mcp_enabled": "true"
            }
        )
        
        if success:
            self.is_registered = True
            identity_manager.activate_identity(self.agent_id)
            
            # Get available MCP tools
            self.available_tools = mcp_gateway.get_verified_tools()
            
            print(f"LangGraph Agent {self.agent_id} registered with {len(self.available_tools)} MCP tools")
            return True
        
        return False
    
    async def execute_task(
        self,
        task_id: str,
        task_type: str,
        task_description: str,
        parameters: Dict[str, Any],
        mcp_gateway: MCPSecurityGateway,
        trust_calculator: TrustCalculator
    ) -> Dict[str, Any]:
        """Execute a task using LangGraph workflow"""
        print(f"LangGraph Agent {self.agent_id} executing task: {task_id}")
        
        start_time = time.time()
        
        # Create initial state
        initial_state = AgentState(
            messages=[
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=f"Execute task: {task_description}")
            ],
            task_id=task_id,
            task_type=task_type,
            task_description=task_description,
            parameters=parameters,
            agent_id=self.agent_id,
            trust_score=self.trust_score,
            mcp_tools=[tool.tool_id for tool in self.available_tools],
            execution_result=None,
            error=None,
            execution_time=0.0,
            security_events=[]
        )
        
        try:
            # Execute workflow
            final_state = await self.workflow.ainvoke(initial_state)
            
            # Update agent statistics
            execution_time = time.time() - start_time
            final_state["execution_time"] = execution_time
            
            if final_state.get("error"):
                self.tasks_failed += 1
                await self._report_task_failure(task_id, final_state["error"], trust_calculator)
            else:
                self.tasks_completed += 1
                await self._report_task_success(task_id, execution_time, trust_calculator)
            
            self.last_activity = time.time()
            
            return {
                "success": not bool(final_state.get("error")),
                "task_id": task_id,
                "agent_id": self.agent_id,
                "result": final_state.get("execution_result"),
                "error": final_state.get("error"),
                "execution_time": execution_time,
                "security_events": final_state.get("security_events", [])
            }
            
        except Exception as e:
            self.tasks_failed += 1
            await self._report_task_failure(task_id, str(e), trust_calculator)
            
            return {
                "success": False,
                "task_id": task_id,
                "agent_id": self.agent_id,
                "error": str(e),
                "execution_time": time.time() - start_time,
                "security_events": []
            }
    
    async def _analyze_task(self, state: AgentState) -> AgentState:
        """Analyze the task using LLM"""
        try:
            # Create analysis prompt
            analysis_prompt = f"""
            Analyze this task and determine the best approach:
            
            Task ID: {state['task_id']}
            Task Type: {state['task_type']}
            Description: {state['task_description']}
            Parameters: {json.dumps(state['parameters'], indent=2)}
            
            Available MCP Tools: {[tool.name for tool in self.available_tools]}
            Agent Capabilities: {self.capabilities}
            Current Trust Score: {state['trust_score']}
            
            Provide a brief analysis of:
            1. What this task requires
            2. Which tools would be most appropriate
            3. Any security considerations
            4. Expected complexity
            
            Keep your response concise and focused.
            """
            
            # Get LLM analysis
            response = await self.llm.ainvoke([HumanMessage(content=analysis_prompt)])
            analysis = response.content
            
            # Add analysis to messages
            state["messages"].append(AIMessage(content=f"Task Analysis: {analysis}"))
            
            print(f"Agent {self.agent_id} analyzed task {state['task_id']}")
            
        except Exception as e:
            state["error"] = f"Task analysis failed: {str(e)}"
            print(f"Error in task analysis: {e}")
        
        return state
    
    async def _select_tools(self, state: AgentState) -> AgentState:
        """Select appropriate MCP tools for the task"""
        try:
            # Create tool selection prompt
            tool_selection_prompt = f"""
            Select the best MCP tools for this task:
            
            Task: {state['task_description']}
            Task Type: {state['task_type']}
            
            Available Tools:
            {json.dumps([{
                'id': tool.tool_id,
                'name': tool.name,
                'description': tool.description,
                'capabilities': tool.capabilities,
                'risk_level': tool.risk_level.value
            } for tool in self.available_tools], indent=2)}
            
            Select 1-3 tools that are most appropriate for this task.
            Consider:
            1. Tool capabilities vs task requirements
            2. Security risk levels (prefer LOW risk tools)
            3. Agent capabilities and trust score
            
            Respond with a JSON list of tool IDs: ["tool_id_1", "tool_id_2"]
            """
            
            # Get LLM tool selection
            response = await self.llm.ainvoke([HumanMessage(content=tool_selection_prompt)])
            tool_selection = response.content
            
            # Parse tool selection
            try:
                selected_tools = json.loads(tool_selection)
                if not isinstance(selected_tools, list):
                    selected_tools = [selected_tools]
            except json.JSONDecodeError:
                # Fallback: select first available tool
                selected_tools = [self.available_tools[0].tool_id] if self.available_tools else []
            
            # Validate selected tools
            valid_tools = []
            for tool_id in selected_tools:
                if any(tool.tool_id == tool_id for tool in self.available_tools):
                    valid_tools.append(tool_id)
            
            state["mcp_tools"] = valid_tools
            state["messages"].append(AIMessage(content=f"Selected tools: {valid_tools}"))
            
            print(f"Agent {self.agent_id} selected tools: {valid_tools}")
            
        except Exception as e:
            state["error"] = f"Tool selection failed: {str(e)}"
            print(f"Error in tool selection: {e}")
        
        return state
    
    async def _execute_tools(self, state: AgentState) -> AgentState:
        """Execute selected MCP tools"""
        try:
            if not state["mcp_tools"]:
                state["error"] = "No tools selected for execution"
                return state
            
            # This would integrate with MCP gateway
            # For now, simulate tool execution
            results = []
            for tool_id in state["mcp_tools"]:
                # Simulate tool execution
                result = {
                    "tool_id": tool_id,
                    "status": "success",
                    "result": f"Tool {tool_id} executed successfully",
                    "execution_time": 0.1
                }
                results.append(result)
                
                # Log security event
                security_event = {
                    "timestamp": time.time(),
                    "agent_id": self.agent_id,
                    "action": "tool_execution",
                    "tool_id": tool_id,
                    "status": "success"
                }
                state["security_events"].append(security_event)
            
            state["execution_result"] = {
                "tools_used": state["mcp_tools"],
                "results": results,
                "success": True
            }
            
            state["messages"].append(AIMessage(content=f"Tool execution completed: {len(results)} tools executed"))
            
            print(f"Agent {self.agent_id} executed {len(results)} tools")
            
        except Exception as e:
            state["error"] = f"Tool execution failed: {str(e)}"
            print(f"Error in tool execution: {e}")
        
        return state
    
    async def _validate_results(self, state: AgentState) -> AgentState:
        """Validate tool execution results"""
        try:
            if not state.get("execution_result"):
                state["error"] = "No execution results to validate"
                return state
            
            # Create validation prompt
            validation_prompt = f"""
            Validate the results of this task execution:
            
            Task: {state['task_description']}
            Tools Used: {state['mcp_tools']}
            Results: {json.dumps(state['execution_result'], indent=2)}
            
            Check if:
            1. The results are complete and accurate
            2. All required information was extracted/processed
            3. The results match the task requirements
            4. Any security issues are present
            
            Respond with "VALID" if results are good, or describe any issues.
            """
            
            # Get LLM validation
            response = await self.llm.ainvoke([HumanMessage(content=validation_prompt)])
            validation = response.content
            
            if "VALID" in validation.upper():
                state["messages"].append(AIMessage(content="Results validated successfully"))
                print(f"Agent {self.agent_id} validated results for task {state['task_id']}")
            else:
                state["error"] = f"Validation failed: {validation}"
                print(f"Validation failed for task {state['task_id']}: {validation}")
            
        except Exception as e:
            state["error"] = f"Result validation failed: {str(e)}"
            print(f"Error in result validation: {e}")
        
        return state
    
    async def _report_performance(self, state: AgentState) -> AgentState:
        """Report performance and update trust"""
        try:
            # Create performance report
            performance_report = {
                "task_id": state["task_id"],
                "agent_id": self.agent_id,
                "execution_time": state["execution_time"],
                "tools_used": state["mcp_tools"],
                "success": not bool(state.get("error")),
                "security_events": len(state.get("security_events", [])),
                "timestamp": time.time()
            }
            
            state["messages"].append(AIMessage(content=f"Performance reported: {json.dumps(performance_report, indent=2)}"))
            
            print(f"Agent {self.agent_id} reported performance for task {state['task_id']}")
            
        except Exception as e:
            print(f"Error in performance reporting: {e}")
        
        return state
    
    async def _report_task_success(
        self,
        task_id: str,
        execution_time: float,
        trust_calculator: TrustCalculator
    ):
        """Report successful task completion"""
        event = TrustEvent(
            event_id=f"success_{task_id}_{int(time.time())}",
            agent_id=self.agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time(),
            value=min(1.0, 0.8 + (1.0 / execution_time) * 0.2),  # Faster = higher value
            context={
                "task_id": task_id,
                "execution_time": execution_time,
                "framework": "langgraph",
                "llm_model": self.llm_model
            }
        )
        
        trust_calculator.add_trust_event(event)
    
    async def _report_task_failure(
        self,
        task_id: str,
        error: str,
        trust_calculator: TrustCalculator
    ):
        """Report failed task completion"""
        event = TrustEvent(
            event_id=f"failure_{task_id}_{int(time.time())}",
            agent_id=self.agent_id,
            event_type=TrustEventType.TASK_FAILURE,
            timestamp=time.time(),
            value=0.1,
            context={
                "task_id": task_id,
                "error": error,
                "framework": "langgraph",
                "llm_model": self.llm_model
            }
        )
        
        trust_calculator.add_trust_event(event)
    
    def get_trust_score(self, trust_calculator: TrustCalculator) -> Optional[float]:
        """Get current trust score"""
        trust_score = trust_calculator.get_trust_score(self.agent_id)
        if trust_score:
            self.trust_score = trust_score.overall_score
            return trust_score.overall_score
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "capabilities": self.capabilities,
            "llm_model": self.llm_model,
            "trust_score": self.trust_score,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "available_tools": len(self.available_tools),
            "last_activity": self.last_activity
        }


# Example usage and testing
async def main():
    """Example usage of SecureLangGraphAgent"""
    from security.authentication.identity_management import IdentityManager
    from trust.trust_calculator import TrustCalculator
    from integration.mcp_security_gateway import MCPSecurityGateway
    
    # Initialize system components
    identity_manager = IdentityManager()
    trust_calculator = TrustCalculator(min_events=1)
    
    async with MCPSecurityGateway() as mcp_gateway:
        # Create secure LangGraph agent
        agent = SecureLangGraphAgent(
            agent_id="langgraph_agent_001",
            agent_type=AgentType.WORKER,
            capabilities=["document_analysis", "data_extraction"],
            llm_model="gemini-1.5-flash"
        )
        
        # Register agent
        await agent.register_with_system(identity_manager, mcp_gateway)
        
        # Execute a task
        result = await agent.execute_task(
            task_id="test_task_001",
            task_type="document_analysis",
            task_description="Analyze a PDF document and extract key information",
            parameters={"file_path": "sample.pdf", "extract_fields": ["title", "author", "date"]},
            mcp_gateway=mcp_gateway,
            trust_calculator=trust_calculator
        )
        
        print(f"Task execution result: {result}")
        print(f"Agent stats: {agent.get_stats()}")


if __name__ == "__main__":
    asyncio.run(main())
