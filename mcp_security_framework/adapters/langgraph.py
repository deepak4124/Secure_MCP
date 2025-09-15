"""
LangGraph Security Adapter for MCP Security Framework

This module provides integration between LangGraph and the MCP Security Framework.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from langgraph.graph import StateGraph, END
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage

from .base import BaseSecurityAdapter, SecurityContext, SecurityEvent
from ..core.trust import TrustEvent, TrustEventType


class LangGraphSecurityAdapter(BaseSecurityAdapter):
    """
    Security adapter for LangGraph framework
    
    Provides secure integration between LangGraph agents and MCP tools
    with identity management, trust calculation, and policy enforcement.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize LangGraph security adapter"""
        super().__init__(*args, **kwargs)
        self.agent_workflows: Dict[str, StateGraph] = {}
    
    async def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Register a LangGraph agent with the security framework
        
        Args:
            agent_id: Unique agent identifier
            agent_type: Type of agent
            capabilities: List of agent capabilities
            metadata: Optional agent metadata
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Register with identity manager
            success, message = self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=b"langgraph_public_key",  # In real system, use actual key
                agent_type=agent_type,
                capabilities=capabilities,
                metadata=metadata or {}
            )
            
            if not success:
                return False, message
            
            # Activate agent
            self.identity_manager.activate_identity(agent_id)
            
            # Create security context
            context = SecurityContext(
                agent_id=agent_id,
                agent_type=agent_type,
                capabilities=capabilities,
                trust_score=0.5,  # Initial trust score
                session_id=f"langgraph_{agent_id}_{int(time.time())}",
                metadata=metadata or {}
            )
            
            self.active_agents[agent_id] = context
            
            # Log security event
            self._log_security_event(
                SecurityEvent.AGENT_REGISTERED,
                agent_id,
                {"agent_type": agent_type, "capabilities": capabilities}
            )
            
            return True, "LangGraph agent registered successfully"
            
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    async def authenticate_agent(self, agent_id: str, credentials: Dict[str, Any]) -> bool:
        """
        Authenticate a LangGraph agent
        
        Args:
            agent_id: Agent identifier
            credentials: Authentication credentials
            
        Returns:
            True if authentication successful
        """
        try:
            if agent_id not in self.active_agents:
                return False
            
            # Simple authentication for demo
            # In production, use proper authentication
            if credentials.get("auth_token") == f"langgraph_{agent_id}":
                self._log_security_event(
                    SecurityEvent.AGENT_AUTHENTICATED,
                    agent_id,
                    {"method": "token"}
                )
                return True
            
            return False
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
    
    async def request_tool_access(
        self,
        agent_id: str,
        tool_id: str,
        operation: str,
        parameters: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Request access to a tool for LangGraph agent
        
        Args:
            agent_id: Agent identifier
            tool_id: Tool identifier
            operation: Operation to perform
            parameters: Tool parameters
            
        Returns:
            Tuple of (allowed, reason)
        """
        try:
            # Check agent permissions
            allowed, reason = self._check_agent_permissions(
                agent_id, tool_id, operation, parameters
            )
            
            if allowed:
                self._log_security_event(
                    SecurityEvent.TOOL_REQUESTED,
                    agent_id,
                    {"tool_id": tool_id, "operation": operation}
                )
            else:
                self._log_security_event(
                    SecurityEvent.POLICY_VIOLATION,
                    agent_id,
                    {"tool_id": tool_id, "reason": reason}
                )
            
            return allowed, reason
            
        except Exception as e:
            return False, f"Access check failed: {str(e)}"
    
    async def execute_tool(
        self,
        agent_id: str,
        tool_id: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a tool with security controls for LangGraph agent
        
        Args:
            agent_id: Agent identifier
            tool_id: Tool identifier
            parameters: Tool parameters
            context: Optional execution context
            
        Returns:
            Tool execution result
        """
        try:
            # Check access first
            allowed, reason = await self.request_tool_access(
                agent_id, tool_id, "execute", parameters
            )
            
            if not allowed:
                return {
                    "success": False,
                    "error": f"Access denied: {reason}",
                    "tool_id": tool_id
                }
            
            # Execute tool through MCP gateway
            result = await self.mcp_gateway.execute_tool(
                tool_id=tool_id,
                parameters=parameters,
                agent_id=agent_id,
                context_id=context.get("context_id") if context else None
            )
            
            # Update agent activity
            self._update_agent_activity(agent_id)
            
            # Log execution
            self._log_security_event(
                SecurityEvent.TOOL_EXECUTED,
                agent_id,
                {
                    "tool_id": tool_id,
                    "success": result.get("success", False),
                    "execution_time": result.get("execution_time", 0)
                }
            )
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "tool_id": tool_id
            }
    
    async def report_trust_event(
        self,
        agent_id: str,
        event_type: str,
        event_data: Dict[str, Any]
    ) -> bool:
        """
        Report a trust event for LangGraph agent
        
        Args:
            agent_id: Agent identifier
            event_type: Type of trust event
            event_data: Event data
            
        Returns:
            True if event reported successfully
        """
        try:
            # Map event type to TrustEventType
            event_type_mapping = {
                "task_success": TrustEventType.TASK_SUCCESS,
                "task_failure": TrustEventType.TASK_FAILURE,
                "security_violation": TrustEventType.SECURITY_VIOLATION,
                "cooperation_positive": TrustEventType.COOPERATION_POSITIVE,
                "cooperation_negative": TrustEventType.COOPERATION_NEGATIVE,
                "honesty_positive": TrustEventType.HONESTY_POSITIVE,
                "honesty_negative": TrustEventType.HONESTY_NEGATIVE
            }
            
            trust_event_type = event_type_mapping.get(event_type)
            if not trust_event_type:
                return False
            
            # Create trust event
            trust_event = TrustEvent(
                event_id=f"langgraph_{agent_id}_{int(time.time())}",
                agent_id=agent_id,
                event_type=trust_event_type,
                timestamp=time.time(),
                value=event_data.get("value", 0.5),
                context=event_data.get("context", {}),
                source_agent=event_data.get("source_agent")
            )
            
            # Add to trust calculator
            success = self.trust_calculator.add_trust_event(trust_event)
            
            if success:
                # Update agent trust score
                trust_score = self.trust_calculator.get_trust_score(agent_id)
                if trust_score and agent_id in self.active_agents:
                    self.active_agents[agent_id].trust_score = trust_score.overall_score
                
                # Log security event
                self._log_security_event(
                    SecurityEvent.TRUST_UPDATED,
                    agent_id,
                    {
                        "event_type": event_type,
                        "new_trust_score": trust_score.overall_score if trust_score else 0.5
                    }
                )
            
            return success
            
        except Exception as e:
            print(f"Trust event reporting error: {e}")
            return False
    
    def create_secure_workflow(
        self,
        agent_id: str,
        workflow_name: str,
        nodes: Dict[str, callable],
        edges: List[Tuple[str, str]]
    ) -> StateGraph:
        """
        Create a secure LangGraph workflow for an agent
        
        Args:
            agent_id: Agent identifier
            workflow_name: Name of the workflow
            nodes: Dictionary of node functions
            edges: List of (from_node, to_node) tuples
            
        Returns:
            Secure LangGraph workflow
        """
        try:
            # Create workflow
            workflow = StateGraph(dict)
            
            # Add nodes
            for node_name, node_func in nodes.items():
                # Wrap node function with security controls
                secure_node_func = self._create_secure_node(agent_id, node_func)
                workflow.add_node(node_name, secure_node_func)
            
            # Add edges
            for from_node, to_node in edges:
                if to_node == "END":
                    workflow.add_edge(from_node, END)
                else:
                    workflow.add_edge(from_node, to_node)
            
            # Set entry point
            if edges:
                entry_point = edges[0][0]
                workflow.set_entry_point(entry_point)
            
            # Compile workflow
            compiled_workflow = workflow.compile()
            
            # Store workflow
            self.agent_workflows[f"{agent_id}_{workflow_name}"] = compiled_workflow
            
            return compiled_workflow
            
        except Exception as e:
            print(f"Workflow creation error: {e}")
            return None
    
    def _create_secure_node(self, agent_id: str, node_func: callable) -> callable:
        """
        Create a secure wrapper for a LangGraph node
        
        Args:
            agent_id: Agent identifier
            node_func: Original node function
            
        Returns:
            Secure node function
        """
        async def secure_node(state):
            try:
                # Update agent activity
                self._update_agent_activity(agent_id)
                
                # Execute original node function
                result = await node_func(state)
                
                # Log successful execution
                self._log_security_event(
                    SecurityEvent.TOOL_EXECUTED,
                    agent_id,
                    {"node": node_func.__name__, "success": True}
                )
                
                return result
                
            except Exception as e:
                # Log failed execution
                self._log_security_event(
                    SecurityEvent.SECURITY_ALERT,
                    agent_id,
                    {"node": node_func.__name__, "error": str(e)}
                )
                
                # Report trust event
                await self.report_trust_event(
                    agent_id,
                    "task_failure",
                    {
                        "value": 0.1,
                        "context": {"error": str(e), "node": node_func.__name__}
                    }
                )
                
                raise e
        
        return secure_node
    
    async def execute_workflow(
        self,
        agent_id: str,
        workflow_name: str,
        initial_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a secure workflow for an agent
        
        Args:
            agent_id: Agent identifier
            workflow_name: Name of the workflow
            initial_state: Initial workflow state
            
        Returns:
            Workflow execution result
        """
        try:
            workflow_key = f"{agent_id}_{workflow_name}"
            if workflow_key not in self.agent_workflows:
                return {
                    "success": False,
                    "error": f"Workflow not found: {workflow_name}"
                }
            
            workflow = self.agent_workflows[workflow_key]
            
            # Execute workflow
            result = await workflow.ainvoke(initial_state)
            
            # Report successful execution
            await self.report_trust_event(
                agent_id,
                "task_success",
                {
                    "value": 0.8,
                    "context": {"workflow": workflow_name}
                }
            )
            
            return {
                "success": True,
                "result": result,
                "workflow": workflow_name
            }
            
        except Exception as e:
            # Report failed execution
            await self.report_trust_event(
                agent_id,
                "task_failure",
                {
                    "value": 0.1,
                    "context": {"workflow": workflow_name, "error": str(e)}
                }
            )
            
            return {
                "success": False,
                "error": str(e),
                "workflow": workflow_name
            }
    
    def get_agent_workflows(self, agent_id: str) -> List[str]:
        """
        Get list of workflows for an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of workflow names
        """
        workflows = []
        prefix = f"{agent_id}_"
        
        for workflow_key in self.agent_workflows.keys():
            if workflow_key.startswith(prefix):
                workflow_name = workflow_key[len(prefix):]
                workflows.append(workflow_name)
        
        return workflows
