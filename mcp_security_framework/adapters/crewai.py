"""
CrewAI Security Adapter for MCP Security Framework

This module provides integration between CrewAI and the MCP Security Framework.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple

from .base import BaseSecurityAdapter, SecurityContext, SecurityEvent
from ..core.trust import TrustEvent, TrustEventType


class CrewAISecurityAdapter(BaseSecurityAdapter):
    """
    Security adapter for CrewAI framework
    
    Provides secure integration between CrewAI agents and MCP tools
    with identity management, trust calculation, and policy enforcement.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize CrewAI security adapter"""
        super().__init__(*args, **kwargs)
        self.crew_sessions: Dict[str, Dict[str, Any]] = {}
        self.agent_tasks: Dict[str, List[Dict[str, Any]]] = {}
    
    async def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Register a CrewAI agent with the security framework
        
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
                public_key=b"crewai_public_key",  # In real system, use actual key
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
                session_id=f"crewai_{agent_id}_{int(time.time())}",
                metadata=metadata or {}
            )
            
            self.active_agents[agent_id] = context
            self.agent_tasks[agent_id] = []
            
            # Log security event
            self._log_security_event(
                SecurityEvent.AGENT_REGISTERED,
                agent_id,
                {"agent_type": agent_type, "capabilities": capabilities}
            )
            
            return True, "CrewAI agent registered successfully"
            
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    async def authenticate_agent(self, agent_id: str, credentials: Dict[str, Any]) -> bool:
        """
        Authenticate a CrewAI agent
        
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
            if credentials.get("auth_token") == f"crewai_{agent_id}":
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
        Request access to a tool for CrewAI agent
        
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
        Execute a tool with security controls for CrewAI agent
        
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
        Report a trust event for CrewAI agent
        
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
                event_id=f"crewai_{agent_id}_{int(time.time())}",
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
    
    async def create_crew(
        self,
        crew_id: str,
        crew_name: str,
        agents: List[str],
        tasks: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Create a secure crew with CrewAI agents
        
        Args:
            crew_id: Unique crew identifier
            crew_name: Name of the crew
            agents: List of agent IDs in the crew
            tasks: List of tasks for the crew
            metadata: Optional crew metadata
            
        Returns:
            True if crew created successfully
        """
        try:
            # Verify all agents are registered
            for agent_id in agents:
                if agent_id not in self.active_agents:
                    return False
            
            # Create crew session
            crew_session = {
                "crew_id": crew_id,
                "crew_name": crew_name,
                "agents": agents,
                "tasks": tasks,
                "metadata": metadata or {},
                "created_at": time.time(),
                "status": "active"
            }
            
            self.crew_sessions[crew_id] = crew_session
            
            # Log crew creation
            self._log_security_event(
                SecurityEvent.AGENT_AUTHENTICATED,
                agents[0],  # Use first agent as initiator
                {
                    "action": "crew_created",
                    "crew_id": crew_id,
                    "crew_name": crew_name,
                    "agents": agents
                }
            )
            
            return True
            
        except Exception as e:
            print(f"Crew creation error: {e}")
            return False
    
    async def execute_crew_task(
        self,
        crew_id: str,
        task_id: str,
        task_description: str,
        assigned_agent: str,
        task_parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a task within a crew with security controls
        
        Args:
            crew_id: Crew identifier
            task_id: Task identifier
            task_description: Description of the task
            assigned_agent: Agent assigned to the task
            task_parameters: Task parameters
            
        Returns:
            Task execution result
        """
        try:
            # Verify crew exists
            if crew_id not in self.crew_sessions:
                return {
                    "success": False,
                    "error": f"Crew not found: {crew_id}"
                }
            
            # Verify agent is in crew
            crew = self.crew_sessions[crew_id]
            if assigned_agent not in crew["agents"]:
                return {
                    "success": False,
                    "error": f"Agent {assigned_agent} not in crew {crew_id}"
                }
            
            # Update agent activity
            self._update_agent_activity(assigned_agent)
            
            # Record task assignment
            task_data = {
                "task_id": task_id,
                "crew_id": crew_id,
                "assigned_agent": assigned_agent,
                "task_description": task_description,
                "parameters": task_parameters,
                "assigned_at": time.time(),
                "status": "in_progress"
            }
            
            if assigned_agent not in self.agent_tasks:
                self.agent_tasks[assigned_agent] = []
            
            self.agent_tasks[assigned_agent].append(task_data)
            
            # Simulate task execution
            # In real implementation, this would integrate with CrewAI's task execution
            result = {
                "success": True,
                "task_id": task_id,
                "crew_id": crew_id,
                "assigned_agent": assigned_agent,
                "task_description": task_description,
                "execution_time": 0.2,
                "result": f"Task completed by {assigned_agent} in crew {crew_id}"
            }
            
            # Update task status
            task_data["status"] = "completed"
            task_data["completed_at"] = time.time()
            task_data["result"] = result
            
            # Report successful task execution
            await self.report_trust_event(
                assigned_agent,
                "task_success",
                {
                    "value": 0.8,
                    "context": {
                        "task_id": task_id,
                        "crew_id": crew_id,
                        "execution_time": result["execution_time"]
                    }
                }
            )
            
            # Report cooperation event for other agents in crew
            for agent_id in crew["agents"]:
                if agent_id != assigned_agent:
                    await self.report_trust_event(
                        agent_id,
                        "cooperation_positive",
                        {
                            "value": 0.6,
                            "context": {
                                "task_id": task_id,
                                "crew_id": crew_id,
                                "cooperating_agent": assigned_agent
                            },
                            "source_agent": assigned_agent
                        }
                    )
            
            return result
            
        except Exception as e:
            # Report failed task execution
            await self.report_trust_event(
                assigned_agent,
                "task_failure",
                {
                    "value": 0.1,
                    "context": {
                        "task_id": task_id,
                        "crew_id": crew_id,
                        "error": str(e)
                    }
                }
            )
            
            return {
                "success": False,
                "error": str(e),
                "task_id": task_id,
                "crew_id": crew_id
            }
    
    async def get_crew_status(self, crew_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a crew
        
        Args:
            crew_id: Crew identifier
            
        Returns:
            Crew status information or None if not found
        """
        if crew_id not in self.crew_sessions:
            return None
        
        crew = self.crew_sessions[crew_id]
        
        # Get task statistics for each agent
        agent_stats = {}
        for agent_id in crew["agents"]:
            tasks = self.agent_tasks.get(agent_id, [])
            crew_tasks = [t for t in tasks if t.get("crew_id") == crew_id]
            
            agent_stats[agent_id] = {
                "total_tasks": len(crew_tasks),
                "completed_tasks": len([t for t in crew_tasks if t.get("status") == "completed"]),
                "in_progress_tasks": len([t for t in crew_tasks if t.get("status") == "in_progress"]),
                "trust_score": self._get_agent_trust_score(agent_id)
            }
        
        return {
            "crew_id": crew_id,
            "crew_name": crew["crew_name"],
            "agents": crew["agents"],
            "status": crew["status"],
            "created_at": crew["created_at"],
            "agent_stats": agent_stats,
            "total_tasks": len(crew["tasks"])
        }
    
    def get_agent_tasks(
        self,
        agent_id: str,
        crew_id: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get tasks for an agent
        
        Args:
            agent_id: Agent identifier
            crew_id: Optional specific crew ID
            status: Optional task status filter
            
        Returns:
            List of agent tasks
        """
        if agent_id not in self.agent_tasks:
            return []
        
        tasks = self.agent_tasks[agent_id]
        
        # Filter by crew ID if specified
        if crew_id:
            tasks = [t for t in tasks if t.get("crew_id") == crew_id]
        
        # Filter by status if specified
        if status:
            tasks = [t for t in tasks if t.get("status") == status]
        
        return tasks
    
    def get_crew_list(self) -> List[Dict[str, Any]]:
        """
        Get list of all crews
        
        Returns:
            List of crew information
        """
        crews = []
        for crew_id, crew in self.crew_sessions.items():
            crews.append({
                "crew_id": crew_id,
                "crew_name": crew["crew_name"],
                "agents": crew["agents"],
                "status": crew["status"],
                "created_at": crew["created_at"]
            })
        
        return crews
