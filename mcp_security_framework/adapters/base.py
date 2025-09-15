"""
Base Security Adapter for MCP Security Framework

This module provides the base class and interfaces for MAS framework adapters.
"""

import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class SecurityContext:
    """Security context for agent operations"""
    
    def __init__(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: List[str],
        trust_score: float,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.capabilities = capabilities
        self.trust_score = trust_score
        self.session_id = session_id
        self.metadata = metadata or {}
        self.created_at = time.time()
        self.last_activity = time.time()


@dataclass
class AgentInfo:
    """Agent information structure"""
    agent_id: str
    agent_type: str
    capabilities: List[str]
    trust_score: float
    status: str
    metadata: Dict[str, Any]


class SecurityEvent(Enum):
    """Security event types"""
    AGENT_REGISTERED = "agent_registered"
    AGENT_AUTHENTICATED = "agent_authenticated"
    TOOL_REQUESTED = "tool_requested"
    TOOL_EXECUTED = "tool_executed"
    TRUST_UPDATED = "trust_updated"
    POLICY_VIOLATION = "policy_violation"
    SECURITY_ALERT = "security_alert"


class BaseSecurityAdapter(ABC):
    """
    Base class for MAS framework security adapters
    
    This class defines the interface that all MAS framework adapters must implement
    to integrate with the MCP Security Framework.
    """
    
    def __init__(
        self,
        identity_manager,
        trust_calculator,
        policy_engine,
        mcp_gateway,
        tool_registry
    ):
        """
        Initialize security adapter
        
        Args:
            identity_manager: Identity management system
            trust_calculator: Trust calculation system
            policy_engine: Policy enforcement engine
            mcp_gateway: MCP security gateway
            tool_registry: Tool registry
        """
        self.identity_manager = identity_manager
        self.trust_calculator = trust_calculator
        self.policy_engine = policy_engine
        self.mcp_gateway = mcp_gateway
        self.tool_registry = tool_registry
        
        # Adapter state
        self.active_agents: Dict[str, SecurityContext] = {}
        self.security_events: List[Dict[str, Any]] = []
    
    @abstractmethod
    async def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Register an agent with the security framework
        
        Args:
            agent_id: Unique agent identifier
            agent_type: Type of agent
            capabilities: List of agent capabilities
            metadata: Optional agent metadata
            
        Returns:
            Tuple of (success, message)
        """
        pass
    
    @abstractmethod
    async def authenticate_agent(self, agent_id: str, credentials: Dict[str, Any]) -> bool:
        """
        Authenticate an agent
        
        Args:
            agent_id: Agent identifier
            credentials: Authentication credentials
            
        Returns:
            True if authentication successful
        """
        pass
    
    @abstractmethod
    async def request_tool_access(
        self,
        agent_id: str,
        tool_id: str,
        operation: str,
        parameters: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Request access to a tool
        
        Args:
            agent_id: Agent identifier
            tool_id: Tool identifier
            operation: Operation to perform
            parameters: Tool parameters
            
        Returns:
            Tuple of (allowed, reason)
        """
        pass
    
    @abstractmethod
    async def execute_tool(
        self,
        agent_id: str,
        tool_id: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a tool with security controls
        
        Args:
            agent_id: Agent identifier
            tool_id: Tool identifier
            parameters: Tool parameters
            context: Optional execution context
            
        Returns:
            Tool execution result
        """
        pass
    
    @abstractmethod
    async def report_trust_event(
        self,
        agent_id: str,
        event_type: str,
        event_data: Dict[str, Any]
    ) -> bool:
        """
        Report a trust event
        
        Args:
            agent_id: Agent identifier
            event_type: Type of trust event
            event_data: Event data
            
        Returns:
            True if event reported successfully
        """
        pass
    
    def get_agent_info(self, agent_id: str) -> Optional[AgentInfo]:
        """
        Get agent information
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Agent information or None if not found
        """
        if agent_id not in self.active_agents:
            return None
        
        context = self.active_agents[agent_id]
        identity = self.identity_manager.get_agent_identity(agent_id)
        
        if not identity:
            return None
        
        return AgentInfo(
            agent_id=agent_id,
            agent_type=context.agent_type,
            capabilities=context.capabilities,
            trust_score=context.trust_score,
            status=identity.status.value,
            metadata=context.metadata
        )
    
    def list_active_agents(self) -> List[AgentInfo]:
        """
        List all active agents
        
        Returns:
            List of active agent information
        """
        agents = []
        for agent_id in self.active_agents:
            agent_info = self.get_agent_info(agent_id)
            if agent_info:
                agents.append(agent_info)
        
        return agents
    
    def get_security_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get security events
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of security events
        """
        events = self.security_events.copy()
        if limit:
            events = events[-limit:]
        
        return events
    
    def _log_security_event(
        self,
        event_type: SecurityEvent,
        agent_id: str,
        details: Dict[str, Any]
    ) -> None:
        """
        Log a security event
        
        Args:
            event_type: Type of security event
            agent_id: Agent identifier
            details: Event details
        """
        event = {
            "timestamp": time.time(),
            "event_type": event_type.value,
            "agent_id": agent_id,
            "details": details
        }
        
        self.security_events.append(event)
    
    def _update_agent_activity(self, agent_id: str) -> None:
        """
        Update agent activity timestamp
        
        Args:
            agent_id: Agent identifier
        """
        if agent_id in self.active_agents:
            self.active_agents[agent_id].last_activity = time.time()
    
    def _get_agent_trust_score(self, agent_id: str) -> float:
        """
        Get current trust score for agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Current trust score
        """
        trust_score = self.trust_calculator.get_trust_score(agent_id)
        if trust_score:
            return trust_score.overall_score
        
        # Return default trust score
        return 0.5
    
    def _check_agent_permissions(
        self,
        agent_id: str,
        tool_id: str,
        operation: str,
        parameters: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Check agent permissions for tool access
        
        Args:
            agent_id: Agent identifier
            tool_id: Tool identifier
            operation: Operation to perform
            parameters: Tool parameters
            
        Returns:
            Tuple of (allowed, reason)
        """
        # Get agent context
        if agent_id not in self.active_agents:
            return False, "Agent not active"
        
        context = self.active_agents[agent_id]
        
        # Get tool information
        tool = self.tool_registry.get_tool(tool_id)
        if not tool:
            return False, "Tool not found"
        
        # Create policy context
        from ..core.policy import PolicyContext
        policy_context = PolicyContext(
            agent_id=agent_id,
            agent_type=context.agent_type,
            agent_capabilities=context.capabilities,
            agent_trust_score=context.trust_score,
            tool_id=tool_id,
            tool_risk_level=tool.risk_level,
            operation=operation,
            parameters=parameters,
            context_metadata=context.metadata
        )
        
        # Evaluate policy
        decision = self.policy_engine.evaluate_access(policy_context)
        
        if decision.value == "deny":
            return False, "Policy denied access"
        
        return True, "Access granted"
