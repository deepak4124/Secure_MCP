"""
AutoGen Security Adapter for MCP Security Framework

This module provides integration between AutoGen and the MCP Security Framework.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple

from .base import BaseSecurityAdapter, SecurityContext, SecurityEvent
from ..core.trust import TrustEvent, TrustEventType


class AutoGenSecurityAdapter(BaseSecurityAdapter):
    """
    Security adapter for AutoGen framework
    
    Provides secure integration between AutoGen agents and MCP tools
    with identity management, trust calculation, and policy enforcement.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize AutoGen security adapter"""
        super().__init__(*args, **kwargs)
        self.agent_conversations: Dict[str, List[Dict[str, Any]]] = {}
    
    async def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Register an AutoGen agent with the security framework
        
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
                public_key=b"autogen_public_key",  # In real system, use actual key
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
                session_id=f"autogen_{agent_id}_{int(time.time())}",
                metadata=metadata or {}
            )
            
            self.active_agents[agent_id] = context
            self.agent_conversations[agent_id] = []
            
            # Log security event
            self._log_security_event(
                SecurityEvent.AGENT_REGISTERED,
                agent_id,
                {"agent_type": agent_type, "capabilities": capabilities}
            )
            
            return True, "AutoGen agent registered successfully"
            
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    async def authenticate_agent(self, agent_id: str, credentials: Dict[str, Any]) -> bool:
        """
        Authenticate an AutoGen agent
        
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
            if credentials.get("auth_token") == f"autogen_{agent_id}":
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
        Request access to a tool for AutoGen agent
        
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
        Execute a tool with security controls for AutoGen agent
        
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
        Report a trust event for AutoGen agent
        
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
                event_id=f"autogen_{agent_id}_{int(time.time())}",
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
    
    async def start_conversation(
        self,
        agent_id: str,
        conversation_id: str,
        participants: List[str]
    ) -> bool:
        """
        Start a secure conversation between AutoGen agents
        
        Args:
            agent_id: Initiating agent identifier
            conversation_id: Unique conversation identifier
            participants: List of participant agent IDs
            
        Returns:
            True if conversation started successfully
        """
        try:
            # Verify all participants are registered
            for participant_id in participants:
                if participant_id not in self.active_agents:
                    return False
            
            # Log conversation start
            self._log_security_event(
                SecurityEvent.AGENT_AUTHENTICATED,
                agent_id,
                {
                    "conversation_id": conversation_id,
                    "participants": participants,
                    "action": "conversation_started"
                }
            )
            
            return True
            
        except Exception as e:
            print(f"Conversation start error: {e}")
            return False
    
    async def send_message(
        self,
        agent_id: str,
        conversation_id: str,
        message: str,
        recipient_id: Optional[str] = None
    ) -> bool:
        """
        Send a secure message in AutoGen conversation
        
        Args:
            agent_id: Sender agent identifier
            conversation_id: Conversation identifier
            message: Message content
            recipient_id: Optional specific recipient
            
        Returns:
            True if message sent successfully
        """
        try:
            # Update agent activity
            self._update_agent_activity(agent_id)
            
            # Store message in conversation history
            if agent_id not in self.agent_conversations:
                self.agent_conversations[agent_id] = []
            
            message_data = {
                "timestamp": time.time(),
                "conversation_id": conversation_id,
                "sender": agent_id,
                "recipient": recipient_id,
                "message": message
            }
            
            self.agent_conversations[agent_id].append(message_data)
            
            # Log message
            self._log_security_event(
                SecurityEvent.TOOL_EXECUTED,
                agent_id,
                {
                    "action": "message_sent",
                    "conversation_id": conversation_id,
                    "recipient": recipient_id
                }
            )
            
            return True
            
        except Exception as e:
            print(f"Message send error: {e}")
            return False
    
    async def execute_agent_task(
        self,
        agent_id: str,
        task_description: str,
        task_parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a task for AutoGen agent with security controls
        
        Args:
            agent_id: Agent identifier
            task_description: Description of the task
            task_parameters: Task parameters
            
        Returns:
            Task execution result
        """
        try:
            # Update agent activity
            self._update_agent_activity(agent_id)
            
            # Simulate task execution
            # In real implementation, this would integrate with AutoGen's task execution
            result = {
                "success": True,
                "task_description": task_description,
                "parameters": task_parameters,
                "execution_time": 0.1,
                "result": f"Task completed by {agent_id}"
            }
            
            # Report successful task execution
            await self.report_trust_event(
                agent_id,
                "task_success",
                {
                    "value": 0.8,
                    "context": {
                        "task_description": task_description,
                        "execution_time": result["execution_time"]
                    }
                }
            )
            
            return result
            
        except Exception as e:
            # Report failed task execution
            await self.report_trust_event(
                agent_id,
                "task_failure",
                {
                    "value": 0.1,
                    "context": {
                        "task_description": task_description,
                        "error": str(e)
                    }
                }
            )
            
            return {
                "success": False,
                "error": str(e),
                "task_description": task_description
            }
    
    def get_conversation_history(
        self,
        agent_id: str,
        conversation_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get conversation history for an agent
        
        Args:
            agent_id: Agent identifier
            conversation_id: Optional specific conversation ID
            limit: Maximum number of messages to return
            
        Returns:
            List of conversation messages
        """
        if agent_id not in self.agent_conversations:
            return []
        
        messages = self.agent_conversations[agent_id]
        
        # Filter by conversation ID if specified
        if conversation_id:
            messages = [msg for msg in messages if msg.get("conversation_id") == conversation_id]
        
        # Limit results if specified
        if limit:
            messages = messages[-limit:]
        
        return messages
    
    def get_agent_conversations(self, agent_id: str) -> List[str]:
        """
        Get list of conversation IDs for an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of conversation IDs
        """
        if agent_id not in self.agent_conversations:
            return []
        
        conversations = set()
        for message in self.agent_conversations[agent_id]:
            conv_id = message.get("conversation_id")
            if conv_id:
                conversations.add(conv_id)
        
        return list(conversations)
