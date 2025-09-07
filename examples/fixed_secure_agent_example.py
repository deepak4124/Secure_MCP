"""
Fixed Secure Agent Example for Multi-Agent MCP Networks

This example demonstrates:
- Agent registration and authentication
- Trust score calculation and management
- Secure communication between agents
- Basic task allocation with trust considerations
- Proper trust bootstrap for new agents
"""

import asyncio
import time
import json
from typing import Dict, List, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Import our security modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.authentication.identity_management import (
    IdentityManager, AgentType, IdentityStatus, AgentIdentity
)
from trust.trust_calculator import (
    TrustCalculator, TrustEvent, TrustEventType, TrustDimension
)


class SecureAgent:
    """
    A secure agent that can participate in the multi-agent MCP network
    """
    
    def __init__(self, agent_id: str, agent_type: AgentType, capabilities: List[str]):
        """
        Initialize a secure agent
        
        Args:
            agent_id: Unique agent identifier
            agent_type: Type of agent (worker, coordinator, etc.)
            capabilities: List of agent capabilities
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.capabilities = capabilities
        
        # Generate cryptographic keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Agent state
        self.is_registered = False
        self.trust_score = 0.5
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.last_activity = time.time()
        
        # Communication
        self.message_queue = asyncio.Queue()
        self.peers = {}  # Known peer agents
    
    async def register_with_identity_manager(self, identity_manager: IdentityManager) -> bool:
        """
        Register this agent with the identity manager
        
        Args:
            identity_manager: Identity manager instance
            
        Returns:
            True if registration successful
        """
        success, message = identity_manager.register_agent(
            agent_id=self.agent_id,
            public_key=self.public_key,
            agent_type=self.agent_type,
            capabilities=self.capabilities,
            metadata={
                "version": "1.0",
                "location": "datacenter_1",
                "created_at": str(time.time())
            }
        )
        
        if success:
            self.is_registered = True
            print(f"Agent {self.agent_id} registered successfully: {message}")
            return True
        else:
            print(f"Agent {self.agent_id} registration failed: {message}")
            return False
    
    async def activate_identity(self, identity_manager: IdentityManager) -> bool:
        """
        Activate this agent's identity
        
        Args:
            identity_manager: Identity manager instance
            
        Returns:
            True if activation successful
        """
        if not self.is_registered:
            print(f"Agent {self.agent_id} not registered")
            return False
        
        success = identity_manager.activate_identity(self.agent_id)
        if success:
            print(f"Agent {self.agent_id} identity activated")
            return True
        else:
            print(f"Agent {self.agent_id} identity activation failed")
            return False
    
    async def execute_task(self, task: Dict) -> Dict:
        """
        Execute a task and return results
        
        Args:
            task: Task description and parameters
            
        Returns:
            Task execution results
        """
        task_id = task.get("task_id", "unknown")
        task_type = task.get("type", "unknown")
        
        print(f"Agent {self.agent_id} executing task {task_id} of type {task_type}")
        
        # Simulate task execution
        await asyncio.sleep(0.1)  # Simulate processing time
        
        # Simulate success/failure based on agent capabilities
        success = task_type in self.capabilities
        
        if success:
            self.tasks_completed += 1
            result = {
                "task_id": task_id,
                "agent_id": self.agent_id,
                "status": "success",
                "result": f"Task {task_id} completed successfully",
                "timestamp": time.time()
            }
        else:
            self.tasks_failed += 1
            result = {
                "task_id": task_id,
                "agent_id": self.agent_id,
                "status": "failure",
                "error": f"Agent {self.agent_id} cannot handle task type {task_type}",
                "timestamp": time.time()
            }
        
        self.last_activity = time.time()
        return result
    
    async def report_trust_event(
        self, 
        trust_calculator: TrustCalculator, 
        event_type: TrustEventType, 
        value: float,
        context: Optional[Dict] = None
    ):
        """
        Report a trust event to the trust calculator
        
        Args:
            trust_calculator: Trust calculator instance
            event_type: Type of trust event
            value: Event value (0.0 to 1.0)
            context: Optional context information
        """
        event = TrustEvent(
            event_id=f"{self.agent_id}_{int(time.time())}",
            agent_id=self.agent_id,
            event_type=event_type,
            timestamp=time.time(),
            value=value,
            context=context or {}
        )
        
        success = trust_calculator.add_trust_event(event)
        if success:
            print(f"Agent {self.agent_id} reported trust event: {event_type.value}")
        else:
            print(f"Agent {self.agent_id} failed to report trust event")
    
    async def get_trust_score(self, trust_calculator: TrustCalculator) -> Optional[float]:
        """
        Get current trust score from trust calculator
        
        Args:
            trust_calculator: Trust calculator instance
            
        Returns:
            Current trust score or None
        """
        trust_score = trust_calculator.get_trust_score(self.agent_id)
        if trust_score:
            self.trust_score = trust_score.overall_score
            return trust_score.overall_score
        return None


class TaskAllocator:
    """
    Trust-aware task allocator for the multi-agent system
    """
    
    def __init__(self, identity_manager: IdentityManager, trust_calculator: TrustCalculator):
        """
        Initialize task allocator
        
        Args:
            identity_manager: Identity manager instance
            trust_calculator: Trust calculator instance
        """
        self.identity_manager = identity_manager
        self.trust_calculator = trust_calculator
        self.pending_tasks = []
        self.allocated_tasks = {}
    
    async def bootstrap_trust_for_agents(self, agents: List[SecureAgent]):
        """
        Bootstrap trust scores for new agents by giving them initial trust events
        
        Args:
            agents: List of agents to bootstrap
        """
        print("Bootstrapping trust scores for new agents...")
        
        for agent in agents:
            # Give each agent some initial positive trust events
            initial_events = [
                TrustEvent(
                    event_id=f"bootstrap_{agent.agent_id}_1",
                    agent_id=agent.agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - 3600,  # 1 hour ago
                    value=0.8,
                    context={"type": "bootstrap", "reason": "initial_trust"}
                ),
                TrustEvent(
                    event_id=f"bootstrap_{agent.agent_id}_2",
                    agent_id=agent.agent_id,
                    event_type=TrustEventType.COOPERATION_POSITIVE,
                    timestamp=time.time() - 1800,  # 30 minutes ago
                    value=0.7,
                    context={"type": "bootstrap", "reason": "initial_trust"}
                ),
                TrustEvent(
                    event_id=f"bootstrap_{agent.agent_id}_3",
                    agent_id=agent.agent_id,
                    event_type=TrustEventType.HONESTY_POSITIVE,
                    timestamp=time.time() - 900,  # 15 minutes ago
                    value=0.9,
                    context={"type": "bootstrap", "reason": "initial_trust"}
                )
            ]
            
            for event in initial_events:
                self.trust_calculator.add_trust_event(event)
            
            print(f"  Bootstrapped trust for {agent.agent_id}")
    
    async def allocate_task(self, task: Dict, available_agents: List[SecureAgent]) -> Optional[str]:
        """
        Allocate a task to the most suitable agent
        
        Args:
            task: Task to allocate
            available_agents: List of available agents
            
        Returns:
            Agent ID if allocation successful, None otherwise
        """
        if not available_agents:
            print("No available agents for task allocation")
            return None
        
        task_type = task.get("type", "unknown")
        task_priority = task.get("priority", "normal")
        
        # Filter agents by capability
        capable_agents = [
            agent for agent in available_agents
            if task_type in agent.capabilities and agent.is_registered
        ]
        
        if not capable_agents:
            print(f"No agents capable of handling task type: {task_type}")
            return None
        
        # Get trust scores for capable agents
        agent_scores = []
        for agent in capable_agents:
            trust_score = self.trust_calculator.get_trust_score(agent.agent_id)
            if trust_score:
                # Use trust score if available, otherwise use default
                score = trust_score.overall_score if trust_score.confidence > 0.3 else 0.5
                agent_scores.append((agent.agent_id, score))
            else:
                # Use default score for agents without trust scores
                agent_scores.append((agent.agent_id, 0.5))
        
        if not agent_scores:
            print("No agents with trust scores available")
            return None
        
        # Sort by trust score (highest first)
        agent_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Select best agent
        selected_agent_id = agent_scores[0][0]
        
        # Record allocation
        self.allocated_tasks[task.get("task_id")] = {
            "agent_id": selected_agent_id,
            "allocated_at": time.time(),
            "task": task
        }
        
        print(f"Task {task.get('task_id')} allocated to agent {selected_agent_id} (trust: {agent_scores[0][1]:.3f})")
        return selected_agent_id
    
    async def handle_task_completion(self, task_id: str, result: Dict):
        """
        Handle task completion and update trust scores
        
        Args:
            task_id: Task identifier
            result: Task execution result
        """
        if task_id not in self.allocated_tasks:
            print(f"Unknown task ID: {task_id}")
            return
        
        allocation = self.allocated_tasks[task_id]
        agent_id = allocation["agent_id"]
        
        # Update trust based on task result
        if result.get("status") == "success":
            # Report positive trust event
            event = TrustEvent(
                event_id=f"task_success_{task_id}",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time(),
                value=0.9,
                context={"task_id": task_id, "task_type": result.get("task_type", "unknown")}
            )
            self.trust_calculator.add_trust_event(event)
        else:
            # Report negative trust event
            event = TrustEvent(
                event_id=f"task_failure_{task_id}",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_FAILURE,
                timestamp=time.time(),
                value=0.1,
                context={"task_id": task_id, "error": result.get("error", "unknown")}
            )
            self.trust_calculator.add_trust_event(event)
        
        # Remove from allocated tasks
        del self.allocated_tasks[task_id]
        
        print(f"Task {task_id} completion handled for agent {agent_id}")


async def main():
    """
    Main example demonstrating secure multi-agent system
    """
    print("=== Fixed Secure Multi-Agent MCP System Example ===\n")
    
    # Initialize system components
    identity_manager = IdentityManager()
    trust_calculator = TrustCalculator(min_events=1)  # Reduced for demo
    task_allocator = TaskAllocator(identity_manager, trust_calculator)
    
    # Create agents with different capabilities
    agents = [
        SecureAgent("agent_001", AgentType.WORKER, ["data_processing", "analysis"]),
        SecureAgent("agent_002", AgentType.WORKER, ["data_processing", "visualization"]),
        SecureAgent("agent_003", AgentType.COORDINATOR, ["coordination", "monitoring"]),
        SecureAgent("agent_004", AgentType.WORKER, ["analysis", "reporting"]),
    ]
    
    print("1. Registering agents...")
    for agent in agents:
        await agent.register_with_identity_manager(identity_manager)
        await agent.activate_identity(identity_manager)
    
    print(f"\n2. Active agents: {len(identity_manager.list_active_agents())}")
    
    # Bootstrap trust scores for new agents
    await task_allocator.bootstrap_trust_for_agents(agents)
    
    print(f"\n3. Trust scores after bootstrap:")
    for agent in agents:
        trust_score = await agent.get_trust_score(trust_calculator)
        if trust_score:
            print(f"  {agent.agent_id}: {trust_score:.3f}")
    
    # Create some test tasks
    tasks = [
        {"task_id": "task_001", "type": "data_processing", "priority": "high"},
        {"task_id": "task_002", "type": "analysis", "priority": "normal"},
        {"task_id": "task_003", "type": "visualization", "priority": "low"},
        {"task_id": "task_004", "type": "data_processing", "priority": "normal"},
        {"task_id": "task_005", "type": "reporting", "priority": "high"},
    ]
    
    print(f"\n4. Allocating {len(tasks)} tasks...")
    
    # Allocate and execute tasks
    for task in tasks:
        # Allocate task
        selected_agent_id = await task_allocator.allocate_task(task, agents)
        
        if selected_agent_id:
            # Find the selected agent
            selected_agent = next(agent for agent in agents if agent.agent_id == selected_agent_id)
            
            # Execute task
            result = await selected_agent.execute_task(task)
            
            # Handle completion
            await task_allocator.handle_task_completion(task["task_id"], result)
            
            # Report trust events
            if result["status"] == "success":
                await selected_agent.report_trust_event(
                    trust_calculator, TrustEventType.TASK_SUCCESS, 0.9
                )
            else:
                await selected_agent.report_trust_event(
                    trust_calculator, TrustEventType.TASK_FAILURE, 0.1
                )
        else:
            print(f"  Failed to allocate task {task['task_id']}")
    
    print(f"\n5. Trust scores after task execution:")
    for agent in agents:
        trust_score = await agent.get_trust_score(trust_calculator)
        if trust_score:
            print(f"  {agent.agent_id}: {trust_score:.3f}")
    
    print(f"\n6. Trust ranking:")
    ranking = trust_calculator.get_trust_ranking()
    for i, (agent_id, score) in enumerate(ranking, 1):
        print(f"  {i}. {agent_id}: {score:.3f}")
    
    print(f"\n7. Sybil detection:")
    sybil_agents = trust_calculator.detect_sybil_agents()
    if sybil_agents:
        print(f"  Potential sybil agents: {sybil_agents}")
    else:
        print("  No sybil agents detected")
    
    print(f"\n8. Agent statistics:")
    for agent in agents:
        print(f"  {agent.agent_id}: {agent.tasks_completed} completed, {agent.tasks_failed} failed")
    
    print(f"\n=== Fixed Example completed successfully ===")


if __name__ == "__main__":
    asyncio.run(main())
