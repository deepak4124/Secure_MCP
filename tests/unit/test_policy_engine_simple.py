"""
Unit tests for Policy Engine (Simplified)
"""

import pytest
import time
from unittest.mock import Mock, patch
from mcp_security_framework.core.policy import (
    PolicyEngine, AccessPolicy, PolicyDecision, PolicyContext
)


class TestPolicyEngine:
    """Test cases for PolicyEngine"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.policy_engine = PolicyEngine()
        self.test_policy_id = "test_policy_001"
        self.test_agent_id = "test_agent_001"
    
    def test_policy_engine_initialization(self):
        """Test policy engine initialization"""
        assert self.policy_engine is not None
        assert hasattr(self.policy_engine, 'policies')
        assert hasattr(self.policy_engine, 'default_policies')
        assert hasattr(self.policy_engine, 'config')
    
    def test_add_policy_success(self):
        """Test successful policy addition"""
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Test Policy",
            description="Test policy for unit testing",
            rules=[
                {
                    "condition": "agent_type == 'worker'",
                    "action": "allow",
                    "reason": "Worker agent access"
                }
            ],
            priority=1
        )
        
        result = self.policy_engine.add_policy(policy)
        
        assert result is True
        assert self.test_policy_id in self.policy_engine.policies
        assert self.policy_engine.policies[self.test_policy_id] == policy
    
    def test_add_policy_duplicate(self):
        """Test adding duplicate policy"""
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Test Policy",
            description="Test policy",
            rules=[
                {
                    "condition": "agent_type == 'worker'",
                    "action": "allow",
                    "reason": "Worker access"
                }
            ],
            priority=1
        )
        
        # Add policy first time
        self.policy_engine.add_policy(policy)
        
        # Try to add duplicate
        result = self.policy_engine.add_policy(policy)
        
        assert result is False
    
    def test_remove_policy(self):
        """Test policy removal"""
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Test Policy",
            description="Test policy",
            rules=[
                {
                    "condition": "agent_type == 'worker'",
                    "action": "allow",
                    "reason": "Worker access"
                }
            ],
            priority=1
        )
        
        # Add policy
        self.policy_engine.add_policy(policy)
        assert self.test_policy_id in self.policy_engine.policies
        
        # Remove policy
        result = self.policy_engine.remove_policy(self.test_policy_id)
        
        assert result is True
        assert self.test_policy_id not in self.policy_engine.policies
    
    def test_remove_policy_not_found(self):
        """Test removing non-existent policy"""
        result = self.policy_engine.remove_policy("non_existent_policy")
        
        assert result is False
    
    def test_get_policy(self):
        """Test getting policy"""
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Test Policy",
            description="Test policy",
            rules=[
                {
                    "condition": "agent_type == 'worker'",
                    "action": "allow",
                    "reason": "Worker access"
                }
            ],
            priority=1
        )
        
        # Add policy
        self.policy_engine.add_policy(policy)
        
        # Get policy
        retrieved_policy = self.policy_engine.get_policy(self.test_policy_id)
        
        assert retrieved_policy is not None
        assert retrieved_policy.policy_id == self.test_policy_id
        assert retrieved_policy.name == "Test Policy"
    
    def test_get_policy_not_found(self):
        """Test getting non-existent policy"""
        policy = self.policy_engine.get_policy("non_existent_policy")
        
        assert policy is None
    
    def test_list_policies(self):
        """Test listing all policies"""
        # Add multiple policies
        policies = [
            AccessPolicy(
                policy_id="policy_1",
                name="Policy 1",
                description="First policy",
                rules=[{"condition": "true", "action": "allow", "reason": "test"}],
                priority=1
            ),
            AccessPolicy(
                policy_id="policy_2",
                name="Policy 2",
                description="Second policy",
                rules=[{"condition": "true", "action": "deny", "reason": "test"}],
                priority=2
            )
        ]
        
        for policy in policies:
            self.policy_engine.add_policy(policy)
        
        # List policies
        policy_list = self.policy_engine.list_policies()
        
        assert len(policy_list) >= 2  # At least our added policies
        policy_ids = [p.policy_id for p in policy_list]
        assert "policy_1" in policy_ids
        assert "policy_2" in policy_ids
    
    def test_evaluate_policy_context(self):
        """Test policy evaluation with context"""
        # Create policy
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Worker Policy",
            description="Allows worker agents",
            rules=[
                {
                    "condition": "agent_type == 'worker'",
                    "action": "allow",
                    "reason": "Worker agent access"
                }
            ],
            priority=1
        )
        
        self.policy_engine.add_policy(policy)
        
        # Create context
        context = PolicyContext(
            agent_id=self.test_agent_id,
            agent_type="worker",
            agent_capabilities=["read", "write"],
            agent_trust_score=0.8,
            tool_id="test_tool",
            tool_risk_level="low",
            operation="read",
            parameters={},
            context_metadata={}
        )
        
        # Evaluate policy
        result = self.policy_engine.evaluate_policy(self.test_policy_id, context)
        
        assert result is not None
        assert result.decision == PolicyDecision.ALLOW
    
    def test_evaluate_policy_context_deny(self):
        """Test policy evaluation that results in deny"""
        # Create policy
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Admin Policy",
            description="Denies non-admin agents",
            rules=[
                {
                    "condition": "agent_type != 'admin'",
                    "action": "deny",
                    "reason": "Admin access required"
                }
            ],
            priority=1
        )
        
        self.policy_engine.add_policy(policy)
        
        # Create context with non-admin agent
        context = PolicyContext(
            agent_id=self.test_agent_id,
            agent_type="worker",
            agent_capabilities=["read"],
            agent_trust_score=0.8,
            tool_id="test_tool",
            tool_risk_level="low",
            operation="read",
            parameters={},
            context_metadata={}
        )
        
        # Evaluate policy
        result = self.policy_engine.evaluate_policy(self.test_policy_id, context)
        
        assert result is not None
        assert result.decision == PolicyDecision.DENY
    
    def test_evaluate_policy_not_found(self):
        """Test evaluating non-existent policy"""
        context = PolicyContext(
            agent_id=self.test_agent_id,
            agent_type="worker",
            agent_capabilities=["read"],
            agent_trust_score=0.8,
            tool_id="test_tool",
            tool_risk_level="low",
            operation="read",
            parameters={},
            context_metadata={}
        )
        
        result = self.policy_engine.evaluate_policy("non_existent_policy", context)
        
        assert result is None
    
    def test_evaluate_all_policies(self):
        """Test evaluating all policies"""
        # Create multiple policies
        policies = [
            AccessPolicy(
                policy_id="policy_1",
                name="High Priority Policy",
                description="High priority",
                rules=[
                    {
                        "condition": "agent_type == 'admin'",
                        "action": "allow",
                        "reason": "Admin access"
                    }
                ],
                priority=1
            ),
            AccessPolicy(
                policy_id="policy_2",
                name="Low Priority Policy",
                description="Low priority",
                rules=[
                    {
                        "condition": "agent_type == 'worker'",
                        "action": "deny",
                        "reason": "Worker denied"
                    }
                ],
                priority=2
            )
        ]
        
        for policy in policies:
            self.policy_engine.add_policy(policy)
        
        # Evaluate with admin agent
        context = PolicyContext(
            agent_id=self.test_agent_id,
            agent_type="admin",
            agent_capabilities=["admin"],
            agent_trust_score=0.9,
            tool_id="test_tool",
            tool_risk_level="low",
            operation="read",
            parameters={},
            context_metadata={}
        )
        
        result = self.policy_engine.evaluate_all_policies(context)
        
        assert result is not None
        assert result.decision == PolicyDecision.ALLOW
        assert result.policy_id == "policy_1"  # Higher priority
    
    def test_policy_priority_ordering(self):
        """Test policy priority ordering"""
        # Create policies with different priorities
        policies = [
            AccessPolicy(
                policy_id="policy_low",
                name="Low Priority",
                description="Low priority policy",
                rules=[
                    {
                        "condition": "agent_type == 'worker'",
                        "action": "allow",
                        "reason": "Worker allowed"
                    }
                ],
                priority=10
            ),
            AccessPolicy(
                policy_id="policy_high",
                name="High Priority",
                description="High priority policy",
                rules=[
                    {
                        "condition": "agent_type == 'worker'",
                        "action": "deny",
                        "reason": "Worker denied"
                    }
                ],
                priority=1
            )
        ]
        
        for policy in policies:
            self.policy_engine.add_policy(policy)
        
        # Evaluate with worker agent
        context = PolicyContext(
            agent_id=self.test_agent_id,
            agent_type="worker",
            agent_capabilities=["read"],
            agent_trust_score=0.8,
            tool_id="test_tool",
            tool_risk_level="low",
            operation="read",
            parameters={},
            context_metadata={}
        )
        
        result = self.policy_engine.evaluate_all_policies(context)
        
        assert result is not None
        assert result.decision == PolicyDecision.DENY
        assert result.policy_id == "policy_high"  # Higher priority should win
    
    def test_audit_logging(self):
        """Test audit logging for policy operations"""
        # Track initial audit log count
        initial_log_count = len(self.policy_engine.audit_log)
        
        # Add policy
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Audit Policy",
            description="Policy for audit testing",
            rules=[
                {
                    "condition": "agent_type == 'worker'",
                    "action": "allow",
                    "reason": "Worker access"
                }
            ],
            priority=1
        )
        
        self.policy_engine.add_policy(policy)
        
        # Check audit log was created
        assert len(self.policy_engine.audit_log) > initial_log_count
        latest_log = self.policy_engine.audit_log[-1]
        assert latest_log["action"] == "add_policy"
        assert latest_log["policy_id"] == self.test_policy_id

