"""
Unit tests for Policy Engine (Working with actual implementation)
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
    
    def test_update_policy(self):
        """Test policy update"""
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
        
        # Update policy
        updated_policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Updated Test Policy",
            description="Updated test policy",
            rules=[
                {
                    "condition": "agent_type == 'admin'",
                    "action": "allow",
                    "reason": "Admin access"
                }
            ],
            priority=2
        )
        
        result = self.policy_engine.update_policy(updated_policy)
        
        assert result is True
        assert self.policy_engine.policies[self.test_policy_id].name == "Updated Test Policy"
        assert self.policy_engine.policies[self.test_policy_id].priority == 2
    
    def test_evaluate_access(self):
        """Test access evaluation"""
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
        
        # Evaluate access
        result = self.policy_engine.evaluate_access(context)
        
        assert result is not None
        assert result.decision == PolicyDecision.ALLOW
    
    def test_evaluate_access_deny(self):
        """Test access evaluation that results in deny"""
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
        
        # Evaluate access
        result = self.policy_engine.evaluate_access(context)
        
        assert result is not None
        assert result.decision == PolicyDecision.DENY
    
    def test_get_policy_summary(self):
        """Test getting policy summary"""
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
        
        # Get policy summary
        summary = self.policy_engine.get_policy_summary()
        
        assert isinstance(summary, dict)
        assert "total_policies" in summary
        assert "enabled_policies" in summary
        assert "policy_list" in summary
        assert summary["total_policies"] >= 2
    
    def test_export_policies(self):
        """Test policy export"""
        # Add a policy
        policy = AccessPolicy(
            policy_id=self.test_policy_id,
            name="Export Test Policy",
            description="Policy for export testing",
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
        
        # Export policies
        result = self.policy_engine.export_policies("test_policies.json")
        
        assert result is True
    
    def test_import_policies(self):
        """Test policy import"""
        # First export some policies
        policy = AccessPolicy(
            policy_id="import_test_policy",
            name="Import Test Policy",
            description="Policy for import testing",
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
        self.policy_engine.export_policies("test_import.json")
        
        # Create new policy engine and import
        new_engine = PolicyEngine()
        result = new_engine.import_policies("test_import.json")
        
        assert result is True
        assert "import_test_policy" in new_engine.policies
    
    def test_business_hours_check(self):
        """Test business hours check"""
        # Test the business hours helper method
        is_business_hours = self.policy_engine._is_business_hours()
        
        # This will depend on current time, so just check it returns a boolean
        assert isinstance(is_business_hours, bool)
    
    def test_weekend_check(self):
        """Test weekend check"""
        # Test the weekend helper method
        is_weekend = self.policy_engine._is_weekend()
        
        # This will depend on current time, so just check it returns a boolean
        assert isinstance(is_weekend, bool)
    
    def test_risk_level_calculation(self):
        """Test risk level calculation"""
        # Test different risk values
        low_risk = self.policy_engine._get_risk_level(0.2)
        medium_risk = self.policy_engine._get_risk_level(0.5)
        high_risk = self.policy_engine._get_risk_level(0.8)
        
        assert low_risk == "low"
        assert medium_risk == "medium"
        assert high_risk == "high"
    
    def test_composite_score_calculation(self):
        """Test composite score calculation"""
        scores = [0.8, 0.6, 0.9]
        weights = [0.5, 0.3, 0.2]
        
        composite_score = self.policy_engine._calculate_composite_score(scores, weights)
        
        assert isinstance(composite_score, float)
        assert 0.0 <= composite_score <= 1.0
    
    def test_geolocation_check(self):
        """Test geolocation check"""
        allowed_countries = ["US", "CA", "UK"]
        
        # Test with allowed country
        result = self.policy_engine._check_geolocation(allowed_countries, "US")
        assert result is True
        
        # Test with disallowed country
        result = self.policy_engine._check_geolocation(allowed_countries, "CN")
        assert result is False
    
    def test_data_classification_validation(self):
        """Test data classification validation"""
        # Test valid classification
        result = self.policy_engine._validate_data_classification("public", "public")
        assert result is True
        
        # Test invalid classification
        result = self.policy_engine._validate_data_classification("confidential", "public")
        assert result is False

