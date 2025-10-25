"""
Unit tests for Policy Engine
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
        self.test_resource = "test_resource"
        self.test_action = "read"
    
    def test_create_policy_success(self):
        """Test successful policy creation"""
        rules = [
            PolicyRule(
                rule_id="rule_1",
                condition=PolicyCondition(
                    field="agent_type",
                    operator="equals",
                    value="worker"
                ),
                action=PolicyAction.ALLOW
            )
        ]
        
        policy = Policy(
            policy_id=self.test_policy_id,
            name="Test Policy",
            description="Test policy for unit testing",
            rules=rules,
            priority=1
        )
        
        result = self.policy_engine.create_policy(policy)
        
        assert result is True
        assert self.test_policy_id in self.policy_engine.policies
        assert self.policy_engine.policies[self.test_policy_id] == policy
    
    def test_create_policy_duplicate(self):
        """Test creating duplicate policy"""
        rules = [PolicyRule(
            rule_id="rule_1",
            condition=PolicyCondition(
                field="agent_type",
                operator="equals",
                value="worker"
            ),
            action=PolicyAction.ALLOW
        )]
        
        policy = Policy(
            policy_id=self.test_policy_id,
            name="Test Policy",
            description="Test policy",
            rules=rules,
            priority=1
        )
        
        # Create policy first time
        self.policy_engine.create_policy(policy)
        
        # Try to create duplicate
        result = self.policy_engine.create_policy(policy)
        
        assert result is False
    
    def test_evaluate_policy_allow(self):
        """Test policy evaluation that results in ALLOW"""
        # Create policy that allows worker agents
        rules = [
            PolicyRule(
                rule_id="rule_1",
                condition=PolicyCondition(
                    field="agent_type",
                    operator="equals",
                    value="worker"
                ),
                action=PolicyAction.ALLOW
            )
        ]
        
        policy = Policy(
            policy_id=self.test_policy_id,
            name="Allow Worker Policy",
            description="Allows worker agents",
            rules=rules,
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Evaluate with worker agent
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "worker",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        result = self.policy_engine.evaluate_policy(self.test_policy_id, context)
        
        assert result is not None
        assert result.decision == PolicyAction.ALLOW
        assert result.policy_id == self.test_policy_id
        assert len(result.matched_rules) == 1
    
    def test_evaluate_policy_deny(self):
        """Test policy evaluation that results in DENY"""
        # Create policy that denies admin agents
        rules = [
            PolicyRule(
                rule_id="rule_1",
                condition=PolicyCondition(
                    field="agent_type",
                    operator="equals",
                    value="admin"
                ),
                action=PolicyAction.DENY
            )
        ]
        
        policy = Policy(
            policy_id=self.test_policy_id,
            name="Deny Admin Policy",
            description="Denies admin agents",
            rules=rules,
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Evaluate with admin agent
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "admin",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        result = self.policy_engine.evaluate_policy(self.test_policy_id, context)
        
        assert result is not None
        assert result.decision == PolicyAction.DENY
        assert result.policy_id == self.test_policy_id
    
    def test_evaluate_policy_no_match(self):
        """Test policy evaluation with no matching rules"""
        # Create policy with specific condition
        rules = [
            PolicyRule(
                rule_id="rule_1",
                condition=PolicyCondition(
                    field="agent_type",
                    operator="equals",
                    value="worker"
                ),
                action=PolicyAction.ALLOW
            )
        ]
        
        policy = Policy(
            policy_id=self.test_policy_id,
            name="Worker Only Policy",
            description="Only for workers",
            rules=rules,
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Evaluate with different agent type
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "user",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        result = self.policy_engine.evaluate_policy(self.test_policy_id, context)
        
        assert result is not None
        assert result.decision == PolicyAction.DENY  # Default deny
        assert len(result.matched_rules) == 0
    
    def test_evaluate_policy_not_found(self):
        """Test evaluating non-existent policy"""
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "worker",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        result = self.policy_engine.evaluate_policy("non_existent_policy", context)
        
        assert result is None
    
    def test_evaluate_all_policies(self):
        """Test evaluating all policies"""
        # Create multiple policies
        policies = [
            Policy(
                policy_id="policy_1",
                name="High Priority Policy",
                description="High priority",
                rules=[PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="admin"
                    ),
                    action=PolicyAction.ALLOW
                )],
                priority=1
            ),
            Policy(
                policy_id="policy_2",
                name="Low Priority Policy",
                description="Low priority",
                rules=[PolicyRule(
                    rule_id="rule_2",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.DENY
                )],
                priority=2
            )
        ]
        
        for policy in policies:
            self.policy_engine.create_policy(policy)
        
        # Evaluate with admin agent (should match policy_1)
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "admin",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        result = self.policy_engine.evaluate_all_policies(context)
        
        assert result is not None
        assert result.decision == PolicyAction.ALLOW
        assert result.policy_id == "policy_1"  # Higher priority
    
    def test_policy_priority_ordering(self):
        """Test policy priority ordering"""
        # Create policies with different priorities
        policies = [
            Policy(
                policy_id="policy_low",
                name="Low Priority",
                description="Low priority policy",
                rules=[PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.ALLOW
                )],
                priority=10
            ),
            Policy(
                policy_id="policy_high",
                name="High Priority",
                description="High priority policy",
                rules=[PolicyRule(
                    rule_id="rule_2",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.DENY
                )],
                priority=1
            )
        ]
        
        for policy in policies:
            self.policy_engine.create_policy(policy)
        
        # Evaluate with worker agent
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "worker",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        result = self.policy_engine.evaluate_all_policies(context)
        
        assert result is not None
        assert result.decision == PolicyAction.DENY
        assert result.policy_id == "policy_high"  # Higher priority should win
    
    def test_condition_operators(self):
        """Test different condition operators"""
        operators_tests = [
            ("equals", "worker", "worker", True),
            ("equals", "worker", "admin", False),
            ("not_equals", "worker", "admin", True),
            ("not_equals", "worker", "worker", False),
            ("in", "worker", ["worker", "admin"], True),
            ("in", "user", ["worker", "admin"], False),
            ("not_in", "user", ["worker", "admin"], True),
            ("not_in", "worker", ["worker", "admin"], False),
            ("greater_than", 5, 3, True),
            ("greater_than", 3, 5, False),
            ("less_than", 3, 5, True),
            ("less_than", 5, 3, False),
            ("contains", "test_resource", "resource", True),
            ("contains", "test_resource", "admin", False)
        ]
        
        for operator, field_value, condition_value, expected in operators_tests:
            rule = PolicyRule(
                rule_id=f"rule_{operator}",
                condition=PolicyCondition(
                    field="test_field",
                    operator=operator,
                    value=condition_value
                ),
                action=PolicyAction.ALLOW
            )
            
            policy = Policy(
                policy_id=f"policy_{operator}",
                name=f"Test {operator}",
                description=f"Test {operator} operator",
                rules=[rule],
                priority=1
            )
            
            self.policy_engine.create_policy(policy)
            
            context = {"test_field": field_value}
            result = self.policy_engine.evaluate_policy(f"policy_{operator}", context)
            
            if expected:
                assert result.decision == PolicyAction.ALLOW
            else:
                assert result.decision == PolicyAction.DENY
    
    def test_time_based_conditions(self):
        """Test time-based policy conditions"""
        # Create policy with time-based condition
        rule = PolicyRule(
            rule_id="time_rule",
            condition=PolicyCondition(
                field="time",
                operator="between",
                value={"start": "09:00", "end": "17:00"}
            ),
            action=PolicyAction.ALLOW
        )
        
        policy = Policy(
            policy_id="time_policy",
            name="Business Hours Policy",
            description="Only allow during business hours",
            rules=[rule],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Test during business hours (mock time)
        with patch('time.localtime') as mock_time:
            mock_time.return_value = time.struct_time((2024, 1, 1, 10, 0, 0, 0, 0, 0))
            
            context = {"time": "10:00"}
            result = self.policy_engine.evaluate_policy("time_policy", context)
            
            assert result.decision == PolicyAction.ALLOW
    
    def test_risk_level_conditions(self):
        """Test risk level based conditions"""
        # Create policy with risk level condition
        rule = PolicyRule(
            rule_id="risk_rule",
            condition=PolicyCondition(
                field="risk_level",
                operator="less_than",
                value=0.5
            ),
            action=PolicyAction.ALLOW
        )
        
        policy = Policy(
            policy_id="risk_policy",
            name="Low Risk Policy",
            description="Only allow low risk operations",
            rules=[rule],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Test with low risk
        context = {"risk_level": 0.3}
        result = self.policy_engine.evaluate_policy("risk_policy", context)
        
        assert result.decision == PolicyAction.ALLOW
        
        # Test with high risk
        context = {"risk_level": 0.8}
        result = self.policy_engine.evaluate_policy("risk_policy", context)
        
        assert result.decision == PolicyAction.DENY
    
    def test_compliance_conditions(self):
        """Test compliance-based conditions"""
        # Create policy with compliance condition
        rule = PolicyRule(
            rule_id="compliance_rule",
            condition=PolicyCondition(
                field="compliance_standard",
                operator="in",
                value=["GDPR", "HIPAA"]
            ),
            action=PolicyAction.ALLOW
        )
        
        policy = Policy(
            policy_id="compliance_policy",
            name="Compliance Policy",
            description="Only allow compliant operations",
            rules=[rule],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Test with compliant standard
        context = {"compliance_standard": "GDPR"}
        result = self.policy_engine.evaluate_policy("compliance_policy", context)
        
        assert result.decision == PolicyAction.ALLOW
        
        # Test with non-compliant standard
        context = {"compliance_standard": "SOX"}
        result = self.policy_engine.evaluate_policy("compliance_policy", context)
        
        assert result.decision == PolicyAction.DENY
    
    def test_geolocation_conditions(self):
        """Test geolocation-based conditions"""
        # Create policy with geolocation condition
        rule = PolicyRule(
            rule_id="geo_rule",
            condition=PolicyCondition(
                field="country",
                operator="in",
                value=["US", "CA", "UK"]
            ),
            action=PolicyAction.ALLOW
        )
        
        policy = Policy(
            policy_id="geo_policy",
            name="Geolocation Policy",
            description="Only allow from specific countries",
            rules=[rule],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Test with allowed country
        context = {"country": "US"}
        result = self.policy_engine.evaluate_policy("geo_policy", context)
        
        assert result.decision == PolicyAction.ALLOW
        
        # Test with blocked country
        context = {"country": "CN"}
        result = self.policy_engine.evaluate_policy("geo_policy", context)
        
        assert result.decision == PolicyAction.DENY
    
    def test_data_classification_conditions(self):
        """Test data classification conditions"""
        # Create policy with data classification condition
        rule = PolicyRule(
            rule_id="data_rule",
            condition=PolicyCondition(
                field="data_classification",
                operator="equals",
                value="public"
            ),
            action=PolicyAction.ALLOW
        )
        
        policy = Policy(
            policy_id="data_policy",
            name="Data Classification Policy",
            description="Only allow public data access",
            rules=[rule],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Test with public data
        context = {"data_classification": "public"}
        result = self.policy_engine.evaluate_policy("data_policy", context)
        
        assert result.decision == PolicyAction.ALLOW
        
        # Test with sensitive data
        context = {"data_classification": "confidential"}
        result = self.policy_engine.evaluate_policy("data_policy", context)
        
        assert result.decision == PolicyAction.DENY
    
    def test_policy_violation_tracking(self):
        """Test policy violation tracking"""
        # Create deny policy
        rule = PolicyRule(
            rule_id="deny_rule",
            condition=PolicyCondition(
                field="agent_type",
                operator="equals",
                value="blocked"
            ),
            action=PolicyAction.DENY
        )
        
        policy = Policy(
            policy_id="deny_policy",
            name="Deny Policy",
            description="Denies blocked agents",
            rules=[rule],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Evaluate with blocked agent
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "blocked",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        result = self.policy_engine.evaluate_policy("deny_policy", context)
        
        assert result.decision == PolicyAction.DENY
        
        # Check violation was recorded
        violations = self.policy_engine.get_policy_violations(self.test_agent_id)
        assert len(violations) == 1
        assert violations[0].agent_id == self.test_agent_id
        assert violations[0].policy_id == "deny_policy"
    
    def test_policy_audit_logging(self):
        """Test policy evaluation audit logging"""
        # Create policy
        rule = PolicyRule(
            rule_id="audit_rule",
            condition=PolicyCondition(
                field="agent_type",
                operator="equals",
                value="worker"
            ),
            action=PolicyAction.ALLOW
        )
        
        policy = Policy(
            policy_id="audit_policy",
            name="Audit Policy",
            description="Policy for audit testing",
            rules=[rule],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # Evaluate policy
        context = {
            "agent_id": self.test_agent_id,
            "agent_type": "worker",
            "resource": self.test_resource,
            "action": self.test_action
        }
        
        initial_log_count = len(self.policy_engine.audit_log)
        self.policy_engine.evaluate_policy("audit_policy", context)
        
        # Check audit log was created
        assert len(self.policy_engine.audit_log) > initial_log_count
        latest_log = self.policy_engine.audit_log[-1]
        assert latest_log["action"] == "policy_evaluation"
        assert latest_log["policy_id"] == "audit_policy"
        assert latest_log["agent_id"] == self.test_agent_id
