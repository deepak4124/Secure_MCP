"""
Policy Engine for MCP Security Framework

This module provides access control and policy enforcement for MCP operations.
"""

import time
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
import json
import yaml


class PolicyDecision(Enum):
    """Policy decision enumeration"""
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


class AccessPolicy:
    """Access policy data structure"""
    
    def __init__(
        self,
        policy_id: str,
        name: str,
        description: str,
        rules: List[Dict[str, Any]],
        priority: int = 0,
        enabled: bool = True
    ):
        self.policy_id = policy_id
        self.name = name
        self.description = description
        self.rules = rules
        self.priority = priority
        self.enabled = enabled
        self.created_at = time.time()
        self.last_modified = time.time()


@dataclass
class PolicyContext:
    """Context for policy evaluation"""
    agent_id: str
    agent_type: str
    agent_capabilities: List[str]
    agent_trust_score: float
    tool_id: str
    tool_risk_level: str
    operation: str
    parameters: Dict[str, Any]
    context_metadata: Dict[str, Any]


class PolicyEngine:
    """
    Policy engine for access control and authorization
    
    Features:
    - Role-based access control (RBAC)
    - Capability-based access control (CBAC)
    - Attribute-based access control (ABAC)
    - Trust-aware policy enforcement
    - Dynamic policy evaluation
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize policy engine
        
        Args:
            config_path: Path to policy configuration file
        """
        self.policies: Dict[str, AccessPolicy] = {}
        self.default_policies = self._load_default_policies()
        self.config = self._load_config(config_path) if config_path else {}
        
        # Initialize with default policies
        for policy in self.default_policies:
            self.add_policy(policy)
    
    def _load_default_policies(self) -> List[AccessPolicy]:
        """Load default security policies"""
        return [
            AccessPolicy(
                policy_id="trust_threshold",
                name="Trust Threshold Policy",
                description="Require minimum trust score for tool access",
                rules=[
                    {
                        "condition": "agent_trust_score < 0.3",
                        "action": "deny",
                        "reason": "Insufficient trust score"
                    }
                ],
                priority=100
            ),
            AccessPolicy(
                policy_id="high_risk_tools",
                name="High Risk Tool Policy",
                description="Restrict access to high-risk tools",
                rules=[
                    {
                        "condition": "tool_risk_level == 'critical'",
                        "action": "deny",
                        "reason": "Critical risk tool access denied"
                    },
                    {
                        "condition": "tool_risk_level == 'high' and agent_trust_score < 0.7",
                        "action": "deny",
                        "reason": "High risk tool requires high trust"
                    }
                ],
                priority=90
            ),
            AccessPolicy(
                policy_id="capability_matching",
                name="Capability Matching Policy",
                description="Ensure agent has required capabilities",
                rules=[
                    {
                        "condition": "not agent_has_capability('tool_execution')",
                        "action": "deny",
                        "reason": "Agent lacks tool execution capability"
                    }
                ],
                priority=80
            ),
            AccessPolicy(
                policy_id="rate_limiting",
                name="Rate Limiting Policy",
                description="Limit tool execution frequency",
                rules=[
                    {
                        "condition": "execution_count > 100 and time_window < 3600",
                        "action": "deny",
                        "reason": "Rate limit exceeded"
                    }
                ],
                priority=70
            )
        ]
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load policy configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {}
    
    def add_policy(self, policy: AccessPolicy) -> bool:
        """
        Add a new policy
        
        Args:
            policy: Policy to add
            
        Returns:
            True if policy added successfully
        """
        if policy.policy_id in self.policies:
            return False
        
        self.policies[policy.policy_id] = policy
        return True
    
    def remove_policy(self, policy_id: str) -> bool:
        """
        Remove a policy
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            True if policy removed successfully
        """
        if policy_id not in self.policies:
            return False
        
        del self.policies[policy_id]
        return True
    
    def update_policy(self, policy: AccessPolicy) -> bool:
        """
        Update an existing policy
        
        Args:
            policy: Updated policy
            
        Returns:
            True if policy updated successfully
        """
        if policy.policy_id not in self.policies:
            return False
        
        policy.last_modified = time.time()
        self.policies[policy.policy_id] = policy
        return True
    
    def evaluate_access(
        self, 
        context: PolicyContext,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        """
        Evaluate access request against all policies
        
        Args:
            context: Policy evaluation context
            additional_context: Additional context data
            
        Returns:
            Policy decision
        """
        # Sort policies by priority (highest first)
        sorted_policies = sorted(
            self.policies.values(),
            key=lambda p: p.priority,
            reverse=True
        )
        
        # Evaluate each policy
        for policy in sorted_policies:
            if not policy.enabled:
                continue
            
            decision = self._evaluate_policy(policy, context, additional_context)
            
            # If policy makes a definitive decision, return it
            if decision != PolicyDecision.INDETERMINATE:
                return decision
        
        # Default to allow if no policy makes a decision
        return PolicyDecision.ALLOW
    
    def evaluate_policy(self, context: PolicyContext) -> PolicyDecision:
        """
        Evaluate policy for a given context (alias for evaluate_access)
        
        Args:
            context: Policy evaluation context
            
        Returns:
            Policy decision
        """
        return self.evaluate_access(context)
    
    def _evaluate_policy(
        self, 
        policy: AccessPolicy, 
        context: PolicyContext,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        """Evaluate a single policy"""
        for rule in policy.rules:
            condition = rule.get("condition", "")
            action = rule.get("action", "allow")
            
            # Evaluate condition
            if self._evaluate_condition(condition, context, additional_context):
                if action == "deny":
                    return PolicyDecision.DENY
                elif action == "allow":
                    return PolicyDecision.ALLOW
        
        return PolicyDecision.INDETERMINATE
    
    def _evaluate_condition(
        self, 
        condition: str, 
        context: PolicyContext,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Evaluate a policy condition with advanced features"""
        try:
            # Create evaluation context
            eval_context = {
                "agent_id": context.agent_id,
                "agent_type": context.agent_type,
                "agent_capabilities": context.agent_capabilities,
                "agent_trust_score": context.agent_trust_score,
                "tool_id": context.tool_id,
                "tool_risk_level": context.tool_risk_level,
                "operation": context.operation,
                "parameters": context.parameters,
                "context_metadata": context.context_metadata
            }
            
            # Add additional context
            if additional_context:
                eval_context.update(additional_context)
            
            # Add helper functions
            eval_context["agent_has_capability"] = lambda cap: cap in context.agent_capabilities
            eval_context["tool_has_parameter"] = lambda param: param in context.parameters
            eval_context["is_business_hours"] = self._is_business_hours
            eval_context["is_weekend"] = self._is_weekend
            eval_context["get_risk_level"] = self._get_risk_level
            eval_context["calculate_composite_score"] = self._calculate_composite_score
            eval_context["check_geolocation"] = self._check_geolocation
            eval_context["validate_data_classification"] = self._validate_data_classification
            eval_context["check_compliance_requirements"] = self._check_compliance_requirements
            
            # Add time-based functions
            eval_context["current_hour"] = time.localtime().tm_hour
            eval_context["current_day"] = time.localtime().tm_wday
            eval_context["current_time"] = time.time()
            
            # Add mathematical functions
            eval_context["min"] = min
            eval_context["max"] = max
            eval_context["abs"] = abs
            eval_context["round"] = round
            
            # Evaluate condition with enhanced context
            return eval(condition, {"__builtins__": {}}, eval_context)
            
        except Exception as e:
            print(f"Error evaluating condition '{condition}': {e}")
            return False
    
    def _is_business_hours(self) -> bool:
        """Check if current time is within business hours"""
        current_time = time.localtime()
        hour = current_time.tm_hour
        day = current_time.tm_wday
        
        # Business hours: Monday-Friday, 9 AM - 5 PM
        return 0 <= day <= 4 and 9 <= hour <= 17
    
    def _is_weekend(self) -> bool:
        """Check if current time is weekend"""
        current_time = time.localtime()
        day = current_time.tm_wday
        
        # Weekend: Saturday (5) and Sunday (6)
        return day >= 5
    
    def _get_risk_level(self, value: float) -> str:
        """Convert numeric risk value to risk level"""
        if value >= 0.8:
            return "critical"
        elif value >= 0.6:
            return "high"
        elif value >= 0.4:
            return "medium"
        elif value >= 0.2:
            return "low"
        else:
            return "minimal"
    
    def _calculate_composite_score(self, scores: List[float], weights: List[float] = None) -> float:
        """Calculate weighted composite score"""
        if not scores:
            return 0.0
        
        if weights is None:
            weights = [1.0] * len(scores)
        
        if len(scores) != len(weights):
            weights = [1.0] * len(scores)
        
        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0
        
        weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
        return weighted_sum / total_weight
    
    def _check_geolocation(self, allowed_countries: List[str], user_country: str = None) -> bool:
        """Check if user's geolocation is allowed"""
        if not user_country:
            return True  # Allow if no geolocation data
        
        return user_country.upper() in [country.upper() for country in allowed_countries]
    
    def _validate_data_classification(self, data_classification: str, required_level: str) -> bool:
        """Validate data classification level"""
        classification_levels = {
            "public": 0,
            "internal": 1,
            "confidential": 2,
            "secret": 3,
            "top_secret": 4
        }
        
        data_level = classification_levels.get(data_classification.lower(), 0)
        required_level_num = classification_levels.get(required_level.lower(), 0)
        
        return data_level >= required_level_num
    
    def _check_compliance_requirements(self, compliance_type: str, context: Dict[str, Any]) -> bool:
        """Check compliance requirements"""
        if compliance_type == "gdpr":
            return self._check_gdpr_compliance(context)
        elif compliance_type == "hipaa":
            return self._check_hipaa_compliance(context)
        elif compliance_type == "sox":
            return self._check_sox_compliance(context)
        else:
            return True  # Unknown compliance type, allow by default
    
    def _check_gdpr_compliance(self, context: Dict[str, Any]) -> bool:
        """Check GDPR compliance requirements"""
        # Check for data processing consent
        has_consent = context.get("data_processing_consent", False)
        
        # Check for data minimization
        data_minimization = context.get("data_minimization", True)
        
        # Check for purpose limitation
        purpose_limitation = context.get("purpose_limitation", True)
        
        return has_consent and data_minimization and purpose_limitation
    
    def _check_hipaa_compliance(self, context: Dict[str, Any]) -> bool:
        """Check HIPAA compliance requirements"""
        # Check for PHI handling authorization
        phi_authorization = context.get("phi_authorization", False)
        
        # Check for minimum necessary standard
        minimum_necessary = context.get("minimum_necessary", True)
        
        # Check for audit logging
        audit_logging = context.get("audit_logging", True)
        
        return phi_authorization and minimum_necessary and audit_logging
    
    def _check_sox_compliance(self, context: Dict[str, Any]) -> bool:
        """Check SOX compliance requirements"""
        # Check for financial data access authorization
        financial_authorization = context.get("financial_authorization", False)
        
        # Check for segregation of duties
        segregation_of_duties = context.get("segregation_of_duties", True)
        
        # Check for change management
        change_management = context.get("change_management", True)
        
        return financial_authorization and segregation_of_duties and change_management
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get summary of all policies"""
        return {
            "total_policies": len(self.policies),
            "enabled_policies": len([p for p in self.policies.values() if p.enabled]),
            "policies": [
                {
                    "policy_id": policy.policy_id,
                    "name": policy.name,
                    "description": policy.description,
                    "priority": policy.priority,
                    "enabled": policy.enabled,
                    "rule_count": len(policy.rules)
                }
                for policy in self.policies.values()
            ]
        }
    
    def export_policies(self, file_path: str) -> bool:
        """
        Export policies to file
        
        Args:
            file_path: Path to export file
            
        Returns:
            True if export successful
        """
        try:
            policies_data = {
                "policies": [
                    {
                        "policy_id": policy.policy_id,
                        "name": policy.name,
                        "description": policy.description,
                        "rules": policy.rules,
                        "priority": policy.priority,
                        "enabled": policy.enabled
                    }
                    for policy in self.policies.values()
                ]
            }
            
            with open(file_path, 'w') as f:
                yaml.dump(policies_data, f, default_flow_style=False)
            
            return True
            
        except Exception as e:
            print(f"Error exporting policies: {e}")
            return False
    
    def import_policies(self, file_path: str) -> bool:
        """
        Import policies from file
        
        Args:
            file_path: Path to import file
            
        Returns:
            True if import successful
        """
        try:
            with open(file_path, 'r') as f:
                policies_data = yaml.safe_load(f)
            
            for policy_data in policies_data.get("policies", []):
                policy = AccessPolicy(
                    policy_id=policy_data["policy_id"],
                    name=policy_data["name"],
                    description=policy_data["description"],
                    rules=policy_data["rules"],
                    priority=policy_data.get("priority", 0),
                    enabled=policy_data.get("enabled", True)
                )
                
                self.add_policy(policy)
            
            return True
            
        except Exception as e:
            print(f"Error importing policies: {e}")
            return False
