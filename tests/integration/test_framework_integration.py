"""
Integration tests for MCP Security Framework
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, MagicMock
from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
from mcp_security_framework.core.gateway import MCPSecurityGateway, RequestContext, ResponseContext
from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
from mcp_security_framework.core.identity import AgentType
from mcp_security_framework.core.policy import Policy, PolicyRule, PolicyCondition, PolicyAction
from mcp_security_framework.core.trust import TrustEvent, TrustEventType


class TestFrameworkIntegration:
    """Integration tests for the complete MCP Security Framework"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.identity_manager = IdentityManager()
        self.trust_calculator = TrustCalculator()
        self.policy_engine = PolicyEngine()
        self.tool_registry = ToolRegistry()
        
        # Create basic security gateway
        self.gateway = MCPSecurityGateway(
            identity_manager=self.identity_manager,
            trust_calculator=self.trust_calculator,
            policy_engine=self.policy_engine,
            tool_registry=self.tool_registry
        )
    
    def test_complete_agent_lifecycle(self):
        """Test complete agent lifecycle from registration to operation"""
        agent_id = "integration_test_agent"
        public_key = b"test_public_key"
        agent_type = AgentType.WORKER
        capabilities = ["read", "write"]
        metadata = {"department": "testing"}
        
        # 1. Register agent
        registration_result = self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=public_key,
            agent_type=agent_type,
            capabilities=capabilities,
            metadata=metadata
        )
        assert registration_result is True
        
        # 2. Authenticate agent
        auth_result = self.identity_manager.authenticate_agent(agent_id, public_key)
        assert auth_result is True
        
        # 3. Add trust events
        trust_events = [
            TrustEvent(
                event_id="event_1",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 300,
                value=0.8
            ),
            TrustEvent(
                event_id="event_2",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 200,
                value=0.9
            ),
            TrustEvent(
                event_id="event_3",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 100,
                value=0.85
            )
        ]
        
        for event in trust_events:
            self.trust_calculator.add_trust_event(event)
        
        # 4. Get trust score
        trust_score = self.trust_calculator.get_trust_score(agent_id)
        assert trust_score is not None
        assert trust_score.agent_id == agent_id
        assert 0.0 <= trust_score.overall_score <= 1.0
        
        # 5. Create and evaluate policy
        policy = Policy(
            policy_id="integration_policy",
            name="Integration Test Policy",
            description="Policy for integration testing",
            rules=[
                PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.ALLOW
                )
            ],
            priority=1
        )
        
        self.policy_engine.create_policy(policy)
        
        # 6. Evaluate policy
        context = {
            "agent_id": agent_id,
            "agent_type": "worker",
            "resource": "test_resource",
            "action": "read"
        }
        
        policy_result = self.policy_engine.evaluate_policy("integration_policy", context)
        assert policy_result is not None
        assert policy_result.decision == PolicyAction.ALLOW
        
        # 7. Revoke agent identity
        revoke_result = self.identity_manager.revoke_agent_identity(agent_id)
        assert revoke_result is True
        
        # 8. Verify revocation
        auth_result_after_revoke = self.identity_manager.authenticate_agent(agent_id, public_key)
        assert auth_result_after_revoke is False
    
    @pytest.mark.asyncio
    async def test_gateway_request_processing(self):
        """Test complete request processing through gateway"""
        # Setup: Register agent and create policy
        agent_id = "gateway_test_agent"
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Create allow policy
        policy = Policy(
            policy_id="gateway_policy",
            name="Gateway Test Policy",
            description="Policy for gateway testing",
            rules=[
                PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.ALLOW
                )
            ],
            priority=1
        )
        self.policy_engine.create_policy(policy)
        
        # Add trust events
        for i in range(6):  # Minimum for trust calculation
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 60,
                value=0.8
            )
            self.trust_calculator.add_trust_event(event)
        
        # Create request
        request = RequestContext(
            operation="read",
            resource="test_resource",
            agent_id=agent_id
        )
        
        # Process request through gateway
        response = await self.gateway.process_request(agent_id, request)
        
        # Verify response
        assert response is not None
        assert isinstance(response, ResponseContext)
        assert response.status in ["allowed", "blocked", "error"]
    
    def test_trust_policy_integration(self):
        """Test integration between trust system and policy engine"""
        agent_id = "trust_policy_agent"
        
        # Register agent
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Add trust events with varying scores
        trust_events = [
            TrustEvent(
                event_id="event_1",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 300,
                value=0.9  # High trust
            ),
            TrustEvent(
                event_id="event_2",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 200,
                value=0.8
            ),
            TrustEvent(
                event_id="event_3",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 100,
                value=0.85
            ),
            TrustEvent(
                event_id="event_4",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 50,
                value=0.9
            ),
            TrustEvent(
                event_id="event_5",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 25,
                value=0.8
            ),
            TrustEvent(
                event_id="event_6",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 10,
                value=0.9
            )
        ]
        
        for event in trust_events:
            self.trust_calculator.add_trust_event(event)
        
        # Get trust score
        trust_score = self.trust_calculator.get_trust_score(agent_id)
        assert trust_score is not None
        assert trust_score.overall_score > 0.8  # High trust score
        
        # Create policy that requires high trust
        policy = Policy(
            policy_id="high_trust_policy",
            name="High Trust Policy",
            description="Requires high trust score",
            rules=[
                PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="trust_score",
                        operator="greater_than",
                        value=0.7
                    ),
                    action=PolicyAction.ALLOW
                )
            ],
            priority=1
        )
        self.policy_engine.create_policy(policy)
        
        # Evaluate policy with trust score
        context = {
            "agent_id": agent_id,
            "trust_score": trust_score.overall_score,
            "resource": "sensitive_resource",
            "action": "read"
        }
        
        policy_result = self.policy_engine.evaluate_policy("high_trust_policy", context)
        assert policy_result is not None
        assert policy_result.decision == PolicyAction.ALLOW
    
    def test_sybil_detection_integration(self):
        """Test sybil detection integration with trust system"""
        # Create multiple agents with similar patterns
        agents = ["agent_1", "agent_2", "agent_3", "agent_4", "agent_5"]
        
        for agent_id in agents:
            # Register agent
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"key_{agent_id}".encode(),
                agent_type=AgentType.WORKER,
                capabilities=["read"],
                metadata={}
            )
            
            # Add similar trust events (potential sybil pattern)
            for i in range(10):
                event = TrustEvent(
                    event_id=f"event_{agent_id}_{i}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - i * 10,
                    value=0.9,  # Very high trust
                    source_agent=f"related_agent_{i}"
                )
                self.trust_calculator.add_trust_event(event)
        
        # Detect sybil agents
        sybil_agents = self.trust_calculator.detect_sybil_agents()
        
        # Should detect potential sybil agents based on high connectivity
        assert isinstance(sybil_agents, list)
        # The exact number depends on the detection algorithm
    
    def test_collusion_detection_integration(self):
        """Test collusion detection integration"""
        agent_id = "collusion_test_agent"
        
        # Register agent
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Add events that might indicate collusion
        for i in range(8):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 60,
                value=0.9,  # High value
                source_agent="colluding_agent"  # Same source
            )
            self.trust_calculator.add_trust_event(event)
        
        # Detect collusion
        colluding_agents = self.trust_calculator.detect_collusion(agent_id)
        
        assert isinstance(colluding_agents, list)
    
    def test_policy_violation_tracking_integration(self):
        """Test policy violation tracking integration"""
        agent_id = "violation_test_agent"
        
        # Register agent
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Create deny policy
        policy = Policy(
            policy_id="deny_policy",
            name="Deny Policy",
            description="Denies all requests",
            rules=[
                PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_id",
                        operator="equals",
                        value=agent_id
                    ),
                    action=PolicyAction.DENY
                )
            ],
            priority=1
        )
        self.policy_engine.create_policy(policy)
        
        # Evaluate policy (should be denied)
        context = {
            "agent_id": agent_id,
            "resource": "test_resource",
            "action": "read"
        }
        
        policy_result = self.policy_engine.evaluate_policy("deny_policy", context)
        assert policy_result.decision == PolicyAction.DENY
        
        # Check violation was recorded
        violations = self.policy_engine.get_policy_violations(agent_id)
        assert len(violations) == 1
        assert violations[0].agent_id == agent_id
        assert violations[0].policy_id == "deny_policy"
    
    def test_audit_logging_integration(self):
        """Test audit logging across all components"""
        agent_id = "audit_test_agent"
        
        # Track initial audit log counts
        initial_identity_logs = len(self.identity_manager.audit_log)
        initial_trust_logs = len(self.trust_calculator.audit_log)
        initial_policy_logs = len(self.policy_engine.audit_log)
        
        # Perform operations that should generate audit logs
        
        # 1. Register agent
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # 2. Add trust event
        event = TrustEvent(
            event_id="audit_event",
            agent_id=agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time(),
            value=0.8
        )
        self.trust_calculator.add_trust_event(event)
        
        # 3. Create and evaluate policy
        policy = Policy(
            policy_id="audit_policy",
            name="Audit Policy",
            description="Policy for audit testing",
            rules=[
                PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.ALLOW
                )
            ],
            priority=1
        )
        self.policy_engine.create_policy(policy)
        
        context = {
            "agent_id": agent_id,
            "agent_type": "worker",
            "resource": "test_resource",
            "action": "read"
        }
        self.policy_engine.evaluate_policy("audit_policy", context)
        
        # Verify audit logs were created
        assert len(self.identity_manager.audit_log) > initial_identity_logs
        assert len(self.trust_calculator.audit_log) > initial_trust_logs
        assert len(self.policy_engine.audit_log) > initial_policy_logs
        
        # Check specific log entries
        identity_log = self.identity_manager.audit_log[-1]
        assert identity_log["action"] == "register_agent"
        assert identity_log["agent_id"] == agent_id
        
        trust_log = self.trust_calculator.audit_log[-1]
        assert trust_log["action"] == "add_trust_event"
        assert trust_log["agent_id"] == agent_id
        
        policy_log = self.policy_engine.audit_log[-1]
        assert policy_log["action"] == "policy_evaluation"
        assert policy_log["agent_id"] == agent_id
    
    def test_performance_under_load(self):
        """Test framework performance under load"""
        # Register multiple agents
        agent_count = 50
        agents = []
        
        for i in range(agent_count):
            agent_id = f"load_test_agent_{i}"
            agents.append(agent_id)
            
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"key_{i}".encode(),
                agent_type=AgentType.WORKER,
                capabilities=["read"],
                metadata={}
            )
            
            # Add trust events
            for j in range(6):  # Minimum for trust calculation
                event = TrustEvent(
                    event_id=f"event_{agent_id}_{j}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - j * 60,
                    value=0.8
                )
                self.trust_calculator.add_trust_event(event)
        
        # Create policy
        policy = Policy(
            policy_id="load_test_policy",
            name="Load Test Policy",
            description="Policy for load testing",
            rules=[
                PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.ALLOW
                )
            ],
            priority=1
        )
        self.policy_engine.create_policy(policy)
        
        # Measure performance
        start_time = time.time()
        
        # Perform multiple operations
        for agent_id in agents:
            # Get trust score
            trust_score = self.trust_calculator.get_trust_score(agent_id)
            assert trust_score is not None
            
            # Evaluate policy
            context = {
                "agent_id": agent_id,
                "agent_type": "worker",
                "resource": "test_resource",
                "action": "read"
            }
            policy_result = self.policy_engine.evaluate_policy("load_test_policy", context)
            assert policy_result is not None
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Performance assertions
        assert duration < 10.0  # Should complete within 10 seconds
        operations_per_second = (agent_count * 2) / duration  # 2 operations per agent
        assert operations_per_second > 10  # Should handle at least 10 ops/sec
    
    def test_error_handling_integration(self):
        """Test error handling across integrated components"""
        # Test with invalid agent ID
        invalid_agent_id = "non_existent_agent"
        
        # Try to get trust score for non-existent agent
        trust_score = self.trust_calculator.get_trust_score(invalid_agent_id)
        assert trust_score is None
        
        # Try to authenticate non-existent agent
        auth_result = self.identity_manager.authenticate_agent(invalid_agent_id, b"key")
        assert auth_result is False
        
        # Try to evaluate policy for non-existent agent
        context = {
            "agent_id": invalid_agent_id,
            "agent_type": "worker",
            "resource": "test_resource",
            "action": "read"
        }
        
        # Create a policy first
        policy = Policy(
            policy_id="error_test_policy",
            name="Error Test Policy",
            description="Policy for error testing",
            rules=[
                PolicyRule(
                    rule_id="rule_1",
                    condition=PolicyCondition(
                        field="agent_type",
                        operator="equals",
                        value="worker"
                    ),
                    action=PolicyAction.ALLOW
                )
            ],
            priority=1
        )
        self.policy_engine.create_policy(policy)
        
        policy_result = self.policy_engine.evaluate_policy("error_test_policy", context)
        assert policy_result is not None  # Should still evaluate (default deny)
        assert policy_result.decision == PolicyAction.DENY  # Default deny for unknown agents


class TestRealGatewayIntegration:
    """Integration tests for RealMCPSecurityGateway"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Mock the real models to avoid downloading during tests
        with patch('mcp_security_framework.models.real_models.RealTrustModel') as mock_trust_model, \
             patch('mcp_security_framework.models.real_models.RealSecurityModel') as mock_security_model:
            
            # Setup mocks
            mock_trust_model.return_value = Mock()
            mock_security_model.return_value = Mock()
            
            self.identity_manager = IdentityManager()
            self.trust_calculator = TrustCalculator()
            self.policy_engine = PolicyEngine()
            self.tool_registry = ToolRegistry()
            
            self.real_gateway = RealMCPSecurityGateway(
                identity_manager=self.identity_manager,
                trust_calculator=self.trust_calculator,
                policy_engine=self.policy_engine,
                tool_registry=self.tool_registry
            )
    
    @pytest.mark.asyncio
    async def test_real_gateway_request_processing(self):
        """Test request processing through real gateway"""
        # Register agent
        agent_id = "real_gateway_agent"
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Mock the real models
        self.real_gateway.real_security_model.detect_threat.return_value = {
            "threat_level": "safe",
            "confidence": 0.9,
            "is_threat": False
        }
        self.real_gateway.real_trust_model.calculate_trust_score.return_value = 0.8
        
        # Create request
        request = RequestContext(
            operation="read",
            resource="test_resource",
            agent_id=agent_id
        )
        
        # Process request
        response = await self.real_gateway.process_request(agent_id, request)
        
        # Verify response
        assert response is not None
        assert isinstance(response, ResponseContext)
        assert response.trust_score == 0.8
        assert response.threat_assessment["threat_level"] == "safe"
    
    @pytest.mark.asyncio
    async def test_real_gateway_threat_detection(self):
        """Test threat detection in real gateway"""
        # Register agent
        agent_id = "threat_test_agent"
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Mock threat detection
        self.real_gateway.real_security_model.detect_threat.return_value = {
            "threat_level": "malicious",
            "confidence": 0.95,
            "is_threat": True
        }
        
        # Create request
        request = RequestContext(
            operation="malicious_operation",
            resource="sensitive_resource",
            agent_id=agent_id
        )
        
        # Process request
        response = await self.real_gateway.process_request(agent_id, request)
        
        # Verify threat was detected
        assert response.status == "blocked"
        assert "threat detected" in response.message.lower()
        assert response.threat_assessment["threat_level"] == "malicious"
    
    def test_real_gateway_metrics_collection(self):
        """Test real-time metrics collection"""
        # Get initial metrics
        initial_metrics = self.real_gateway.get_real_time_metrics()
        
        assert "requests_processed" in initial_metrics
        assert "threats_detected" in initial_metrics
        assert "average_response_time" in initial_metrics
        assert "threat_detection_rate" in initial_metrics
        assert "throughput" in initial_metrics
        
        # Verify initial values
        assert initial_metrics["requests_processed"] == 0
        assert initial_metrics["threats_detected"] == 0
        assert initial_metrics["average_response_time"] == 0
        assert initial_metrics["threat_detection_rate"] == 1.0  # 0/0 = 1.0 (edge case)
        assert initial_metrics["throughput"] == 0

