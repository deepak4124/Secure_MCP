"""
Complete Integration Tests for MCP Security Framework with Comprehensive Metrics
"""

import pytest
import asyncio
import time
import statistics
import threading
import queue
from unittest.mock import Mock, patch, MagicMock
from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
from mcp_security_framework.core.gateway import MCPSecurityGateway, RequestContext, ResponseContext
from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
from mcp_security_framework.core.identity import AgentType
from mcp_security_framework.core.policy import AccessPolicy, PolicyDecision, PolicyContext
from mcp_security_framework.core.trust import TrustEvent, TrustEventType


class TestCompleteFrameworkIntegration:
    """Complete integration tests with comprehensive metrics collection"""
    
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
        
        # Metrics collection
        self.integration_metrics = {
            "end_to_end_performance": {},
            "component_interaction_metrics": {},
            "security_validation_metrics": {},
            "scalability_metrics": {},
            "reliability_metrics": {}
        }
    
    def teardown_method(self):
        """Report integration test metrics"""
        self._report_integration_metrics()
    
    def _report_integration_metrics(self):
        """Report comprehensive integration test metrics"""
        print(f"\n📊 Integration Test Metrics Summary:")
        for category, metrics in self.integration_metrics.items():
            if metrics:
                print(f"   {category}: {metrics}")
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_complete_agent_lifecycle_performance(self):
        """Test complete agent lifecycle with performance metrics"""
        lifecycle_metrics = {
            "registration_times": [],
            "authentication_times": [],
            "trust_calculation_times": [],
            "policy_evaluation_times": [],
            "revocation_times": [],
            "total_lifecycle_times": []
        }
        
        agent_count = 100
        
        for i in range(agent_count):
            agent_id = f"lifecycle_agent_{i}"
            public_key = f"lifecycle_key_{i}".encode()
            
            # 1. Registration
            reg_start = time.time()
            registration_result = self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=public_key,
                agent_type=AgentType.WORKER,
                capabilities=["read", "write"],
                metadata={"department": "testing", "role": "tester"}
            )
            reg_end = time.time()
            lifecycle_metrics["registration_times"].append(reg_end - reg_start)
            
            # 2. Add trust events
            for j in range(6):  # Minimum for trust calculation
                event = TrustEvent(
                    event_id=f"lifecycle_event_{agent_id}_{j}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - j * 60,
                    value=0.8
                )
                self.trust_calculator.add_trust_event(event)
            
            # 3. Trust calculation
            trust_start = time.time()
            trust_score = self.trust_calculator.get_trust_score(agent_id)
            trust_end = time.time()
            lifecycle_metrics["trust_calculation_times"].append(trust_end - trust_start)
            
            # 4. Policy evaluation
            policy_start = time.time()
            context = PolicyContext(
                agent_id=agent_id,
                agent_type="worker",
                agent_capabilities=["read", "write"],
                agent_trust_score=trust_score.overall_score if trust_score else 0.5,
                tool_id="test_tool",
                tool_risk_level="low",
                operation="read",
                parameters={},
                context_metadata={}
            )
            policy_result = self.policy_engine.evaluate_access(context)
            policy_end = time.time()
            lifecycle_metrics["policy_evaluation_times"].append(policy_end - policy_start)
            
            # 5. Revocation
            revoke_start = time.time()
            revoke_result = self.identity_manager.revoke_identity(agent_id, "Test lifecycle completion")
            revoke_end = time.time()
            lifecycle_metrics["revocation_times"].append(revoke_end - revoke_start)
            
            # Calculate total lifecycle time
            total_time = (reg_end - reg_start) + (trust_end - trust_start) + (policy_end - policy_start) + (revoke_end - revoke_start)
            lifecycle_metrics["total_lifecycle_times"].append(total_time)
        
        # Calculate performance metrics
        performance_metrics = {
            "agent_count": agent_count,
            "avg_registration_time": statistics.mean(lifecycle_metrics["registration_times"]),
            "avg_trust_calculation_time": statistics.mean(lifecycle_metrics["trust_calculation_times"]),
            "avg_policy_evaluation_time": statistics.mean(lifecycle_metrics["policy_evaluation_times"]),
            "avg_revocation_time": statistics.mean(lifecycle_metrics["revocation_times"]),
            "avg_total_lifecycle_time": statistics.mean(lifecycle_metrics["total_lifecycle_times"]),
            "max_lifecycle_time": max(lifecycle_metrics["total_lifecycle_times"]),
            "min_lifecycle_time": min(lifecycle_metrics["total_lifecycle_times"]),
            "throughput": agent_count / sum(lifecycle_metrics["total_lifecycle_times"])
        }
        
        # Store metrics
        self.integration_metrics["end_to_end_performance"]["lifecycle"] = performance_metrics
        
        # Assertions
        assert performance_metrics["avg_total_lifecycle_time"] < 0.1, f"Average lifecycle time {performance_metrics['avg_total_lifecycle_time']}s too slow"
        assert performance_metrics["throughput"] > 10, f"Lifecycle throughput {performance_metrics['throughput']} too low"
        
        print(f"✅ Complete Agent Lifecycle Performance:")
        print(f"   Agents processed: {agent_count}")
        print(f"   Avg lifecycle time: {performance_metrics['avg_total_lifecycle_time']:.4f}s")
        print(f"   Throughput: {performance_metrics['throughput']:.2f} lifecycles/sec")
        print(f"   Avg registration: {performance_metrics['avg_registration_time']:.4f}s")
        print(f"   Avg trust calculation: {performance_metrics['avg_trust_calculation_time']:.4f}s")
        print(f"   Avg policy evaluation: {performance_metrics['avg_policy_evaluation_time']:.4f}s")
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_gateway_request_processing_performance(self):
        """Test gateway request processing with comprehensive metrics"""
        # Setup: Register agents and create policies
        agent_count = 50
        
        for i in range(agent_count):
            agent_id = f"gateway_agent_{i}"
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"gateway_key_{i}".encode(),
                agent_type=AgentType.WORKER,
                capabilities=["read", "write"],
                metadata={}
            )
            
            # Add trust events
            for j in range(6):
                event = TrustEvent(
                    event_id=f"gateway_event_{agent_id}_{j}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - j * 60,
                    value=0.8
                )
                self.trust_calculator.add_trust_event(event)
        
        # Create policies
        policies = [
            AccessPolicy(
                policy_id="allow_worker",
                name="Allow Worker Policy",
                description="Allows worker agents",
                rules=[{"condition": "agent_type == 'worker'", "action": "allow", "reason": "Worker access"}],
                priority=1
            ),
            AccessPolicy(
                policy_id="deny_admin",
                name="Deny Admin Policy",
                description="Denies admin agents",
                rules=[{"condition": "agent_type == 'admin'", "action": "deny", "reason": "Admin denied"}],
                priority=2
            )
        ]
        
        for policy in policies:
            self.policy_engine.add_policy(policy)
        
        # Test request processing performance
        request_metrics = {
            "processing_times": [],
            "successful_requests": 0,
            "blocked_requests": 0,
            "error_requests": 0,
            "response_times": []
        }
        
        request_count = 200
        
        for i in range(request_count):
            agent_id = f"gateway_agent_{i % agent_count}"
            
            # Create request
            request = RequestContext(
                operation="read" if i % 2 == 0 else "write",
                resource=f"resource_{i}",
                agent_id=agent_id
            )
            
            # Process request
            start_time = time.time()
            try:
                response = await self.gateway.process_request(agent_id, request)
                end_time = time.time()
                
                processing_time = end_time - start_time
                request_metrics["processing_times"].append(processing_time)
                request_metrics["response_times"].append(processing_time)
                
                if response.status == "allowed":
                    request_metrics["successful_requests"] += 1
                elif response.status == "blocked":
                    request_metrics["blocked_requests"] += 1
                else:
                    request_metrics["error_requests"] += 1
                    
            except Exception as e:
                end_time = time.time()
                processing_time = end_time - start_time
                request_metrics["processing_times"].append(processing_time)
                request_metrics["error_requests"] += 1
        
        # Calculate performance metrics
        performance_metrics = {
            "total_requests": request_count,
            "avg_processing_time": statistics.mean(request_metrics["processing_times"]),
            "max_processing_time": max(request_metrics["processing_times"]),
            "min_processing_time": min(request_metrics["processing_times"]),
            "throughput": request_count / sum(request_metrics["processing_times"]),
            "success_rate": request_metrics["successful_requests"] / request_count,
            "block_rate": request_metrics["blocked_requests"] / request_count,
            "error_rate": request_metrics["error_requests"] / request_count
        }
        
        # Store metrics
        self.integration_metrics["end_to_end_performance"]["gateway_processing"] = performance_metrics
        
        # Assertions
        assert performance_metrics["avg_processing_time"] < 0.05, f"Average processing time {performance_metrics['avg_processing_time']}s too slow"
        assert performance_metrics["throughput"] > 20, f"Gateway throughput {performance_metrics['throughput']} too low"
        assert performance_metrics["error_rate"] < 0.05, f"Error rate {performance_metrics['error_rate']} too high"
        
        print(f"✅ Gateway Request Processing Performance:")
        print(f"   Total requests: {request_count}")
        print(f"   Avg processing time: {performance_metrics['avg_processing_time']:.4f}s")
        print(f"   Throughput: {performance_metrics['throughput']:.2f} requests/sec")
        print(f"   Success rate: {performance_metrics['success_rate']:.2%}")
        print(f"   Block rate: {performance_metrics['block_rate']:.2%}")
        print(f"   Error rate: {performance_metrics['error_rate']:.2%}")
    
    def test_component_interaction_accuracy(self):
        """Test accuracy of component interactions"""
        interaction_metrics = {
            "trust_policy_integration": {},
            "identity_trust_integration": {},
            "policy_identity_integration": {},
            "overall_integration_accuracy": 0.0
        }
        
        # Test 1: Trust-Policy Integration
        agent_id = "integration_test_agent"
        
        # Register agent
        self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=b"integration_test_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Add trust events with varying scores
        trust_scenarios = [
            (0.9, "high_trust"),
            (0.5, "medium_trust"),
            (0.2, "low_trust")
        ]
        
        trust_policy_results = {}
        
        for trust_value, scenario_name in trust_scenarios:
            # Clear previous events
            # Note: In real implementation, you'd need a method to clear events
            
            # Add events with specific trust value
            for i in range(6):
                event = TrustEvent(
                    event_id=f"integration_event_{scenario_name}_{i}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - i * 60,
                    value=trust_value
                )
                self.trust_calculator.add_trust_event(event)
            
            # Get trust score
            trust_score = self.trust_calculator.get_trust_score(agent_id)
            
            # Create policy that requires specific trust level
            policy = AccessPolicy(
                policy_id=f"trust_policy_{scenario_name}",
                name=f"Trust Policy {scenario_name}",
                description=f"Requires {scenario_name}",
                rules=[{
                    "condition": f"agent_trust_score >= {trust_value - 0.1}",
                    "action": "allow",
                    "reason": f"Trust level {scenario_name}"
                }],
                priority=1
            )
            
            self.policy_engine.add_policy(policy)
            
            # Evaluate policy
            context = PolicyContext(
                agent_id=agent_id,
                agent_type="worker",
                agent_capabilities=["read"],
                agent_trust_score=trust_score.overall_score if trust_score else 0.0,
                tool_id="test_tool",
                tool_risk_level="low",
                operation="read",
                parameters={},
                context_metadata={}
            )
            
            policy_result = self.policy_engine.evaluate_access(context)
            
            # Check if policy decision matches expected trust level
            expected_allow = trust_value >= 0.5  # High/medium trust should be allowed
            actual_allow = policy_result.decision == PolicyDecision.ALLOW
            
            trust_policy_results[scenario_name] = {
                "trust_score": trust_score.overall_score if trust_score else 0.0,
                "expected_allow": expected_allow,
                "actual_allow": actual_allow,
                "correct": expected_allow == actual_allow
            }
        
        # Calculate trust-policy integration accuracy
        trust_policy_accuracy = sum(1 for result in trust_policy_results.values() if result["correct"]) / len(trust_policy_results)
        interaction_metrics["trust_policy_integration"] = {
            "accuracy": trust_policy_accuracy,
            "results": trust_policy_results
        }
        
        # Test 2: Identity-Trust Integration
        identity_trust_results = {}
        
        for i in range(10):
            test_agent_id = f"identity_trust_agent_{i}"
            
            # Register agent
            reg_result = self.identity_manager.register_agent(
                agent_id=test_agent_id,
                public_key=f"identity_trust_key_{i}".encode(),
                agent_type=AgentType.WORKER,
                capabilities=["read"],
                metadata={}
            )
            
            # Add trust events
            for j in range(6):
                event = TrustEvent(
                    event_id=f"identity_trust_event_{test_agent_id}_{j}",
                    agent_id=test_agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - j * 60,
                    value=0.8
                )
                self.trust_calculator.add_trust_event(event)
            
            # Get trust score
            trust_score = self.trust_calculator.get_trust_score(test_agent_id)
            
            # Get identity
            identity = self.identity_manager.get_agent_identity(test_agent_id)
            
            # Check integration
            identity_trust_results[test_agent_id] = {
                "registration_success": reg_result,
                "trust_score_available": trust_score is not None,
                "identity_available": identity is not None,
                "integration_success": reg_result and trust_score is not None and identity is not None
            }
        
        identity_trust_accuracy = sum(1 for result in identity_trust_results.values() if result["integration_success"]) / len(identity_trust_results)
        interaction_metrics["identity_trust_integration"] = {
            "accuracy": identity_trust_accuracy,
            "results": identity_trust_results
        }
        
        # Calculate overall integration accuracy
        overall_accuracy = (trust_policy_accuracy + identity_trust_accuracy) / 2
        interaction_metrics["overall_integration_accuracy"] = overall_accuracy
        
        # Store metrics
        self.integration_metrics["component_interaction_metrics"] = interaction_metrics
        
        # Assertions
        assert overall_accuracy >= 0.8, f"Overall integration accuracy {overall_accuracy} below threshold"
        assert trust_policy_accuracy >= 0.7, f"Trust-policy integration accuracy {trust_policy_accuracy} below threshold"
        assert identity_trust_accuracy >= 0.9, f"Identity-trust integration accuracy {identity_trust_accuracy} below threshold"
        
        print(f"✅ Component Interaction Accuracy:")
        print(f"   Overall accuracy: {overall_accuracy:.2%}")
        print(f"   Trust-policy integration: {trust_policy_accuracy:.2%}")
        print(f"   Identity-trust integration: {identity_trust_accuracy:.2%}")
    
    def test_security_validation_comprehensive(self):
        """Test comprehensive security validation"""
        security_metrics = {
            "authentication_security": {},
            "authorization_security": {},
            "trust_security": {},
            "policy_security": {},
            "overall_security_score": 0.0
        }
        
        # Test 1: Authentication Security
        auth_security_tests = {
            "valid_authentication": 0,
            "invalid_authentication": 0,
            "authentication_bypass_attempts": 0,
            "total_auth_tests": 0
        }
        
        # Test valid authentication
        valid_agents = []
        for i in range(20):
            agent_id = f"auth_security_agent_{i}"
            public_key = f"auth_security_key_{i}".encode()
            valid_agents.append((agent_id, public_key))
            
            reg_result = self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=public_key,
                agent_type=AgentType.WORKER,
                capabilities=["read"],
                metadata={}
            )
            
            if reg_result:
                auth_security_tests["valid_authentication"] += 1
            auth_security_tests["total_auth_tests"] += 1
        
        # Test invalid authentication
        for i in range(20):
            invalid_agent_id = f"invalid_auth_agent_{i}"
            identity = self.identity_manager.get_agent_identity(invalid_agent_id)
            
            if identity is None:
                auth_security_tests["invalid_authentication"] += 1
            else:
                auth_security_tests["authentication_bypass_attempts"] += 1
            auth_security_tests["total_auth_tests"] += 1
        
        auth_security_score = (auth_security_tests["valid_authentication"] + auth_security_tests["invalid_authentication"]) / auth_security_tests["total_auth_tests"]
        security_metrics["authentication_security"] = {
            "score": auth_security_score,
            "tests": auth_security_tests
        }
        
        # Test 2: Authorization Security
        authz_security_tests = {
            "authorized_access": 0,
            "unauthorized_access": 0,
            "privilege_escalation_attempts": 0,
            "total_authz_tests": 0
        }
        
        # Create restrictive policy
        restrictive_policy = AccessPolicy(
            policy_id="restrictive_policy",
            name="Restrictive Policy",
            description="Very restrictive access",
            rules=[{
                "condition": "agent_type == 'admin' AND agent_trust_score >= 0.9",
                "action": "allow",
                "reason": "Admin with high trust only"
            }],
            priority=1
        )
        
        self.policy_engine.add_policy(restrictive_policy)
        
        # Test authorized access (admin with high trust)
        admin_agent_id = "admin_high_trust_agent"
        self.identity_manager.register_agent(
            agent_id=admin_agent_id,
            public_key=b"admin_high_trust_key",
            agent_type=AgentType.COORDINATOR,  # Higher privilege
            capabilities=["admin"],
            metadata={}
        )
        
        # Add high trust events
        for i in range(6):
            event = TrustEvent(
                event_id=f"admin_trust_event_{i}",
                agent_id=admin_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 60,
                value=0.95
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(admin_agent_id)
        
        context = PolicyContext(
            agent_id=admin_agent_id,
            agent_type="admin",
            agent_capabilities=["admin"],
            agent_trust_score=trust_score.overall_score if trust_score else 0.0,
            tool_id="admin_tool",
            tool_risk_level="high",
            operation="admin_operation",
            parameters={},
            context_metadata={}
        )
        
        policy_result = self.policy_engine.evaluate_access(context)
        
        if policy_result.decision == PolicyDecision.ALLOW:
            authz_security_tests["authorized_access"] += 1
        else:
            authz_security_tests["unauthorized_access"] += 1
        authz_security_tests["total_authz_tests"] += 1
        
        # Test unauthorized access (worker with low trust)
        worker_agent_id = "worker_low_trust_agent"
        self.identity_manager.register_agent(
            agent_id=worker_agent_id,
            public_key=b"worker_low_trust_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Add low trust events
        for i in range(6):
            event = TrustEvent(
                event_id=f"worker_trust_event_{i}",
                agent_id=worker_agent_id,
                event_type=TrustEventType.TASK_FAILURE,
                timestamp=time.time() - i * 60,
                value=-0.5
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(worker_agent_id)
        
        context = PolicyContext(
            agent_id=worker_agent_id,
            agent_type="worker",
            agent_capabilities=["read"],
            agent_trust_score=trust_score.overall_score if trust_score else 0.0,
            tool_id="admin_tool",
            tool_risk_level="high",
            operation="admin_operation",
            parameters={},
            context_metadata={}
        )
        
        policy_result = self.policy_engine.evaluate_access(context)
        
        if policy_result.decision == PolicyDecision.DENY:
            authz_security_tests["authorized_access"] += 1
        else:
            authz_security_tests["privilege_escalation_attempts"] += 1
        authz_security_tests["total_authz_tests"] += 1
        
        authz_security_score = authz_security_tests["authorized_access"] / authz_security_tests["total_authz_tests"]
        security_metrics["authorization_security"] = {
            "score": authz_security_score,
            "tests": authz_security_tests
        }
        
        # Test 3: Trust Security
        trust_security_tests = {
            "trust_manipulation_attempts": 0,
            "trust_integrity_checks": 0,
            "total_trust_tests": 0
        }
        
        # Test trust manipulation resistance
        manipulation_agent_id = "trust_manipulation_agent"
        self.identity_manager.register_agent(
            agent_id=manipulation_agent_id,
            public_key=b"trust_manipulation_key",
            agent_type=AgentType.WORKER,
            capabilities=["read"],
            metadata={}
        )
        
        # Add mixed events (some good, some bad)
        mixed_events = [
            (TrustEventType.TASK_SUCCESS, 0.9),
            (TrustEventType.SECURITY_VIOLATION, -0.8),
            (TrustEventType.TASK_SUCCESS, 0.8),
            (TrustEventType.SECURITY_VIOLATION, -0.7),
            (TrustEventType.TASK_SUCCESS, 0.7),
            (TrustEventType.SECURITY_VIOLATION, -0.6),
        ]
        
        for i, (event_type, value) in enumerate(mixed_events):
            event = TrustEvent(
                event_id=f"manipulation_event_{i}",
                agent_id=manipulation_agent_id,
                event_type=event_type,
                timestamp=time.time() - i * 60,
                value=value
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(manipulation_agent_id)
        
        # Trust should be low due to security violations
        if trust_score and trust_score.overall_score < 0.5:
            trust_security_tests["trust_integrity_checks"] += 1
        else:
            trust_security_tests["trust_manipulation_attempts"] += 1
        trust_security_tests["total_trust_tests"] += 1
        
        trust_security_score = trust_security_tests["trust_integrity_checks"] / trust_security_tests["total_trust_tests"]
        security_metrics["trust_security"] = {
            "score": trust_security_score,
            "tests": trust_security_tests
        }
        
        # Calculate overall security score
        overall_security_score = (auth_security_score + authz_security_score + trust_security_score) / 3
        security_metrics["overall_security_score"] = overall_security_score
        
        # Store metrics
        self.integration_metrics["security_validation_metrics"] = security_metrics
        
        # Assertions
        assert overall_security_score >= 0.8, f"Overall security score {overall_security_score} below threshold"
        assert auth_security_score >= 0.9, f"Authentication security score {auth_security_score} below threshold"
        assert authz_security_score >= 0.8, f"Authorization security score {authz_security_score} below threshold"
        assert trust_security_score >= 0.7, f"Trust security score {trust_security_score} below threshold"
        
        print(f"✅ Comprehensive Security Validation:")
        print(f"   Overall security score: {overall_security_score:.2%}")
        print(f"   Authentication security: {auth_security_score:.2%}")
        print(f"   Authorization security: {authz_security_score:.2%}")
        print(f"   Trust security: {trust_security_score:.2%}")
    
    def test_scalability_under_load(self):
        """Test framework scalability under various loads"""
        scalability_metrics = {
            "load_levels": [],
            "performance_degradation": {},
            "resource_usage": {},
            "scalability_score": 0.0
        }
        
        load_levels = [10, 50, 100, 200, 500]
        performance_data = []
        
        for load in load_levels:
            print(f"   Testing load level: {load}")
            
            # Measure performance at this load level
            start_time = time.time()
            
            # Register agents
            for i in range(load):
                agent_id = f"scalability_agent_{load}_{i}"
                self.identity_manager.register_agent(
                    agent_id=agent_id,
                    public_key=f"scalability_key_{load}_{i}".encode(),
                    agent_type=AgentType.WORKER,
                    capabilities=["read"],
                    metadata={}
                )
                
                # Add trust events
                for j in range(3):  # Reduced for scalability testing
                    event = TrustEvent(
                        event_id=f"scalability_event_{load}_{i}_{j}",
                        agent_id=agent_id,
                        event_type=TrustEventType.TASK_SUCCESS,
                        timestamp=time.time() - j * 60,
                        value=0.8
                    )
                    self.trust_calculator.add_trust_event(event)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Calculate throughput
            throughput = load / processing_time
            
            performance_data.append({
                "load": load,
                "processing_time": processing_time,
                "throughput": throughput,
                "time_per_agent": processing_time / load
            })
            
            scalability_metrics["load_levels"].append(load)
        
        # Calculate scalability metrics
        baseline_throughput = performance_data[0]["throughput"]
        max_throughput = max(p["throughput"] for p in performance_data)
        min_throughput = min(p["throughput"] for p in performance_data)
        
        # Calculate performance degradation
        degradation_rate = (baseline_throughput - min_throughput) / baseline_throughput if baseline_throughput > 0 else 0
        
        scalability_metrics["performance_degradation"] = {
            "baseline_throughput": baseline_throughput,
            "max_throughput": max_throughput,
            "min_throughput": min_throughput,
            "degradation_rate": degradation_rate
        }
        
        scalability_metrics["resource_usage"] = {
            "performance_data": performance_data
        }
        
        # Calculate scalability score (lower degradation = higher score)
        scalability_score = max(0, 1 - degradation_rate)
        scalability_metrics["scalability_score"] = scalability_score
        
        # Store metrics
        self.integration_metrics["scalability_metrics"] = scalability_metrics
        
        # Assertions
        assert scalability_score >= 0.7, f"Scalability score {scalability_score} below threshold"
        assert degradation_rate < 0.5, f"Performance degradation {degradation_rate} too high"
        
        print(f"✅ Scalability Under Load:")
        print(f"   Scalability score: {scalability_score:.2%}")
        print(f"   Performance degradation: {degradation_rate:.2%}")
        print(f"   Baseline throughput: {baseline_throughput:.2f} agents/sec")
        print(f"   Max throughput: {max_throughput:.2f} agents/sec")
        print(f"   Min throughput: {min_throughput:.2f} agents/sec")
        
        for data in performance_data:
            print(f"   Load {data['load']}: {data['throughput']:.2f} agents/sec ({data['time_per_agent']:.4f}s/agent)")
    
    def test_reliability_and_fault_tolerance(self):
        """Test framework reliability and fault tolerance"""
        reliability_metrics = {
            "error_recovery_tests": {},
            "concurrent_stability_tests": {},
            "data_consistency_tests": {},
            "overall_reliability_score": 0.0
        }
        
        # Test 1: Error Recovery
        error_recovery_tests = {
            "recoverable_errors": 0,
            "unrecoverable_errors": 0,
            "total_error_tests": 0
        }
        
        # Test various error scenarios
        error_scenarios = [
            ("invalid_agent_id", ""),
            ("none_agent_id", None),
            ("invalid_public_key", b""),
            ("none_public_key", None),
        ]
        
        for scenario_name, invalid_value in error_scenarios:
            try:
                if "agent_id" in scenario_name:
                    result = self.identity_manager.register_agent(
                        agent_id=invalid_value,
                        public_key=b"test_key",
                        agent_type=AgentType.WORKER,
                        capabilities=["read"],
                        metadata={}
                    )
                else:  # public_key
                    result = self.identity_manager.register_agent(
                        agent_id="test_agent",
                        public_key=invalid_value,
                        agent_type=AgentType.WORKER,
                        capabilities=["read"],
                        metadata={}
                    )
                
                # If we get here without exception, check if result indicates error handling
                if not result:
                    error_recovery_tests["recoverable_errors"] += 1
                else:
                    error_recovery_tests["unrecoverable_errors"] += 1
                    
            except Exception:
                # Exception was raised, which is also proper error handling
                error_recovery_tests["recoverable_errors"] += 1
            
            error_recovery_tests["total_error_tests"] += 1
        
        error_recovery_score = error_recovery_tests["recoverable_errors"] / error_recovery_tests["total_error_tests"]
        reliability_metrics["error_recovery_tests"] = {
            "score": error_recovery_score,
            "tests": error_recovery_tests
        }
        
        # Test 2: Concurrent Stability
        concurrent_stability_tests = {
            "successful_concurrent_operations": 0,
            "failed_concurrent_operations": 0,
            "total_concurrent_tests": 0
        }
        
        def concurrent_operation_worker(worker_id, operation_count):
            """Worker for concurrent operations"""
            try:
                for i in range(operation_count):
                    agent_id = f"concurrent_reliability_agent_{worker_id}_{i}"
                    
                    # Register agent
                    reg_result = self.identity_manager.register_agent(
                        agent_id=agent_id,
                        public_key=f"concurrent_reliability_key_{worker_id}_{i}".encode(),
                        agent_type=AgentType.WORKER,
                        capabilities=["read"],
                        metadata={}
                    )
                    
                    # Add trust event
                    event = TrustEvent(
                        event_id=f"concurrent_reliability_event_{worker_id}_{i}",
                        agent_id=agent_id,
                        event_type=TrustEventType.TASK_SUCCESS,
                        timestamp=time.time(),
                        value=0.8
                    )
                    self.trust_calculator.add_trust_event(event)
                    
                    # Get trust score
                    trust_score = self.trust_calculator.get_trust_score(agent_id)
                    
                    if reg_result and trust_score:
                        concurrent_stability_tests["successful_concurrent_operations"] += 1
                    else:
                        concurrent_stability_tests["failed_concurrent_operations"] += 1
                    
                    concurrent_stability_tests["total_concurrent_tests"] += 1
                    
            except Exception:
                concurrent_stability_tests["failed_concurrent_operations"] += 1
                concurrent_stability_tests["total_concurrent_tests"] += 1
        
        # Run concurrent operations
        thread_count = 5
        operations_per_thread = 20
        threads = []
        
        for i in range(thread_count):
            thread = threading.Thread(target=concurrent_operation_worker, args=(i, operations_per_thread))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        concurrent_stability_score = concurrent_stability_tests["successful_concurrent_operations"] / concurrent_stability_tests["total_concurrent_tests"]
        reliability_metrics["concurrent_stability_tests"] = {
            "score": concurrent_stability_score,
            "tests": concurrent_stability_tests
        }
        
        # Test 3: Data Consistency
        data_consistency_tests = {
            "consistent_operations": 0,
            "inconsistent_operations": 0,
            "total_consistency_tests": 0
        }
        
        # Test data consistency across operations
        for i in range(20):
            agent_id = f"consistency_agent_{i}"
            
            # Register agent
            reg_result = self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"consistency_key_{i}".encode(),
                agent_type=AgentType.WORKER,
                capabilities=["read"],
                metadata={}
            )
            
            # Add trust events
            for j in range(6):
                event = TrustEvent(
                    event_id=f"consistency_event_{i}_{j}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - j * 60,
                    value=0.8
                )
                self.trust_calculator.add_trust_event(event)
            
            # Get trust score
            trust_score = self.trust_calculator.get_trust_score(agent_id)
            
            # Get identity
            identity = self.identity_manager.get_agent_identity(agent_id)
            
            # Check consistency
            if reg_result and trust_score and identity:
                if identity.agent_id == agent_id and trust_score.agent_id == agent_id:
                    data_consistency_tests["consistent_operations"] += 1
                else:
                    data_consistency_tests["inconsistent_operations"] += 1
            else:
                data_consistency_tests["inconsistent_operations"] += 1
            
            data_consistency_tests["total_consistency_tests"] += 1
        
        data_consistency_score = data_consistency_tests["consistent_operations"] / data_consistency_tests["total_consistency_tests"]
        reliability_metrics["data_consistency_tests"] = {
            "score": data_consistency_score,
            "tests": data_consistency_tests
        }
        
        # Calculate overall reliability score
        overall_reliability_score = (error_recovery_score + concurrent_stability_score + data_consistency_score) / 3
        reliability_metrics["overall_reliability_score"] = overall_reliability_score
        
        # Store metrics
        self.integration_metrics["reliability_metrics"] = reliability_metrics
        
        # Assertions
        assert overall_reliability_score >= 0.8, f"Overall reliability score {overall_reliability_score} below threshold"
        assert error_recovery_score >= 0.8, f"Error recovery score {error_recovery_score} below threshold"
        assert concurrent_stability_score >= 0.9, f"Concurrent stability score {concurrent_stability_score} below threshold"
        assert data_consistency_score >= 0.9, f"Data consistency score {data_consistency_score} below threshold"
        
        print(f"✅ Reliability and Fault Tolerance:")
        print(f"   Overall reliability score: {overall_reliability_score:.2%}")
        print(f"   Error recovery score: {error_recovery_score:.2%}")
        print(f"   Concurrent stability score: {concurrent_stability_score:.2%}")
        print(f"   Data consistency score: {data_consistency_score:.2%}")

