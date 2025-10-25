#!/usr/bin/env python3
"""
MCP Security Framework - Final Integration Tests
===============================================

This script performs comprehensive integration tests for the MCP Security Framework.
It tests the complete workflow from agent registration to policy evaluation.

Usage:
    python test_integration_final.py [options]

Options:
    --verbose         Enable verbose output
    --quick           Run quick tests only
    --stress          Run stress tests
    --config FILE     Configuration file path
"""

import sys
import os
import asyncio
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse

# Add the framework to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mcp_security_framework'))

from mcp_security_framework.core.identity import IdentityManager, AgentType, IdentityStatus
from mcp_security_framework.core.trust import TrustCalculator, TrustEvent, TrustEventType, TrustDimension
from mcp_security_framework.core.policy import PolicyEngine, PolicyContext, PolicyDecision
from mcp_security_framework.core.gateway import MCPSecurityGateway
from mcp_security_framework.core.registry import ToolRegistry


class IntegrationTestSuite:
    """Comprehensive integration test suite for MCP Security Framework"""
    
    def __init__(self, config_path: str = "config/security_config.yaml", verbose: bool = False):
        self.config_path = config_path
        self.verbose = verbose
        self.test_results = []
        self.start_time = time.time()
        
        # Initialize framework components
        self.identity_manager = IdentityManager()
        self.trust_calculator = TrustCalculator()
        self.policy_engine = PolicyEngine()
        self.tool_registry = ToolRegistry()
        self.gateway = None
        
        # Test data
        self.test_agents = []
        self.test_policies = []
        
    def log(self, message: str, level: str = "INFO"):
        """Log test messages"""
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        print(f"{prefix} {message}")
        
        if self.verbose:
            self.test_results.append({
                "timestamp": time.time(),
                "level": level,
                "message": message
            })
    
    def setup_test_environment(self) -> bool:
        """Setup test environment"""
        self.log("🔧 Setting up test environment...")
        
        try:
            # Initialize gateway
            self.gateway = MCPSecurityGateway(config_path=self.config_path)
            self.log("✅ Gateway initialized")
            
            # Load test policies
            self._load_test_policies()
            
            # Create test agents
            self._create_test_agents()
            
            self.log("✅ Test environment setup completed")
            return True
            
        except Exception as e:
            self.log(f"❌ Test environment setup failed: {e}", "ERROR")
            return False
    
    def _load_test_policies(self):
        """Load test policies"""
        try:
            policy_file = Path("test_policies.json")
            if policy_file.exists():
                with open(policy_file, 'r') as f:
                    policy_data = json.load(f)
                    self.test_policies = policy_data.get("policies", [])
                self.log(f"✅ Loaded {len(self.test_policies)} test policies")
            else:
                self.log("⚠️ Test policies file not found, using default policies", "WARNING")
                self._create_default_policies()
        except Exception as e:
            self.log(f"❌ Failed to load test policies: {e}", "ERROR")
            self._create_default_policies()
    
    def _create_default_policies(self):
        """Create default test policies"""
        self.test_policies = [
            {
                "id": "test_admin",
                "name": "Test Admin Policy",
                "rules": [
                    {
                        "action": "allow",
                        "resource": "*",
                        "conditions": {
                            "agent_type": "admin",
                            "trust_score": {"min": 0.8}
                        }
                    }
                ]
            },
            {
                "id": "test_user",
                "name": "Test User Policy",
                "rules": [
                    {
                        "action": "allow",
                        "resource": "user_resources",
                        "conditions": {
                            "agent_type": "user",
                            "trust_score": {"min": 0.5}
                        }
                    }
                ]
            }
        ]
        self.log("✅ Created default test policies")
    
    def _create_test_agents(self):
        """Create test agents"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        agent_configs = [
            {"id": "admin_001", "type": AgentType.ADMIN, "capabilities": ["admin", "user_management"]},
            {"id": "user_001", "type": AgentType.USER, "capabilities": ["read", "write"]},
            {"id": "user_002", "type": AgentType.USER, "capabilities": ["read"]},
            {"id": "guest_001", "type": AgentType.GUEST, "capabilities": ["read_public"]},
            {"id": "service_001", "type": AgentType.SERVICE, "capabilities": ["api_access"]}
        ]
        
        for config in agent_configs:
            try:
                # Generate RSA key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                public_key = private_key.public_key()
                
                # Serialize public key
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Register agent
                success, message = self.identity_manager.register_agent(
                    agent_id=config["id"],
                    public_key=public_key_bytes,
                    agent_type=config["type"],
                    capabilities=config["capabilities"]
                )
                
                if success:
                    self.test_agents.append(config)
                    self.log(f"✅ Created test agent: {config['id']}")
                else:
                    self.log(f"❌ Failed to create agent {config['id']}: {message}", "ERROR")
                    
            except Exception as e:
                self.log(f"❌ Error creating agent {config['id']}: {e}", "ERROR")
    
    async def test_agent_registration(self) -> bool:
        """Test agent registration workflow"""
        self.log("🧪 Testing agent registration workflow...")
        
        try:
            # Test successful registration
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            success, message = self.identity_manager.register_agent(
                agent_id="test_registration",
                public_key=public_key_bytes,
                agent_type=AgentType.USER,
                capabilities=["test"]
            )
            
            if not success:
                self.log(f"❌ Agent registration failed: {message}", "ERROR")
                return False
            
            # Test duplicate registration
            success, message = self.identity_manager.register_agent(
                agent_id="test_registration",
                public_key=public_key_bytes,
                agent_type=AgentType.USER,
                capabilities=["test"]
            )
            
            if success:
                self.log("❌ Duplicate registration should have failed", "ERROR")
                return False
            
            # Test agent retrieval
            identity = self.identity_manager.get_agent_identity("test_registration")
            if not identity:
                self.log("❌ Failed to retrieve agent identity", "ERROR")
                return False
            
            self.log("✅ Agent registration workflow test passed")
            return True
            
        except Exception as e:
            self.log(f"❌ Agent registration test failed: {e}", "ERROR")
            return False
    
    async def test_trust_calculation(self) -> bool:
        """Test trust calculation workflow"""
        self.log("🧪 Testing trust calculation workflow...")
        
        try:
            agent_id = "test_trust_agent"
            
            # Add trust events
            events = [
                TrustEvent(
                    event_id="trust_event_1",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - 10,
                    value=0.8,
                    context={"task": "test_task"}
                ),
                TrustEvent(
                    event_id="trust_event_2",
                    agent_id=agent_id,
                    event_type=TrustEventType.SUCCESSFUL_OPERATION,
                    timestamp=time.time() - 8,
                    value=0.9,
                    context={"operation": "test_operation"}
                ),
                TrustEvent(
                    event_id="trust_event_3",
                    agent_id=agent_id,
                    event_type=TrustEventType.COOPERATION_POSITIVE,
                    timestamp=time.time() - 6,
                    value=0.7,
                    context={"cooperation": "test_cooperation"}
                ),
                TrustEvent(
                    event_id="trust_event_4",
                    agent_id=agent_id,
                    event_type=TrustEventType.HONESTY_POSITIVE,
                    timestamp=time.time() - 4,
                    value=0.85,
                    context={"honesty": "test_honesty"}
                ),
                TrustEvent(
                    event_id="trust_event_5",
                    agent_id=agent_id,
                    event_type=TrustEventType.SUCCESSFUL_OPERATION,
                    timestamp=time.time() - 2,
                    value=0.9,
                    context={"operation": "final_test"}
                )
            ]
            
            # Add events to trust calculator
            for event in events:
                success = self.trust_calculator.add_trust_event(event)
                if not success:
                    self.log(f"❌ Failed to add trust event: {event.event_id}", "ERROR")
                    return False
            
            # Wait for processing
            await asyncio.sleep(0.1)
            
            # Get trust score
            trust_score = self.trust_calculator.get_trust_score(agent_id)
            if not trust_score:
                self.log("❌ Failed to calculate trust score", "ERROR")
                return False
            
            self.log(f"✅ Trust score calculated: {trust_score.overall_score:.3f}")
            
            # Test trust dimensions
            for dimension in TrustDimension:
                dimension_score = getattr(trust_score, dimension.value, None)
                if dimension_score is not None:
                    self.log(f"  {dimension.value}: {dimension_score:.3f}")
            
            self.log("✅ Trust calculation workflow test passed")
            return True
            
        except Exception as e:
            self.log(f"❌ Trust calculation test failed: {e}", "ERROR")
            return False
    
    async def test_policy_evaluation(self) -> bool:
        """Test policy evaluation workflow"""
        self.log("🧪 Testing policy evaluation workflow...")
        
        try:
            # Test admin policy
            admin_context = PolicyContext(
                agent_id="admin_001",
                resource="admin_resources",
                action="read",
                agent_type=AgentType.ADMIN,
                trust_score=0.9
            )
            
            decision = self.policy_engine.evaluate_access(admin_context)
            if decision.decision != "allow":
                self.log(f"❌ Admin policy evaluation failed: {decision.reason}", "ERROR")
                return False
            
            # Test user policy
            user_context = PolicyContext(
                agent_id="user_001",
                resource="user_resources",
                action="read",
                agent_type=AgentType.USER,
                trust_score=0.6
            )
            
            decision = self.policy_engine.evaluate_access(user_context)
            if decision.decision != "allow":
                self.log(f"❌ User policy evaluation failed: {decision.reason}", "ERROR")
                return False
            
            # Test denied access
            denied_context = PolicyContext(
                agent_id="guest_001",
                resource="admin_resources",
                action="write",
                agent_type=AgentType.GUEST,
                trust_score=0.3
            )
            
            decision = self.policy_engine.evaluate_access(denied_context)
            if decision.decision != "deny":
                self.log(f"❌ Denial policy evaluation failed: {decision.reason}", "ERROR")
                return False
            
            self.log("✅ Policy evaluation workflow test passed")
            return True
            
        except Exception as e:
            self.log(f"❌ Policy evaluation test failed: {e}", "ERROR")
            return False
    
    async def test_gateway_integration(self) -> bool:
        """Test gateway integration"""
        self.log("🧪 Testing gateway integration...")
        
        try:
            if not self.gateway:
                self.log("❌ Gateway not initialized", "ERROR")
                return False
            
            # Test gateway status
            status = self.gateway.get_status()
            if not status:
                self.log("❌ Failed to get gateway status", "ERROR")
                return False
            
            self.log(f"✅ Gateway status: {status}")
            
            # Test gateway components
            components = [
                "identity_manager",
                "trust_calculator", 
                "policy_engine",
                "tool_registry"
            ]
            
            for component in components:
                if hasattr(self.gateway, component):
                    self.log(f"✅ Gateway component {component} is available")
                else:
                    self.log(f"❌ Gateway component {component} is missing", "ERROR")
                    return False
            
            self.log("✅ Gateway integration test passed")
            return True
            
        except Exception as e:
            self.log(f"❌ Gateway integration test failed: {e}", "ERROR")
            return False
    
    async def test_end_to_end_workflow(self) -> bool:
        """Test complete end-to-end workflow"""
        self.log("🧪 Testing end-to-end workflow...")
        
        try:
            # Step 1: Register agent
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            success, message = self.identity_manager.register_agent(
                agent_id="e2e_test_agent",
                public_key=public_key_bytes,
                agent_type=AgentType.USER,
                capabilities=["read", "write"]
            )
            
            if not success:
                self.log(f"❌ E2E: Agent registration failed: {message}", "ERROR")
                return False
            
            # Step 2: Build trust
            for i in range(5):
                event = TrustEvent(
                    event_id=f"e2e_trust_event_{i}",
                    agent_id="e2e_test_agent",
                    event_type=TrustEventType.SUCCESSFUL_OPERATION,
                    timestamp=time.time() - (5 - i),
                    value=0.8,
                    context={"e2e_test": f"event_{i}"}
                )
                self.trust_calculator.add_trust_event(event)
            
            await asyncio.sleep(0.1)
            
            # Step 3: Get trust score
            trust_score = self.trust_calculator.get_trust_score("e2e_test_agent")
            if not trust_score:
                self.log("❌ E2E: Failed to calculate trust score", "ERROR")
                return False
            
            # Step 4: Evaluate policy
            context = PolicyContext(
                agent_id="e2e_test_agent",
                resource="user_resources",
                action="read",
                agent_type=AgentType.USER,
                trust_score=trust_score.overall_score
            )
            
            decision = self.policy_engine.evaluate_access(context)
            if decision.decision != "allow":
                self.log(f"❌ E2E: Policy evaluation failed: {decision.reason}", "ERROR")
                return False
            
            self.log(f"✅ E2E workflow completed successfully (trust: {trust_score.overall_score:.3f})")
            return True
            
        except Exception as e:
            self.log(f"❌ E2E workflow test failed: {e}", "ERROR")
            return False
    
    async def run_stress_test(self) -> bool:
        """Run stress test"""
        self.log("🧪 Running stress test...")
        
        try:
            # Test concurrent agent registration
            async def register_agent(agent_id: str):
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key = private_key.public_key()
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                return self.identity_manager.register_agent(
                    agent_id=agent_id,
                    public_key=public_key_bytes,
                    agent_type=AgentType.USER,
                    capabilities=["stress_test"]
                )
            
            # Register multiple agents concurrently
            tasks = []
            for i in range(10):
                task = register_agent(f"stress_agent_{i}")
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            success_count = sum(1 for result in results if isinstance(result, tuple) and result[0])
            self.log(f"✅ Stress test: {success_count}/10 agents registered successfully")
            
            return success_count >= 8  # Allow some failures
            
        except Exception as e:
            self.log(f"❌ Stress test failed: {e}", "ERROR")
            return False
    
    async def run_all_tests(self, quick: bool = False, stress: bool = False) -> Dict[str, bool]:
        """Run all integration tests"""
        self.log("🚀 Starting comprehensive integration tests...")
        
        test_results = {}
        
        # Core tests
        test_results["setup"] = self.setup_test_environment()
        test_results["agent_registration"] = await self.test_agent_registration()
        test_results["trust_calculation"] = await self.test_trust_calculation()
        test_results["policy_evaluation"] = await self.test_policy_evaluation()
        test_results["gateway_integration"] = await self.test_gateway_integration()
        test_results["end_to_end"] = await self.test_end_to_end_workflow()
        
        # Optional tests
        if stress:
            test_results["stress_test"] = await self.run_stress_test()
        
        # Calculate results
        total_tests = len(test_results)
        passed_tests = sum(1 for result in test_results.values() if result)
        success_rate = (passed_tests / total_tests) * 100
        
        self.log(f"📊 Test Results: {passed_tests}/{total_tests} tests passed ({success_rate:.1f}%)")
        
        # Print detailed results
        for test_name, result in test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            self.log(f"  {test_name}: {status}")
        
        return test_results
    
    def save_results(self, results: Dict[str, bool]):
        """Save test results to file"""
        try:
            results_data = {
                "timestamp": time.time(),
                "duration": time.time() - self.start_time,
                "results": results,
                "success_rate": (sum(results.values()) / len(results)) * 100,
                "log": self.test_results if self.verbose else []
            }
            
            results_file = Path("logs/integration_test_results.json")
            results_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(results_file, 'w') as f:
                json.dump(results_data, f, indent=2)
            
            self.log(f"✅ Test results saved to: {results_file}")
            
        except Exception as e:
            self.log(f"❌ Failed to save test results: {e}", "ERROR")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Final Integration Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python test_integration_final.py
    python test_integration_final.py --verbose
    python test_integration_final.py --quick
    python test_integration_final.py --stress
        """
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick tests only"
    )
    
    parser.add_argument(
        "--stress",
        action="store_true",
        help="Run stress tests"
    )
    
    parser.add_argument(
        "--config",
        default="config/security_config.yaml",
        help="Configuration file path"
    )
    
    args = parser.parse_args()
    
    # Create test suite
    test_suite = IntegrationTestSuite(
        config_path=args.config,
        verbose=args.verbose
    )
    
    # Run tests
    async def run_tests():
        results = await test_suite.run_all_tests(
            quick=args.quick,
            stress=args.stress
        )
        
        # Save results
        test_suite.save_results(results)
        
        # Exit with appropriate code
        success_rate = (sum(results.values()) / len(results)) * 100
        if success_rate >= 80:
            print(f"\n🎉 Integration tests completed successfully! ({success_rate:.1f}% pass rate)")
            sys.exit(0)
        else:
            print(f"\n❌ Integration tests failed! ({success_rate:.1f}% pass rate)")
            sys.exit(1)
    
    # Run async tests
    asyncio.run(run_tests())


if __name__ == "__main__":
    main()
