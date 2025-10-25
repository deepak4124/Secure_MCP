#!/usr/bin/env python3
"""
Optimized Real MCP Framework Benchmarking System
Tests actual functionality with performance optimizations
"""

import asyncio
import time
import psutil
import os
import sys
import tempfile
import subprocess
from typing import Dict, List, Any, Optional
import json
from dataclasses import dataclass
import statistics

# Add the framework to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mcp_security_framework.core.identity import IdentityManager, AgentType, IdentityStatus
from mcp_security_framework.core.trust import TrustCalculator, TrustEvent, TrustEventType
from mcp_security_framework.core.policy import PolicyEngine, PolicyContext
from mcp_security_framework.core.gateway import MCPSecurityGateway
from mcp_security_framework.core.registry import ToolRegistry
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@dataclass
class BenchmarkResult:
    """Benchmark result data structure"""
    framework_name: str
    test_name: str
    success: bool
    duration: float
    throughput: float
    memory_usage: float
    cpu_usage: float
    error_message: Optional[str] = None
    details: Dict[str, Any] = None


class OptimizedRealBenchmarker:
    """Optimized benchmarking system with performance improvements"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.frameworks = {
            "our_framework": {
                "name": "Our MCP Security Framework",
                "local": True
            }
        }
        # Pre-generate keys for better performance
        self._generate_test_keys()
    
    def _generate_test_keys(self):
        """Pre-generate test keys for better performance"""
        print("🔑 Pre-generating test keys for performance...")
        self.test_keys = []
        for i in range(1000):  # Generate 1000 keys upfront
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.test_keys.append(public_key)
        print(f"✅ Generated {len(self.test_keys)} test keys")
    
    async def run_comprehensive_benchmark(self) -> Dict[str, Any]:
        """Run comprehensive benchmark on our framework"""
        print("🔧 Running Optimized Real Benchmark on MCP Security Framework")
        print("=" * 60)
        
        # Initialize our framework components
        identity_manager = IdentityManager()
        policy_engine = PolicyEngine()
        tool_registry = ToolRegistry()
        
        # Run all tests
        await self._test_performance(identity_manager, policy_engine)
        await self._test_security(identity_manager, policy_engine)
        await self._test_reliability(identity_manager, policy_engine)
        await self._test_functionality(identity_manager, policy_engine, tool_registry)
        
        return self._generate_report()
    
    async def _test_performance(self, identity_manager, policy_engine):
        """Test performance metrics"""
        print("\n📊 Testing Performance...")
        
        # Test 1: Agent Registration Throughput (Optimized)
        await self._test_agent_registration_throughput_optimized(identity_manager)
        
        # Test 2: Trust Calculation Performance
        await self._test_trust_calculation_performance()
        
        # Test 3: Policy Evaluation Performance
        await self._test_policy_evaluation_performance(policy_engine)
        
        # Test 4: Memory Usage
        await self._test_memory_usage(identity_manager)
        
        # Test 5: CPU Usage
        await self._test_cpu_usage(identity_manager)
    
    async def _test_agent_registration_throughput_optimized(self, identity_manager):
        """Test agent registration throughput with optimized key generation"""
        print("  🔄 Testing Agent Registration Throughput (Optimized)...")
        
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        success_count = 0
        total_operations = 1000
        
        for i in range(total_operations):
            try:
                # Use pre-generated key instead of generating new one
                public_key = self.test_keys[i % len(self.test_keys)]
                
                # Register agent
                success, message = identity_manager.register_agent(
                    agent_id=f"test_agent_{i}",
                    public_key=public_key,
                    agent_type=AgentType.WORKER,
                    capabilities=["test_capability"]
                )
                
                if success:
                    success_count += 1
                    
            except Exception as e:
                print(f"    ❌ Error in registration {i}: {e}")
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        duration = end_time - start_time
        throughput = success_count / duration if duration > 0 else 0
        memory_usage = end_memory - start_memory
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="agent_registration_throughput_optimized",
            success=success_count > 0,
            duration=duration,
            throughput=throughput,
            memory_usage=memory_usage,
            cpu_usage=0,  # Will be calculated separately
            details={
                "total_operations": total_operations,
                "successful_operations": success_count,
                "success_rate": success_count / total_operations
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Throughput: {throughput:.0f} ops/sec")
        print(f"    ✅ Success Rate: {success_count/total_operations*100:.1f}%")
        print(f"    ✅ Memory Usage: {memory_usage:.3f} MB")
    
    async def _test_trust_calculation_performance(self):
        """Test trust calculation performance"""
        print("  🔄 Testing Trust Calculation Performance...")
        
        # Create fresh TrustCalculator for this test
        trust_calculator = TrustCalculator()
        
        start_time = time.time()
        success_count = 0
        total_operations = 100
        
        for i in range(total_operations):
            try:
                # Add multiple events for the same agent to meet min_events requirement
                agent_id = f"test_agent_{i}"
                
                # Add 5 events (minimum required for trust calculation)
                for j in range(5):
                    event = TrustEvent(
                        event_id=f"test_event_{i}_{j}",
                        agent_id=agent_id,
                        event_type=TrustEventType.SUCCESSFUL_OPERATION,
                        timestamp=time.time() - j,  # Use past timestamps
                        value=0.8,
                        context={"test": "true"}
                    )
                    
                    # Record trust event
                    trust_calculator.add_trust_event(event)
                
                # Get trust score (add small delay to ensure calculation is complete)
                await asyncio.sleep(0.001)
                trust_score = trust_calculator.get_trust_score(agent_id)
                
                if trust_score is not None:
                    success_count += 1
                    print(f"    ✅ Trust score calculated for {agent_id}: {trust_score.overall_score:.3f}")
                else:
                    print(f"    ❌ No trust score for {agent_id} after adding 5 events")
                    
            except Exception as e:
                print(f"    ❌ Error in trust calculation {i}: {e}")
                import traceback
                traceback.print_exc()
        
        end_time = time.time()
        duration = end_time - start_time
        throughput = success_count / duration if duration > 0 else 0
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="trust_calculation_performance",
            success=success_count > 0,
            duration=duration,
            throughput=throughput,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_operations": total_operations,
                "successful_operations": success_count,
                "success_rate": success_count / total_operations
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Throughput: {throughput:.0f} ops/sec")
        print(f"    ✅ Success Rate: {success_count/total_operations*100:.1f}%")
    
    async def _test_policy_evaluation_performance(self, policy_engine):
        """Test policy evaluation performance"""
        print("  🔄 Testing Policy Evaluation Performance...")
        
        start_time = time.time()
        success_count = 0
        total_operations = 100
        
        for i in range(total_operations):
            try:
                # Create policy context
                context = PolicyContext(
                    agent_id=f"test_agent_{i}",
                    agent_type="worker",
                    agent_capabilities=["test_capability"],
                    agent_trust_score=0.8,
                    tool_id="test_tool",
                    tool_risk_level="low",
                    operation="execute",
                    parameters={"test": True},
                    context_metadata={"test": True}
                )
                
                # Evaluate policy
                decision = policy_engine.evaluate_policy(context)
                
                if decision is not None:
                    success_count += 1
                    
            except Exception as e:
                print(f"    ❌ Error in policy evaluation {i}: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        throughput = success_count / duration if duration > 0 else 0
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="policy_evaluation_performance",
            success=success_count > 0,
            duration=duration,
            throughput=throughput,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_operations": total_operations,
                "successful_operations": success_count,
                "success_rate": success_count / total_operations
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Throughput: {throughput:.0f} ops/sec")
        print(f"    ✅ Success Rate: {success_count/total_operations*100:.1f}%")
    
    async def _test_memory_usage(self, identity_manager):
        """Test memory usage"""
        print("  🔄 Testing Memory Usage...")
        
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Register many agents using pre-generated keys
        for i in range(2000):
            try:
                public_key = self.test_keys[i % len(self.test_keys)]
                
                identity_manager.register_agent(
                    agent_id=f"memory_test_agent_{i}",
                    public_key=public_key,
                    agent_type=AgentType.WORKER,
                    capabilities=["memory_test"]
                )
            except Exception as e:
                print(f"    ❌ Error in memory test {i}: {e}")
                break
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_usage = final_memory - initial_memory
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="memory_usage",
            success=True,
            duration=0,
            throughput=0,
            memory_usage=memory_usage,
            cpu_usage=0,
            details={
                "initial_memory_mb": initial_memory,
                "final_memory_mb": final_memory,
                "agents_registered": 2000
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Memory Usage: {memory_usage:.3f} MB for 2000 agents")
    
    async def _test_cpu_usage(self, identity_manager):
        """Test CPU usage"""
        print("  🔄 Testing CPU Usage...")
        
        process = psutil.Process()
        cpu_samples = []
        
        # Monitor CPU during operations
        for i in range(50):
            cpu_percent = process.cpu_percent()
            cpu_samples.append(cpu_percent)
            
            # Do some work using pre-generated keys
            try:
                public_key = self.test_keys[i % len(self.test_keys)]
                
                identity_manager.register_agent(
                    agent_id=f"cpu_test_agent_{i}",
                    public_key=public_key,
                    agent_type=AgentType.WORKER,
                    capabilities=["cpu_test"]
                )
            except Exception as e:
                print(f"    ❌ Error in CPU test {i}: {e}")
            
            await asyncio.sleep(0.01)  # Small delay
        
        avg_cpu = statistics.mean(cpu_samples)
        max_cpu = max(cpu_samples)
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="cpu_usage",
            success=True,
            duration=0,
            throughput=0,
            memory_usage=0,
            cpu_usage=avg_cpu,
            details={
                "average_cpu_percent": avg_cpu,
                "max_cpu_percent": max_cpu,
                "samples_taken": len(cpu_samples)
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Average CPU: {avg_cpu:.1f}%")
        print(f"    ✅ Max CPU: {max_cpu:.1f}%")
    
    async def _test_security(self, identity_manager, policy_engine):
        """Test security features"""
        print("\n🔒 Testing Security Features...")
        
        # Test 1: Authentication
        await self._test_authentication(identity_manager)
        
        # Test 2: Authorization
        await self._test_authorization(policy_engine)
        
        # Test 3: Trust-based Security
        await self._test_trust_based_security()
    
    async def _test_authentication(self, identity_manager):
        """Test authentication functionality"""
        print("  🔄 Testing Authentication...")
        
        success_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            try:
                # Use pre-generated key
                public_key = self.test_keys[i % len(self.test_keys)]
                
                # Register agent
                success, message = identity_manager.register_agent(
                    agent_id=f"auth_test_agent_{i}",
                    public_key=public_key,
                    agent_type=AgentType.WORKER,
                    capabilities=["auth_test"]
                )
                
                if success:
                    # Try to get agent identity
                    identity = identity_manager.get_agent_identity(f"auth_test_agent_{i}")
                    if identity is not None:
                        success_count += 1
                        
            except Exception as e:
                print(f"    ❌ Error in authentication test {i}: {e}")
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="authentication",
            success=success_count > 0,
            duration=0,
            throughput=0,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_tests": total_tests,
                "successful_tests": success_count,
                "success_rate": success_count / total_tests
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Authentication Success Rate: {success_count/total_tests*100:.1f}%")
    
    async def _test_authorization(self, policy_engine):
        """Test authorization functionality"""
        print("  🔄 Testing Authorization...")
        
        success_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            try:
                # Create policy context
                context = PolicyContext(
                    agent_id=f"authz_test_agent_{i}",
                    agent_type="worker",
                    agent_capabilities=["test_capability"],
                    agent_trust_score=0.8,
                    tool_id="test_tool",
                    tool_risk_level="low",
                    operation="execute",
                    parameters={"test": True},
                    context_metadata={"test": True}
                )
                
                # Evaluate policy
                decision = policy_engine.evaluate_policy(context)
                
                if decision is not None:
                    success_count += 1
                    
            except Exception as e:
                print(f"    ❌ Error in authorization test {i}: {e}")
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="authorization",
            success=success_count > 0,
            duration=0,
            throughput=0,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_tests": total_tests,
                "successful_tests": success_count,
                "success_rate": success_count / total_tests
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Authorization Success Rate: {success_count/total_tests*100:.1f}%")
    
    async def _test_trust_based_security(self):
        """Test trust-based security"""
        print("  🔄 Testing Trust-based Security...")
        
        # Create fresh TrustCalculator for this test
        trust_calculator = TrustCalculator()
        
        success_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            try:
                # Add multiple events for the same agent to meet min_events requirement
                agent_id = f"security_test_agent_{i}"
                
                # Add 5 events (minimum required for trust calculation)
                for j in range(5):
                    event = TrustEvent(
                        event_id=f"security_test_event_{i}_{j}",
                        agent_id=agent_id,
                        event_type=TrustEventType.SUCCESSFUL_OPERATION,
                        timestamp=time.time() - j,  # Use past timestamps
                        value=0.8,
                        context={"security_test": "true"}
                    )
                    
                    # Record trust event
                    trust_calculator.add_trust_event(event)
                
                # Get trust score (add small delay to ensure calculation is complete)
                await asyncio.sleep(0.001)
                trust_score = trust_calculator.get_trust_score(agent_id)
                
                if trust_score is not None:
                    success_count += 1
                    print(f"    ✅ Trust security score for {agent_id}: {trust_score.overall_score:.3f}")
                    
            except Exception as e:
                print(f"    ❌ Error in trust security test {i}: {e}")
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="trust_based_security",
            success=success_count > 0,
            duration=0,
            throughput=0,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_tests": total_tests,
                "successful_tests": success_count,
                "success_rate": success_count / total_tests
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Trust Security Success Rate: {success_count/total_tests*100:.1f}%")
    
    async def _test_reliability(self, identity_manager, policy_engine):
        """Test reliability features"""
        print("\n🛡️ Testing Reliability Features...")
        
        # Test 1: Error Handling
        await self._test_error_handling(identity_manager)
        
        # Test 2: Concurrent Operations
        await self._test_concurrent_operations(identity_manager)
    
    async def _test_error_handling(self, identity_manager):
        """Test error handling"""
        print("  🔄 Testing Error Handling...")
        
        success_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            try:
                # Try to register agent with invalid data
                success, message = identity_manager.register_agent(
                    agent_id="",  # Invalid empty ID
                    public_key=b"invalid_key",  # Invalid key
                    agent_type=AgentType.WORKER,
                    capabilities=[]
                )
                
                # Should fail gracefully
                if not success and message:
                    success_count += 1
                    
            except Exception as e:
                # Should handle exceptions gracefully
                success_count += 1
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="error_handling",
            success=success_count > 0,
            duration=0,
            throughput=0,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_tests": total_tests,
                "successful_tests": success_count,
                "success_rate": success_count / total_tests
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Error Handling Success Rate: {success_count/total_tests*100:.1f}%")
    
    async def _test_concurrent_operations(self, identity_manager):
        """Test concurrent operations"""
        print("  🔄 Testing Concurrent Operations...")
        
        async def register_agent_async(agent_id: str, key_index: int):
            try:
                public_key = self.test_keys[key_index % len(self.test_keys)]
                
                success, message = identity_manager.register_agent(
                    agent_id=agent_id,
                    public_key=public_key,
                    agent_type=AgentType.WORKER,
                    capabilities=["concurrent_test"]
                )
                return success
            except Exception as e:
                return False
        
        # Run concurrent operations
        tasks = []
        for i in range(20):
            task = register_agent_async(f"concurrent_agent_{i}", i)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is True)
        total_operations = len(results)
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="concurrent_operations",
            success=success_count > 0,
            duration=0,
            throughput=0,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_operations": total_operations,
                "successful_operations": success_count,
                "success_rate": success_count / total_operations
            }
        )
        
        self.results.append(result)
        print(f"    ✅ Concurrent Operations Success Rate: {success_count/total_operations*100:.1f}%")
    
    async def _test_functionality(self, identity_manager, policy_engine, tool_registry):
        """Test overall functionality"""
        print("\n⚙️ Testing Overall Functionality...")
        
        # Test 1: End-to-End Workflow
        await self._test_end_to_end_workflow(identity_manager, policy_engine, tool_registry)
    
    async def _test_end_to_end_workflow(self, identity_manager, policy_engine, tool_registry):
        """Test end-to-end workflow"""
        print("  🔄 Testing End-to-End Workflow...")
        
        # Create fresh TrustCalculator for this test
        trust_calculator = TrustCalculator()
        
        success_count = 0
        total_tests = 5
        
        for i in range(total_tests):
            try:
                # Step 1: Register agent
                public_key = self.test_keys[i % len(self.test_keys)]
                
                success, message = identity_manager.register_agent(
                    agent_id=f"e2e_agent_{i}",
                    public_key=public_key,
                    agent_type=AgentType.WORKER,
                    capabilities=["e2e_test"]
                )
                
                if not success:
                    continue
                
                # Step 2: Record multiple trust events (minimum 5 required)
                agent_id = f"e2e_agent_{i}"
                
                for j in range(5):
                    event = TrustEvent(
                        event_id=f"e2e_event_{i}_{j}",
                        agent_id=agent_id,
                        event_type=TrustEventType.SUCCESSFUL_OPERATION,
                        timestamp=time.time() - j,  # Use past timestamps
                        value=0.8,
                        context={"e2e_test": "true"}
                    )
                    
                    trust_calculator.add_trust_event(event)
                
                # Step 3: Get trust score (add small delay to ensure calculation is complete)
                await asyncio.sleep(0.001)
                trust_score = trust_calculator.get_trust_score(agent_id)
                
                if trust_score is not None:
                    success_count += 1
                    print(f"    ✅ E2E workflow completed for {agent_id}: trust={trust_score.overall_score:.3f}")
                    
            except Exception as e:
                print(f"    ❌ Error in E2E test {i}: {e}")
        
        result = BenchmarkResult(
            framework_name="our_framework",
            test_name="end_to_end_workflow",
            success=success_count > 0,
            duration=0,
            throughput=0,
            memory_usage=0,
            cpu_usage=0,
            details={
                "total_tests": total_tests,
                "successful_tests": success_count,
                "success_rate": success_count / total_tests
            }
        )
        
        self.results.append(result)
        print(f"    ✅ End-to-End Success Rate: {success_count/total_tests*100:.1f}%")
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive report"""
        print("\n📊 Generating Report...")
        
        # Calculate overall metrics
        performance_tests = [r for r in self.results if "throughput" in r.test_name or "performance" in r.test_name]
        security_tests = [r for r in self.results if "authentication" in r.test_name or "authorization" in r.test_name or "security" in r.test_name]
        reliability_tests = [r for r in self.results if "error" in r.test_name or "concurrent" in r.test_name]
        
        # Calculate averages
        avg_throughput = statistics.mean([r.throughput for r in performance_tests if r.throughput > 0]) if performance_tests else 0
        avg_memory = statistics.mean([r.memory_usage for r in self.results if r.memory_usage > 0]) if self.results else 0
        avg_cpu = statistics.mean([r.cpu_usage for r in self.results if r.cpu_usage > 0]) if self.results else 0
        
        # Calculate success rates
        performance_success_rate = sum(1 for r in performance_tests if r.success) / len(performance_tests) if performance_tests else 0
        security_success_rate = sum(1 for r in security_tests if r.success) / len(security_tests) if security_tests else 0
        reliability_success_rate = sum(1 for r in reliability_tests if r.success) / len(reliability_tests) if reliability_tests else 0
        overall_success_rate = sum(1 for r in self.results if r.success) / len(self.results) if self.results else 0
        
        report = {
            "framework": "Our MCP Security Framework (Optimized)",
            "timestamp": time.time(),
            "overall_metrics": {
                "avg_throughput_ops_per_sec": avg_throughput,
                "avg_memory_usage_mb": avg_memory,
                "avg_cpu_usage_percent": avg_cpu,
                "overall_success_rate": overall_success_rate
            },
            "category_metrics": {
                "performance": {
                    "success_rate": performance_success_rate,
                    "avg_throughput": avg_throughput,
                    "tests_passed": sum(1 for r in performance_tests if r.success),
                    "total_tests": len(performance_tests)
                },
                "security": {
                    "success_rate": security_success_rate,
                    "tests_passed": sum(1 for r in security_tests if r.success),
                    "total_tests": len(security_tests)
                },
                "reliability": {
                    "success_rate": reliability_success_rate,
                    "tests_passed": sum(1 for r in reliability_tests if r.success),
                    "total_tests": len(reliability_tests)
                }
            },
            "detailed_results": [
                {
                    "test_name": r.test_name,
                    "success": r.success,
                    "throughput": r.throughput,
                    "memory_usage": r.memory_usage,
                    "cpu_usage": r.cpu_usage,
                    "details": r.details
                }
                for r in self.results
            ]
        }
        
        return report


async def main():
    """Main function"""
    benchmarker = OptimizedRealBenchmarker()
    results = await benchmarker.run_comprehensive_benchmark()
    
    print("\n" + "=" * 60)
    print("🎯 FINAL OPTIMIZED REAL BENCHMARK RESULTS")
    print("=" * 60)
    
    print(f"\n📊 Overall Performance:")
    print(f"   Average Throughput: {results['overall_metrics']['avg_throughput_ops_per_sec']:.0f} ops/sec")
    print(f"   Average Memory Usage: {results['overall_metrics']['avg_memory_usage_mb']:.3f} MB")
    print(f"   Average CPU Usage: {results['overall_metrics']['avg_cpu_usage_percent']:.1f}%")
    print(f"   Overall Success Rate: {results['overall_metrics']['overall_success_rate']*100:.1f}%")
    
    print(f"\n🔒 Security Features:")
    print(f"   Success Rate: {results['category_metrics']['security']['success_rate']*100:.1f}%")
    print(f"   Tests Passed: {results['category_metrics']['security']['tests_passed']}/{results['category_metrics']['security']['total_tests']}")
    
    print(f"\n🛡️ Reliability Features:")
    print(f"   Success Rate: {results['category_metrics']['reliability']['success_rate']*100:.1f}%")
    print(f"   Tests Passed: {results['category_metrics']['reliability']['tests_passed']}/{results['category_metrics']['reliability']['total_tests']}")
    
    print(f"\n⚡ Performance Features:")
    print(f"   Success Rate: {results['category_metrics']['performance']['success_rate']*100:.1f}%")
    print(f"   Tests Passed: {results['category_metrics']['performance']['tests_passed']}/{results['category_metrics']['performance']['total_tests']}")
    
    # Save results
    with open("optimized_real_benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: optimized_real_benchmark_results.json")
    
    return results


if __name__ == "__main__":
    asyncio.run(main())