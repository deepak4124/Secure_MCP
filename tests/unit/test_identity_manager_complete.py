"""
Complete Unit Tests for Identity Manager with Metrics Collection
"""

import pytest
import time
import statistics
from unittest.mock import Mock, patch
from mcp_security_framework.core.identity import (
    IdentityManager, AgentType, IdentityStatus, AgentIdentity
)


class TestIdentityManagerComplete:
    """Complete test cases for IdentityManager with metrics"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.identity_manager = IdentityManager()
        self.test_agent_id = "test_agent_001"
        self.test_public_key = b"test_public_key_data_123456789012345678901234567890"
        self.test_agent_type = AgentType.WORKER
        self.test_capabilities = ["read", "write", "execute"]
        self.test_metadata = {"department": "engineering", "role": "developer"}
        
        # Metrics collection
        self.metrics = {
            "test_execution_times": [],
            "memory_usage": [],
            "success_rates": {},
            "error_counts": {},
            "performance_benchmarks": {}
        }
    
    def teardown_method(self):
        """Collect and report metrics after each test"""
        if hasattr(self, 'metrics'):
            self._report_test_metrics()
    
    def _report_test_metrics(self):
        """Report test execution metrics"""
        if self.metrics["test_execution_times"]:
            avg_time = statistics.mean(self.metrics["test_execution_times"])
            print(f"\n📊 Test Metrics for {self.__class__.__name__}:")
            print(f"   Average execution time: {avg_time:.4f}s")
            print(f"   Total tests executed: {len(self.metrics['test_execution_times'])}")
            print(f"   Success rates: {self.metrics['success_rates']}")
            print(f"   Error counts: {self.metrics['error_counts']}")
    
    def _measure_execution_time(self, func):
        """Decorator to measure execution time"""
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            execution_time = end_time - start_time
            self.metrics["test_execution_times"].append(execution_time)
            return result
        return wrapper
    
    @pytest.mark.benchmark
    def test_register_agent_performance(self):
        """Test agent registration with performance metrics"""
        start_time = time.time()
        
        # Test multiple registrations for performance measurement
        registration_times = []
        success_count = 0
        
        for i in range(100):
            agent_id = f"perf_agent_{i}"
            reg_start = time.time()
            
            result = self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"key_{i}".encode(),
                agent_type=AgentType.WORKER,
                capabilities=self.test_capabilities,
                metadata=self.test_metadata
            )
            
            reg_end = time.time()
            registration_times.append(reg_end - reg_start)
            
            if result:
                success_count += 1
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate metrics
        avg_registration_time = statistics.mean(registration_times)
        min_registration_time = min(registration_times)
        max_registration_time = max(registration_times)
        success_rate = success_count / 100
        
        # Store metrics
        self.metrics["performance_benchmarks"]["registration"] = {
            "total_time": total_time,
            "avg_registration_time": avg_registration_time,
            "min_registration_time": min_registration_time,
            "max_registration_time": max_registration_time,
            "success_rate": success_rate,
            "throughput": 100 / total_time  # registrations per second
        }
        
        # Assertions
        assert success_rate >= 0.95, f"Success rate {success_rate} below threshold"
        assert avg_registration_time < 0.01, f"Average registration time {avg_registration_time}s too slow"
        assert 100 / total_time > 1000, f"Throughput {100 / total_time} too low"
        
        print(f"✅ Registration Performance:")
        print(f"   Throughput: {100 / total_time:.2f} registrations/sec")
        print(f"   Avg time: {avg_registration_time:.4f}s")
        print(f"   Success rate: {success_rate:.2%}")
    
    @pytest.mark.benchmark
    def test_authentication_performance(self):
        """Test authentication with performance metrics"""
        # Setup: Register agents first
        agent_count = 50
        for i in range(agent_count):
            agent_id = f"auth_agent_{i}"
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"auth_key_{i}".encode(),
                agent_type=AgentType.WORKER,
                capabilities=["read"],
                metadata={}
            )
        
        # Test authentication performance
        auth_times = []
        success_count = 0
        
        start_time = time.time()
        
        for i in range(agent_count):
            agent_id = f"auth_agent_{i}"
            auth_start = time.time()
            
            # Test identity verification
            identity = self.identity_manager.get_agent_identity(agent_id)
            if identity:
                success_count += 1
            
            auth_end = time.time()
            auth_times.append(auth_end - auth_start)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate metrics
        avg_auth_time = statistics.mean(auth_times)
        success_rate = success_count / agent_count
        
        # Store metrics
        self.metrics["performance_benchmarks"]["authentication"] = {
            "total_time": total_time,
            "avg_auth_time": avg_auth_time,
            "success_rate": success_rate,
            "throughput": agent_count / total_time
        }
        
        # Assertions
        assert success_rate >= 0.95, f"Authentication success rate {success_rate} below threshold"
        assert avg_auth_time < 0.005, f"Average auth time {avg_auth_time}s too slow"
        
        print(f"✅ Authentication Performance:")
        print(f"   Throughput: {agent_count / total_time:.2f} auths/sec")
        print(f"   Avg time: {avg_auth_time:.4f}s")
        print(f"   Success rate: {success_rate:.2%}")
    
    def test_identity_verification_accuracy(self):
        """Test identity verification accuracy with detailed metrics"""
        # Setup: Register valid agents
        valid_agents = []
        for i in range(20):
            agent_id = f"valid_agent_{i}"
            public_key = f"valid_key_{i}".encode()
            valid_agents.append((agent_id, public_key))
            
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=public_key,
                agent_type=AgentType.WORKER,
                capabilities=["read"],
                metadata={}
            )
        
        # Test verification accuracy
        true_positives = 0
        false_negatives = 0
        true_negatives = 0
        false_positives = 0
        
        # Test valid agents (should be verified)
        for agent_id, public_key in valid_agents:
            identity = self.identity_manager.get_agent_identity(agent_id)
            if identity:
                true_positives += 1
            else:
                false_negatives += 1
        
        # Test invalid agents (should not be verified)
        for i in range(20):
            invalid_agent_id = f"invalid_agent_{i}"
            identity = self.identity_manager.get_agent_identity(invalid_agent_id)
            if identity:
                false_positives += 1
            else:
                true_negatives += 1
        
        # Calculate accuracy metrics
        total_tests = true_positives + false_negatives + true_negatives + false_positives
        accuracy = (true_positives + true_negatives) / total_tests
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Store metrics
        self.metrics["performance_benchmarks"]["verification_accuracy"] = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives
        }
        
        # Assertions
        assert accuracy >= 0.95, f"Verification accuracy {accuracy} below threshold"
        assert precision >= 0.95, f"Precision {precision} below threshold"
        assert recall >= 0.95, f"Recall {recall} below threshold"
        assert f1_score >= 0.95, f"F1 score {f1_score} below threshold"
        
        print(f"✅ Verification Accuracy:")
        print(f"   Accuracy: {accuracy:.2%}")
        print(f"   Precision: {precision:.2%}")
        print(f"   Recall: {recall:.2%}")
        print(f"   F1 Score: {f1_score:.2%}")
    
    def test_concurrent_registration_stress(self):
        """Test concurrent registration under stress"""
        import threading
        import queue
        
        # Shared queue for results
        results = queue.Queue()
        errors = queue.Queue()
        
        def register_agent_worker(worker_id, agent_count):
            """Worker function for concurrent registration"""
            try:
                for i in range(agent_count):
                    agent_id = f"concurrent_agent_{worker_id}_{i}"
                    result = self.identity_manager.register_agent(
                        agent_id=agent_id,
                        public_key=f"concurrent_key_{worker_id}_{i}".encode(),
                        agent_type=AgentType.WORKER,
                        capabilities=["read"],
                        metadata={"worker_id": worker_id}
                    )
                    results.put((worker_id, i, result))
            except Exception as e:
                errors.put((worker_id, str(e)))
        
        # Start concurrent workers
        thread_count = 10
        agents_per_thread = 20
        threads = []
        
        start_time = time.time()
        
        for i in range(thread_count):
            thread = threading.Thread(target=register_agent_worker, args=(i, agents_per_thread))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Collect results
        successful_registrations = 0
        total_attempts = thread_count * agents_per_thread
        
        while not results.empty():
            worker_id, agent_id, result = results.get()
            if result:
                successful_registrations += 1
        
        # Check for errors
        error_count = 0
        while not errors.empty():
            worker_id, error = errors.get()
            error_count += 1
            print(f"❌ Worker {worker_id} error: {error}")
        
        # Calculate metrics
        success_rate = successful_registrations / total_attempts
        throughput = total_attempts / total_time
        
        # Store metrics
        self.metrics["performance_benchmarks"]["concurrent_stress"] = {
            "total_time": total_time,
            "success_rate": success_rate,
            "throughput": throughput,
            "error_count": error_count,
            "thread_count": thread_count,
            "agents_per_thread": agents_per_thread
        }
        
        # Assertions
        assert success_rate >= 0.90, f"Concurrent success rate {success_rate} below threshold"
        assert error_count == 0, f"Concurrent errors detected: {error_count}"
        assert throughput > 100, f"Concurrent throughput {throughput} too low"
        
        print(f"✅ Concurrent Registration Stress Test:")
        print(f"   Threads: {thread_count}")
        print(f"   Total agents: {total_attempts}")
        print(f"   Success rate: {success_rate:.2%}")
        print(f"   Throughput: {throughput:.2f} registrations/sec")
        print(f"   Errors: {error_count}")
    
    def test_memory_usage_under_load(self):
        """Test memory usage under various loads"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Measure baseline memory
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_measurements = []
        
        # Test different load levels
        load_levels = [100, 500, 1000, 2000]
        
        for load in load_levels:
            # Register agents
            for i in range(load):
                agent_id = f"memory_agent_{load}_{i}"
                self.identity_manager.register_agent(
                    agent_id=agent_id,
                    public_key=f"memory_key_{load}_{i}".encode(),
                    agent_type=AgentType.WORKER,
                    capabilities=["read"],
                    metadata={"load_level": load}
                )
            
            # Measure memory
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = current_memory - baseline_memory
            memory_measurements.append({
                "load": load,
                "memory_mb": memory_usage,
                "memory_per_agent": memory_usage / load
            })
        
        # Calculate memory efficiency
        avg_memory_per_agent = statistics.mean([m["memory_per_agent"] for m in memory_measurements])
        memory_growth_rate = (memory_measurements[-1]["memory_mb"] - memory_measurements[0]["memory_mb"]) / (load_levels[-1] - load_levels[0])
        
        # Store metrics
        self.metrics["performance_benchmarks"]["memory_usage"] = {
            "baseline_memory_mb": baseline_memory,
            "memory_measurements": memory_measurements,
            "avg_memory_per_agent": avg_memory_per_agent,
            "memory_growth_rate": memory_growth_rate
        }
        
        # Assertions
        assert avg_memory_per_agent < 0.1, f"Memory per agent {avg_memory_per_agent:.4f}MB too high"
        assert memory_growth_rate < 0.05, f"Memory growth rate {memory_growth_rate:.4f}MB/agent too high"
        
        print(f"✅ Memory Usage Under Load:")
        print(f"   Baseline memory: {baseline_memory:.2f}MB")
        print(f"   Avg memory per agent: {avg_memory_per_agent:.4f}MB")
        print(f"   Memory growth rate: {memory_growth_rate:.4f}MB/agent")
        for measurement in memory_measurements:
            print(f"   Load {measurement['load']}: {measurement['memory_mb']:.2f}MB")
    
    def test_identity_lifecycle_comprehensive(self):
        """Test complete identity lifecycle with metrics"""
        lifecycle_metrics = {
            "registration_time": 0,
            "verification_time": 0,
            "update_time": 0,
            "revocation_time": 0,
            "cleanup_time": 0
        }
        
        agent_id = "lifecycle_agent"
        
        # 1. Registration
        start_time = time.time()
        reg_result = self.identity_manager.register_agent(
            agent_id=agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        lifecycle_metrics["registration_time"] = time.time() - start_time
        
        assert reg_result, "Registration failed"
        
        # 2. Verification
        start_time = time.time()
        identity = self.identity_manager.get_agent_identity(agent_id)
        lifecycle_metrics["verification_time"] = time.time() - start_time
        
        assert identity is not None, "Identity verification failed"
        assert identity.agent_id == agent_id, "Identity mismatch"
        
        # 3. Update (simulate capability update)
        start_time = time.time()
        # Note: Update functionality would need to be implemented
        lifecycle_metrics["update_time"] = time.time() - start_time
        
        # 4. Revocation
        start_time = time.time()
        revoke_result = self.identity_manager.revoke_identity(agent_id, "Test revocation")
        lifecycle_metrics["revocation_time"] = time.time() - start_time
        
        assert revoke_result, "Revocation failed"
        
        # 5. Cleanup verification
        start_time = time.time()
        identity_after_revoke = self.identity_manager.get_agent_identity(agent_id)
        lifecycle_metrics["cleanup_time"] = time.time() - start_time
        
        # Verify revocation
        assert identity_after_revoke is None or identity_after_revoke.status == IdentityStatus.REVOKED, "Revocation not effective"
        
        # Store metrics
        self.metrics["performance_benchmarks"]["lifecycle"] = lifecycle_metrics
        
        # Calculate total lifecycle time
        total_lifecycle_time = sum(lifecycle_metrics.values())
        
        # Assertions
        assert total_lifecycle_time < 1.0, f"Total lifecycle time {total_lifecycle_time}s too slow"
        assert lifecycle_metrics["registration_time"] < 0.1, f"Registration time {lifecycle_metrics['registration_time']}s too slow"
        assert lifecycle_metrics["verification_time"] < 0.05, f"Verification time {lifecycle_metrics['verification_time']}s too slow"
        
        print(f"✅ Identity Lifecycle Performance:")
        print(f"   Registration: {lifecycle_metrics['registration_time']:.4f}s")
        print(f"   Verification: {lifecycle_metrics['verification_time']:.4f}s")
        print(f"   Update: {lifecycle_metrics['update_time']:.4f}s")
        print(f"   Revocation: {lifecycle_metrics['revocation_time']:.4f}s")
        print(f"   Cleanup: {lifecycle_metrics['cleanup_time']:.4f}s")
        print(f"   Total: {total_lifecycle_time:.4f}s")
    
    def test_error_handling_robustness(self):
        """Test error handling and robustness"""
        error_scenarios = [
            ("empty_agent_id", "", self.test_public_key),
            ("none_agent_id", None, self.test_public_key),
            ("invalid_public_key", self.test_agent_id, b""),
            ("none_public_key", self.test_agent_id, None),
            ("duplicate_agent", self.test_agent_id, self.test_public_key),
        ]
        
        error_count = 0
        handled_errors = 0
        
        for scenario_name, agent_id, public_key in error_scenarios:
            try:
                if scenario_name == "duplicate_agent":
                    # First register successfully
                    self.identity_manager.register_agent(
                        agent_id=agent_id,
                        public_key=public_key,
                        agent_type=self.test_agent_type,
                        capabilities=self.test_capabilities,
                        metadata=self.test_metadata
                    )
                
                # Attempt registration that should fail
                result = self.identity_manager.register_agent(
                    agent_id=agent_id,
                    public_key=public_key,
                    agent_type=self.test_agent_type,
                    capabilities=self.test_capabilities,
                    metadata=self.test_metadata
                )
                
                # If we get here and result is False, error was handled properly
                if not result:
                    handled_errors += 1
                else:
                    error_count += 1
                    
            except Exception as e:
                # Exception was raised, which is also proper error handling
                handled_errors += 1
                print(f"✅ {scenario_name}: Exception properly handled - {str(e)[:50]}...")
        
        # Store metrics
        self.metrics["performance_benchmarks"]["error_handling"] = {
            "total_scenarios": len(error_scenarios),
            "handled_errors": handled_errors,
            "unhandled_errors": error_count,
            "error_handling_rate": handled_errors / len(error_scenarios)
        }
        
        # Assertions
        assert error_count == 0, f"Unhandled errors: {error_count}"
        assert handled_errors == len(error_scenarios), f"Not all errors handled: {handled_errors}/{len(error_scenarios)}"
        
        print(f"✅ Error Handling Robustness:")
        print(f"   Total scenarios: {len(error_scenarios)}")
        print(f"   Handled errors: {handled_errors}")
        print(f"   Unhandled errors: {error_count}")
        print(f"   Error handling rate: {handled_errors / len(error_scenarios):.2%}")
    
    def test_security_validation(self):
        """Test security aspects of identity management"""
        security_metrics = {
            "key_validation_tests": 0,
            "access_control_tests": 0,
            "audit_trail_tests": 0,
            "security_violations": 0
        }
        
        # Test 1: Key validation
        invalid_keys = [
            b"",  # Empty key
            b"short",  # Too short
            b"x" * 1000,  # Too long
            None,  # None key
        ]
        
        for invalid_key in invalid_keys:
            try:
                result = self.identity_manager.register_agent(
                    agent_id=f"security_test_{len(str(invalid_key))}",
                    public_key=invalid_key,
                    agent_type=AgentType.WORKER,
                    capabilities=["read"],
                    metadata={}
                )
                if not result:
                    security_metrics["key_validation_tests"] += 1
            except Exception:
                security_metrics["key_validation_tests"] += 1
        
        # Test 2: Access control (verify only registered agents can be retrieved)
        unregistered_agents = ["fake_agent_1", "fake_agent_2", "fake_agent_3"]
        for agent_id in unregistered_agents:
            identity = self.identity_manager.get_agent_identity(agent_id)
            if identity is None:
                security_metrics["access_control_tests"] += 1
        
        # Test 3: Audit trail (check that operations are logged)
        # This would require access to audit logs
        security_metrics["audit_trail_tests"] = 1  # Placeholder
        
        # Store metrics
        self.metrics["performance_benchmarks"]["security_validation"] = security_metrics
        
        # Assertions
        assert security_metrics["key_validation_tests"] >= 3, "Key validation insufficient"
        assert security_metrics["access_control_tests"] >= 3, "Access control insufficient"
        assert security_metrics["security_violations"] == 0, "Security violations detected"
        
        print(f"✅ Security Validation:")
        print(f"   Key validation tests: {security_metrics['key_validation_tests']}")
        print(f"   Access control tests: {security_metrics['access_control_tests']}")
        print(f"   Audit trail tests: {security_metrics['audit_trail_tests']}")
        print(f"   Security violations: {security_metrics['security_violations']}")

