"""
Integration tests for Benchmarking System
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, MagicMock
from mcp_security_framework.benchmarking import (
    BenchmarkRunner, BenchmarkConfig, BenchmarkScope, BenchmarkResult
)
from mcp_security_framework.benchmarking.real_benchmarker import RealBenchmarkRunner
from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
from mcp_security_framework.core.identity import AgentType
from mcp_security_framework.core.gateway import RequestContext


class TestBenchmarkingIntegration:
    """Integration tests for the benchmarking system"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Mock the real models
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
            
            self.benchmark_runner = RealBenchmarkRunner()
    
    def test_benchmark_config_creation(self):
        """Test benchmark configuration creation"""
        config = BenchmarkConfig(
            scope=BenchmarkScope.COMPREHENSIVE,
            iterations=5,
            timeout=30,
            concurrent_requests=10
        )
        
        assert config.scope == BenchmarkScope.COMPREHENSIVE
        assert config.iterations == 5
        assert config.timeout == 30
        assert config.concurrent_requests == 10
    
    def test_benchmark_scope_enum(self):
        """Test benchmark scope enumeration"""
        scopes = [
            BenchmarkScope.SECURITY_ONLY,
            BenchmarkScope.PERFORMANCE_ONLY,
            BenchmarkScope.TRUST_ONLY,
            BenchmarkScope.COMPREHENSIVE
        ]
        
        for scope in scopes:
            assert isinstance(scope, BenchmarkScope)
            assert hasattr(scope, 'value')
    
    @pytest.mark.asyncio
    async def test_real_security_benchmark(self):
        """Test real security benchmarking"""
        # Mock the security model
        self.real_gateway.real_security_model.detect_threat.return_value = {
            "threat_level": "safe",
            "confidence": 0.9,
            "is_threat": False
        }
        
        # Run security benchmark
        security_results = await self.benchmark_runner._run_real_security_benchmark(self.real_gateway)
        
        # Verify results structure
        assert isinstance(security_results, dict)
        assert "total_tests" in security_results
        assert "threats_detected" in security_results
        assert "false_positives" in security_results
        assert "false_negatives" in security_results
        assert "detection_accuracy" in security_results
        
        # Verify values
        assert security_results["total_tests"] > 0
        assert 0.0 <= security_results["detection_accuracy"] <= 1.0
    
    @pytest.mark.asyncio
    async def test_real_performance_benchmark(self):
        """Test real performance benchmarking"""
        # Mock the gateway to return quickly
        async def mock_process_request(agent_id, request):
            await asyncio.sleep(0.001)  # Simulate processing time
            return Mock()
        
        self.real_gateway.process_request = mock_process_request
        
        # Run performance benchmark
        performance_results = await self.benchmark_runner._run_real_performance_benchmark(self.real_gateway)
        
        # Verify results structure
        assert isinstance(performance_results, dict)
        assert "total_requests" in performance_results
        assert "successful_requests" in performance_results
        assert "duration" in performance_results
        assert "throughput" in performance_results
        assert "average_response_time" in performance_results
        
        # Verify values
        assert performance_results["total_requests"] > 0
        assert performance_results["successful_requests"] > 0
        assert performance_results["duration"] > 0
        assert performance_results["throughput"] > 0
        assert performance_results["average_response_time"] > 0
    
    @pytest.mark.asyncio
    async def test_real_trust_benchmark(self):
        """Test real trust benchmarking"""
        # Mock the trust model
        self.benchmark_runner.real_trust_model.calculate_trust_score.return_value = 0.8
        
        # Run trust benchmark
        trust_results = await self.benchmark_runner._run_real_trust_benchmark(self.real_gateway)
        
        # Verify results structure
        assert isinstance(trust_results, dict)
        assert "trust_scores" in trust_results
        assert "average_trust" in trust_results
        assert "trust_variance" in trust_results
        
        # Verify values
        assert isinstance(trust_results["trust_scores"], dict)
        assert len(trust_results["trust_scores"]) > 0
        assert 0.0 <= trust_results["average_trust"] <= 1.0
        assert trust_results["trust_variance"] >= 0.0
    
    @pytest.mark.asyncio
    async def test_comprehensive_benchmark(self):
        """Test comprehensive benchmark execution"""
        # Mock all models
        self.real_gateway.real_security_model.detect_threat.return_value = {
            "threat_level": "safe",
            "confidence": 0.9,
            "is_threat": False
        }
        self.real_gateway.real_trust_model.calculate_trust_score.return_value = 0.8
        self.benchmark_runner.real_trust_model.calculate_trust_score.return_value = 0.8
        
        # Mock gateway processing
        async def mock_process_request(agent_id, request):
            await asyncio.sleep(0.001)
            return Mock()
        
        self.real_gateway.process_request = mock_process_request
        
        # Run comprehensive benchmark
        results = await self.benchmark_runner.run_real_benchmark(self.real_gateway)
        
        # Verify results structure
        assert isinstance(results, dict)
        assert "security_results" in results
        assert "performance_results" in results
        assert "trust_results" in results
        assert "real_metrics" in results
        assert "timestamp" in results
        
        # Verify each component
        assert isinstance(results["security_results"], dict)
        assert isinstance(results["performance_results"], dict)
        assert isinstance(results["trust_results"], dict)
        assert isinstance(results["real_metrics"], dict)
        assert isinstance(results["timestamp"], float)
    
    def test_real_metrics_generation(self):
        """Test real metrics generation"""
        # Mock gateway metrics
        self.real_gateway.get_real_time_metrics.return_value = {
            "requests_processed": 100,
            "threats_detected": 5,
            "average_response_time": 0.1,
            "threat_detection_rate": 0.05,
            "throughput": 1000
        }
        
        # Generate real metrics
        real_metrics = self.benchmark_runner._generate_real_metrics(self.real_gateway)
        
        # Verify structure
        assert isinstance(real_metrics, dict)
        assert "framework_metrics" in real_metrics
        assert "model_performance" in real_metrics
        assert "system_metrics" in real_metrics
        
        # Verify framework metrics
        framework_metrics = real_metrics["framework_metrics"]
        assert framework_metrics["requests_processed"] == 100
        assert framework_metrics["threats_detected"] == 5
        assert framework_metrics["average_response_time"] == 0.1
        assert framework_metrics["threat_detection_rate"] == 0.05
        assert framework_metrics["throughput"] == 1000
        
        # Verify model performance
        model_performance = real_metrics["model_performance"]
        assert "trust_model_loaded" in model_performance
        assert "security_model_loaded" in model_performance
        
        # Verify system metrics
        system_metrics = real_metrics["system_metrics"]
        assert "memory_usage" in system_metrics
        assert "cpu_usage" in system_metrics
        assert "gpu_usage" in system_metrics
    
    def test_benchmark_result_creation(self):
        """Test benchmark result creation"""
        result = BenchmarkResult(
            test_name="integration_test",
            success=True,
            duration=1.5,
            metrics={
                "throughput": 1000,
                "latency": 0.1,
                "accuracy": 0.95
            },
            errors=[]
        )
        
        assert result.test_name == "integration_test"
        assert result.success is True
        assert result.duration == 1.5
        assert result.metrics["throughput"] == 1000
        assert result.metrics["latency"] == 0.1
        assert result.metrics["accuracy"] == 0.95
        assert len(result.errors) == 0
    
    def test_benchmark_result_with_errors(self):
        """Test benchmark result with errors"""
        errors = ["Test error 1", "Test error 2"]
        
        result = BenchmarkResult(
            test_name="error_test",
            success=False,
            duration=0.5,
            metrics={},
            errors=errors
        )
        
        assert result.test_name == "error_test"
        assert result.success is False
        assert result.duration == 0.5
        assert len(result.errors) == 2
        assert result.errors[0] == "Test error 1"
        assert result.errors[1] == "Test error 2"
    
    @pytest.mark.asyncio
    async def test_benchmark_timeout_handling(self):
        """Test benchmark timeout handling"""
        # Create slow mock
        async def slow_process_request(agent_id, request):
            await asyncio.sleep(10)  # Longer than timeout
            return Mock()
        
        self.real_gateway.process_request = slow_process_request
        
        # Run benchmark with short timeout
        config = BenchmarkConfig(
            scope=BenchmarkScope.PERFORMANCE_ONLY,
            iterations=1,
            timeout=1  # 1 second timeout
        )
        
        benchmark_runner = RealBenchmarkRunner(config)
        
        # This should complete within timeout
        start_time = time.time()
        results = await benchmark_runner.run_real_benchmark(self.real_gateway)
        end_time = time.time()
        
        # Should complete within reasonable time (not wait for full 10 seconds)
        assert end_time - start_time < 5.0
        assert isinstance(results, dict)
    
    def test_benchmark_concurrent_execution(self):
        """Test benchmark concurrent execution"""
        # Mock concurrent processing
        async def mock_concurrent_process(agent_id, request):
            await asyncio.sleep(0.01)  # Small delay
            return Mock()
        
        self.real_gateway.process_request = mock_concurrent_process
        
        # Test concurrent execution
        async def test_concurrent():
            tasks = []
            for i in range(10):
                request = RequestContext(
                    operation=f"operation_{i}",
                    resource=f"resource_{i}",
                    agent_id=f"agent_{i}"
                )
                task = self.real_gateway.process_request(f"agent_{i}", request)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
        
        # Run concurrent test
        results = asyncio.run(test_concurrent())
        
        # Verify all tasks completed
        assert len(results) == 10
        # All should be successful (no exceptions)
        for result in results:
            assert not isinstance(result, Exception)
    
    def test_benchmark_metrics_aggregation(self):
        """Test benchmark metrics aggregation"""
        # Create multiple benchmark results
        results = [
            BenchmarkResult(
                test_name="test_1",
                success=True,
                duration=1.0,
                metrics={"throughput": 100, "latency": 0.1},
                errors=[]
            ),
            BenchmarkResult(
                test_name="test_2",
                success=True,
                duration=2.0,
                metrics={"throughput": 200, "latency": 0.2},
                errors=[]
            ),
            BenchmarkResult(
                test_name="test_3",
                success=False,
                duration=0.5,
                metrics={"throughput": 50, "latency": 0.05},
                errors=["Test error"]
            )
        ]
        
        # Aggregate metrics
        aggregated = self.benchmark_runner._aggregate_metrics(results)
        
        # Verify aggregation
        assert "total_tests" in aggregated
        assert "successful_tests" in aggregated
        assert "failed_tests" in aggregated
        assert "average_duration" in aggregated
        assert "total_errors" in aggregated
        
        assert aggregated["total_tests"] == 3
        assert aggregated["successful_tests"] == 2
        assert aggregated["failed_tests"] == 1
        assert aggregated["average_duration"] == 1.17  # (1.0 + 2.0 + 0.5) / 3
        assert aggregated["total_errors"] == 1
    
    def test_benchmark_report_generation(self):
        """Test benchmark report generation"""
        # Create sample results
        results = {
            "security_results": {
                "total_tests": 10,
                "threats_detected": 8,
                "detection_accuracy": 0.9
            },
            "performance_results": {
                "total_requests": 1000,
                "successful_requests": 950,
                "throughput": 1000,
                "average_response_time": 0.1
            },
            "trust_results": {
                "average_trust": 0.8,
                "trust_variance": 0.1
            },
            "real_metrics": {
                "framework_metrics": {
                    "requests_processed": 1000,
                    "threats_detected": 50
                }
            },
            "timestamp": time.time()
        }
        
        # Generate report
        report = self.benchmark_runner._generate_report(results)
        
        # Verify report structure
        assert isinstance(report, dict)
        assert "summary" in report
        assert "security_metrics" in report
        assert "performance_metrics" in report
        assert "trust_metrics" in report
        assert "recommendations" in report
        assert "timestamp" in report
        
        # Verify summary
        summary = report["summary"]
        assert "overall_score" in summary
        assert "status" in summary
        assert "key_findings" in summary
        
        # Verify metrics sections
        assert isinstance(report["security_metrics"], dict)
        assert isinstance(report["performance_metrics"], dict)
        assert isinstance(report["trust_metrics"], dict)
        assert isinstance(report["recommendations"], list)

