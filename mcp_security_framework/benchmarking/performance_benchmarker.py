"""
Performance Benchmarker for MCP Security Framework

This module provides comprehensive performance benchmarking capabilities including
throughput testing, latency measurement, resource utilization monitoring, and
scalability assessment.
"""

import time
import asyncio
import threading
import psutil
import statistics
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed

from pydantic import BaseModel, Field

from .metrics_collector import MetricsCollector, MetricCategory, MetricType


class LoadTestType(Enum):
    """Load test type enumeration"""
    NORMAL_LOAD = "normal_load"
    PEAK_LOAD = "peak_load"
    STRESS_LOAD = "stress_load"
    SPIKE_LOAD = "spike_load"
    ENDURANCE_LOAD = "endurance_load"


class OperationType(Enum):
    """Operation type enumeration"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TRUST_CALCULATION = "trust_calculation"
    POLICY_EVALUATION = "policy_evaluation"
    TOOL_EXECUTION = "tool_execution"
    DATA_ACCESS = "data_access"
    SECURITY_SCAN = "security_scan"
    INCIDENT_RESPONSE = "incident_response"


@dataclass
class PerformanceTest:
    """Performance test definition"""
    test_id: str
    test_type: LoadTestType
    operation_type: OperationType
    description: str
    duration: int  # seconds
    concurrency: int
    request_rate: int  # requests per second
    payload_size: int  # bytes


@dataclass
class PerformanceResult:
    """Performance test result"""
    test_id: str
    operation_type: OperationType
    start_time: float
    end_time: float
    duration: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    throughput: float  # requests per second
    average_latency: float  # milliseconds
    p95_latency: float  # milliseconds
    p99_latency: float  # milliseconds
    resource_utilization: Dict[str, float]
    errors: List[str] = field(default_factory=list)


class PerformanceBenchmarker:
    """
    Comprehensive performance benchmarking system
    
    Provides load testing, latency measurement, resource utilization monitoring,
    and scalability assessment for the MCP Security Framework.
    """
    
    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize performance benchmarker
        
        Args:
            metrics_collector: Metrics collector instance
        """
        self.metrics_collector = metrics_collector
        self.performance_tests: Dict[str, PerformanceTest] = {}
        self.test_results: List[PerformanceResult] = []
        self.resource_monitor = ResourceMonitor()
        
        # Initialize performance tests
        self._initialize_performance_tests()
    
    def _initialize_performance_tests(self) -> None:
        """Initialize predefined performance tests"""
        tests = [
            PerformanceTest(
                test_id="auth_normal_load",
                test_type=LoadTestType.NORMAL_LOAD,
                operation_type=OperationType.AUTHENTICATION,
                description="Normal load authentication testing",
                duration=300,  # 5 minutes
                concurrency=100,
                request_rate=1000,  # 1000 req/s
                payload_size=1024
            ),
            PerformanceTest(
                test_id="auth_peak_load",
                test_type=LoadTestType.PEAK_LOAD,
                operation_type=OperationType.AUTHENTICATION,
                description="Peak load authentication testing",
                duration=600,  # 10 minutes
                concurrency=500,
                request_rate=5000,  # 5000 req/s
                payload_size=1024
            ),
            PerformanceTest(
                test_id="auth_stress_load",
                test_type=LoadTestType.STRESS_LOAD,
                operation_type=OperationType.AUTHENTICATION,
                description="Stress load authentication testing",
                duration=900,  # 15 minutes
                concurrency=1000,
                request_rate=10000,  # 10000 req/s
                payload_size=1024
            ),
            PerformanceTest(
                test_id="trust_calc_normal",
                test_type=LoadTestType.NORMAL_LOAD,
                operation_type=OperationType.TRUST_CALCULATION,
                description="Normal load trust calculation testing",
                duration=300,
                concurrency=50,
                request_rate=500,
                payload_size=2048
            ),
            PerformanceTest(
                test_id="trust_calc_peak",
                test_type=LoadTestType.PEAK_LOAD,
                operation_type=OperationType.TRUST_CALCULATION,
                description="Peak load trust calculation testing",
                duration=600,
                concurrency=200,
                request_rate=2000,
                payload_size=2048
            ),
            PerformanceTest(
                test_id="policy_eval_normal",
                test_type=LoadTestType.NORMAL_LOAD,
                operation_type=OperationType.POLICY_EVALUATION,
                description="Normal load policy evaluation testing",
                duration=300,
                concurrency=100,
                request_rate=1000,
                payload_size=512
            ),
            PerformanceTest(
                test_id="policy_eval_peak",
                test_type=LoadTestType.PEAK_LOAD,
                operation_type=OperationType.POLICY_EVALUATION,
                description="Peak load policy evaluation testing",
                duration=600,
                concurrency=500,
                request_rate=5000,
                payload_size=512
            ),
            PerformanceTest(
                test_id="tool_exec_normal",
                test_type=LoadTestType.NORMAL_LOAD,
                operation_type=OperationType.TOOL_EXECUTION,
                description="Normal load tool execution testing",
                duration=300,
                concurrency=50,
                request_rate=200,
                payload_size=4096
            ),
            PerformanceTest(
                test_id="tool_exec_peak",
                test_type=LoadTestType.PEAK_LOAD,
                operation_type=OperationType.TOOL_EXECUTION,
                description="Peak load tool execution testing",
                duration=600,
                concurrency=200,
                request_rate=1000,
                payload_size=4096
            ),
            PerformanceTest(
                test_id="endurance_test",
                test_type=LoadTestType.ENDURANCE_LOAD,
                operation_type=OperationType.AUTHENTICATION,
                description="Endurance testing over extended period",
                duration=3600,  # 1 hour
                concurrency=100,
                request_rate=1000,
                payload_size=1024
            )
        ]
        
        for test in tests:
            self.performance_tests[test.test_id] = test
    
    async def run_performance_benchmark(
        self,
        framework_instance: Any,
        test_ids: Optional[List[str]] = None,
        warmup_duration: int = 60
    ) -> Dict[str, Any]:
        """
        Run comprehensive performance benchmark
        
        Args:
            framework_instance: Instance of the security framework to test
            test_ids: List of test IDs to run (None for all)
            warmup_duration: Warmup duration in seconds
            
        Returns:
            Dictionary containing benchmark results
        """
        if test_ids is None:
            test_ids = list(self.performance_tests.keys())
        
        benchmark_results = {
            "start_time": time.time(),
            "tests_run": len(test_ids),
            "warmup_duration": warmup_duration,
            "results": {},
            "summary": {}
        }
        
        # Warmup phase
        if warmup_duration > 0:
            await self._warmup_framework(framework_instance, warmup_duration)
        
        # Run performance tests
        for test_id in test_ids:
            if test_id not in self.performance_tests:
                continue
            
            test = self.performance_tests[test_id]
            test_result = await self._run_performance_test(
                framework_instance, test
            )
            benchmark_results["results"][test_id] = test_result
            self.test_results.append(test_result)
        
        # Calculate summary statistics
        benchmark_results["summary"] = self._calculate_performance_summary()
        benchmark_results["end_time"] = time.time()
        benchmark_results["duration"] = benchmark_results["end_time"] - benchmark_results["start_time"]
        
        return benchmark_results
    
    async def _warmup_framework(
        self,
        framework_instance: Any,
        duration: int
    ) -> None:
        """
        Warmup the framework before testing
        
        Args:
            framework_instance: Framework instance
            duration: Warmup duration in seconds
        """
        print(f"Warming up framework for {duration} seconds...")
        
        start_time = time.time()
        warmup_requests = 0
        
        while time.time() - start_time < duration:
            # Perform light operations to warm up the framework
            try:
                # Simulate authentication requests
                await self._simulate_authentication(framework_instance)
                warmup_requests += 1
                
                # Small delay to avoid overwhelming
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Warmup error: {e}")
        
        print(f"Warmup completed: {warmup_requests} requests")
    
    async def _run_performance_test(
        self,
        framework_instance: Any,
        test: PerformanceTest
    ) -> PerformanceResult:
        """
        Run a single performance test
        
        Args:
            framework_instance: Framework instance
            test: Performance test definition
            
        Returns:
            Performance test result
        """
        print(f"Running performance test: {test.test_id}")
        
        start_time = time.time()
        
        # Start resource monitoring
        self.resource_monitor.start_monitoring()
        
        # Run the test
        test_result = await self._execute_load_test(
            framework_instance, test
        )
        
        # Stop resource monitoring
        resource_utilization = self.resource_monitor.stop_monitoring()
        
        # Calculate final metrics
        end_time = time.time()
        duration = end_time - start_time
        
        test_result.start_time = start_time
        test_result.end_time = end_time
        test_result.duration = duration
        test_result.resource_utilization = resource_utilization
        
        # Collect metrics
        self._collect_performance_metrics(test, test_result)
        
        print(f"Test completed: {test_result.throughput:.2f} req/s, "
              f"{test_result.average_latency:.2f}ms avg latency")
        
        return test_result
    
    async def _execute_load_test(
        self,
        framework_instance: Any,
        test: PerformanceTest
    ) -> PerformanceResult:
        """
        Execute load test
        
        Args:
            framework_instance: Framework instance
            test: Performance test definition
            
        Returns:
            Performance test result
        """
        # Initialize result
        result = PerformanceResult(
            test_id=test.test_id,
            operation_type=test.operation_type,
            start_time=0.0,
            end_time=0.0,
            duration=0.0,
            total_requests=0,
            successful_requests=0,
            failed_requests=0,
            throughput=0.0,
            average_latency=0.0,
            p95_latency=0.0,
            p99_latency=0.0,
            resource_utilization={}
        )
        
        # Create request generator
        request_generator = self._create_request_generator(test)
        
        # Execute requests with concurrency control
        latencies = []
        errors = []
        
        with ThreadPoolExecutor(max_workers=test.concurrency) as executor:
            # Submit requests
            futures = []
            for _ in range(test.request_rate * test.duration):
                future = executor.submit(
                    self._execute_single_request,
                    framework_instance,
                    test,
                    next(request_generator)
                )
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    latency, success, error = future.result()
                    latencies.append(latency)
                    result.total_requests += 1
                    
                    if success:
                        result.successful_requests += 1
                    else:
                        result.failed_requests += 1
                        if error:
                            errors.append(error)
                            
                except Exception as e:
                    result.failed_requests += 1
                    errors.append(str(e))
        
        # Calculate statistics
        if latencies:
            result.average_latency = statistics.mean(latencies)
            result.p95_latency = self._calculate_percentile(latencies, 95)
            result.p99_latency = self._calculate_percentile(latencies, 99)
        
        result.throughput = result.total_requests / test.duration
        result.errors = errors
        
        return result
    
    def _create_request_generator(self, test: PerformanceTest):
        """Create request generator for the test"""
        def generator():
            while True:
                yield {
                    "operation": test.operation_type.value,
                    "payload_size": test.payload_size,
                    "timestamp": time.time()
                }
        return generator()
    
    def _execute_single_request(
        self,
        framework_instance: Any,
        test: PerformanceTest,
        request_data: Dict[str, Any]
    ) -> tuple[float, bool, Optional[str]]:
        """
        Execute a single request
        
        Args:
            framework_instance: Framework instance
            test: Performance test definition
            request_data: Request data
            
        Returns:
            Tuple of (latency, success, error)
        """
        start_time = time.time()
        
        try:
            # Simulate the operation based on type
            if test.operation_type == OperationType.AUTHENTICATION:
                success = self._simulate_authentication_sync(framework_instance, request_data)
            elif test.operation_type == OperationType.TRUST_CALCULATION:
                success = self._simulate_trust_calculation_sync(framework_instance, request_data)
            elif test.operation_type == OperationType.POLICY_EVALUATION:
                success = self._simulate_policy_evaluation_sync(framework_instance, request_data)
            elif test.operation_type == OperationType.TOOL_EXECUTION:
                success = self._simulate_tool_execution_sync(framework_instance, request_data)
            else:
                success = self._simulate_generic_operation_sync(framework_instance, request_data)
            
            latency = (time.time() - start_time) * 1000  # Convert to milliseconds
            return latency, success, None
            
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return latency, False, str(e)
    
    def _simulate_authentication_sync(
        self,
        framework_instance: Any,
        request_data: Dict[str, Any]
    ) -> bool:
        """Simulate authentication operation"""
        # In real implementation, this would call the actual authentication method
        # For simulation, we'll add some realistic processing time
        time.sleep(0.001)  # 1ms processing time
        return True
    
    def _simulate_trust_calculation_sync(
        self,
        framework_instance: Any,
        request_data: Dict[str, Any]
    ) -> bool:
        """Simulate trust calculation operation"""
        # In real implementation, this would call the actual trust calculation method
        time.sleep(0.005)  # 5ms processing time
        return True
    
    def _simulate_policy_evaluation_sync(
        self,
        framework_instance: Any,
        request_data: Dict[str, Any]
    ) -> bool:
        """Simulate policy evaluation operation"""
        # In real implementation, this would call the actual policy evaluation method
        time.sleep(0.002)  # 2ms processing time
        return True
    
    def _simulate_tool_execution_sync(
        self,
        framework_instance: Any,
        request_data: Dict[str, Any]
    ) -> bool:
        """Simulate tool execution operation"""
        # In real implementation, this would call the actual tool execution method
        time.sleep(0.010)  # 10ms processing time
        return True
    
    def _simulate_generic_operation_sync(
        self,
        framework_instance: Any,
        request_data: Dict[str, Any]
    ) -> bool:
        """Simulate generic operation"""
        time.sleep(0.001)  # 1ms processing time
        return True
    
    async def _simulate_authentication(
        self,
        framework_instance: Any
    ) -> bool:
        """Simulate authentication operation (async)"""
        # In real implementation, this would call the actual authentication method
        await asyncio.sleep(0.001)  # 1ms processing time
        return True
    
    def _calculate_percentile(self, values: List[float], percentile: int) -> float:
        """
        Calculate percentile of values
        
        Args:
            values: List of values
            percentile: Percentile to calculate (0-100)
            
        Returns:
            Percentile value
        """
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = int((percentile / 100.0) * (len(sorted_values) - 1))
        return sorted_values[index]
    
    def _collect_performance_metrics(
        self,
        test: PerformanceTest,
        result: PerformanceResult
    ) -> None:
        """
        Collect performance metrics
        
        Args:
            test: Performance test definition
            result: Performance test result
        """
        # Collect throughput metrics
        self.metrics_collector.collect_performance_metric(
            metric_id=f"throughput_{test.operation_type.value}_{test.test_type.value}",
            category=MetricCategory.THROUGHPUT,
            value=result.throughput,
            operation_type=test.operation_type.value,
            test_type=test.test_type.value,
            concurrency=test.concurrency
        )
        
        # Collect latency metrics
        self.metrics_collector.collect_performance_metric(
            metric_id=f"latency_{test.operation_type.value}_{test.test_type.value}",
            category=MetricCategory.RESPONSE_TIME,
            value=result.average_latency,
            operation_type=test.operation_type.value,
            test_type=test.test_type.value,
            concurrency=test.concurrency
        )
        
        # Collect resource utilization metrics
        for resource, utilization in result.resource_utilization.items():
            self.metrics_collector.collect_performance_metric(
                metric_id=f"resource_{resource}_{test.operation_type.value}",
                category=MetricCategory.RESOURCE_UTILIZATION,
                value=utilization,
                operation_type=test.operation_type.value,
                resource_type=resource,
                test_type=test.test_type.value
            )
    
    def _calculate_performance_summary(self) -> Dict[str, Any]:
        """
        Calculate overall performance summary
        
        Returns:
            Dictionary containing performance summary
        """
        if not self.test_results:
            return {}
        
        # Calculate overall statistics
        total_requests = sum(r.total_requests for r in self.test_results)
        successful_requests = sum(r.successful_requests for r in self.test_results)
        failed_requests = sum(r.failed_requests for r in self.test_results)
        
        throughputs = [r.throughput for r in self.test_results]
        latencies = [r.average_latency for r in self.test_results]
        
        # Calculate resource utilization averages
        resource_utilization = defaultdict(list)
        for result in self.test_results:
            for resource, utilization in result.resource_utilization.items():
                resource_utilization[resource].append(utilization)
        
        avg_resource_utilization = {}
        for resource, utilizations in resource_utilization.items():
            avg_resource_utilization[resource] = statistics.mean(utilizations)
        
        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "success_rate": successful_requests / total_requests if total_requests > 0 else 0.0,
            "average_throughput": statistics.mean(throughputs) if throughputs else 0.0,
            "max_throughput": max(throughputs) if throughputs else 0.0,
            "average_latency": statistics.mean(latencies) if latencies else 0.0,
            "max_latency": max(latencies) if latencies else 0.0,
            "average_resource_utilization": avg_resource_utilization,
            "test_breakdown": self._get_test_breakdown()
        }
    
    def _get_test_breakdown(self) -> Dict[str, Any]:
        """
        Get breakdown by test type and operation
        
        Returns:
            Dictionary containing test breakdown
        """
        breakdown = defaultdict(lambda: defaultdict(list))
        
        for result in self.test_results:
            test = self.performance_tests.get(result.test_id)
            if test:
                breakdown[test.test_type.value][test.operation_type.value].append({
                    "throughput": result.throughput,
                    "latency": result.average_latency,
                    "success_rate": result.successful_requests / result.total_requests if result.total_requests > 0 else 0.0
                })
        
        # Calculate averages for each category
        for test_type, operations in breakdown.items():
            for operation, results in operations.items():
                if results:
                    breakdown[test_type][operation] = {
                        "count": len(results),
                        "avg_throughput": statistics.mean([r["throughput"] for r in results]),
                        "avg_latency": statistics.mean([r["latency"] for r in results]),
                        "avg_success_rate": statistics.mean([r["success_rate"] for r in results])
                    }
        
        return dict(breakdown)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Get comprehensive performance report
        
        Returns:
            Dictionary containing performance report
        """
        return {
            "timestamp": time.time(),
            "total_tests": len(self.performance_tests),
            "tests_run": len(self.test_results),
            "summary": self._calculate_performance_summary(),
            "test_definitions": {
                test_id: {
                    "test_type": test.test_type.value,
                    "operation_type": test.operation_type.value,
                    "description": test.description,
                    "duration": test.duration,
                    "concurrency": test.concurrency,
                    "request_rate": test.request_rate
                }
                for test_id, test in self.performance_tests.items()
            },
            "metrics_summary": self.metrics_collector.get_metric_summary()
        }


class ResourceMonitor:
    """Resource utilization monitor"""
    
    def __init__(self):
        """Initialize resource monitor"""
        self.monitoring = False
        self.monitor_thread = None
        self.resource_data = []
        self.start_time = None
    
    def start_monitoring(self) -> None:
        """Start resource monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.resource_data = []
        self.start_time = time.time()
        
        self.monitor_thread = threading.Thread(target=self._monitor_resources)
        self.monitor_thread.start()
    
    def stop_monitoring(self) -> Dict[str, float]:
        """
        Stop resource monitoring and return average utilization
        
        Returns:
            Dictionary containing average resource utilization
        """
        if not self.monitoring:
            return {}
        
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join()
        
        if not self.resource_data:
            return {}
        
        # Calculate averages
        cpu_utilizations = [data["cpu"] for data in self.resource_data]
        memory_utilizations = [data["memory"] for data in self.resource_data]
        disk_utilizations = [data["disk"] for data in self.resource_data]
        network_utilizations = [data["network"] for data in self.resource_data]
        
        return {
            "cpu": statistics.mean(cpu_utilizations),
            "memory": statistics.mean(memory_utilizations),
            "disk": statistics.mean(disk_utilizations),
            "network": statistics.mean(network_utilizations)
        }
    
    def _monitor_resources(self) -> None:
        """Monitor system resources"""
        while self.monitoring:
            try:
                # Get system resource utilization
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                network = psutil.net_io_counters()
                
                resource_data = {
                    "timestamp": time.time(),
                    "cpu": cpu_percent,
                    "memory": memory.percent,
                    "disk": disk.percent,
                    "network": network.bytes_sent + network.bytes_recv
                }
                
                self.resource_data.append(resource_data)
                
                # Small delay to avoid excessive monitoring
                time.sleep(1)
                
            except Exception as e:
                print(f"Resource monitoring error: {e}")
                break
