"""
Benchmarking Demo for MCP Security Framework

This demo shows how to use the comprehensive benchmarking system to evaluate
the security framework's performance, security effectiveness, and compliance
capabilities.
"""

import asyncio
import time
import json
from typing import Dict, Any

# Import the benchmarking components
from mcp_security_framework.benchmarking import (
    BenchmarkRunner,
    BenchmarkConfig,
    BenchmarkScope,
    ReportFormat,
    ComplianceStandard
)

# Import the security framework components
from mcp_security_framework.core import (
    IdentityManager,
    TrustCalculator,
    PolicyEngine,
    ToolRegistry,
    MCPSecurityGateway
)

# Import enhanced security components
from mcp_security_framework.core.enhanced_gateway import EnhancedMCPSecurityGateway
from mcp_security_framework.security.advanced.dynamic_trust_manager import DynamicTrustManager
from mcp_security_framework.security.advanced.maestro_layer_security import MAESTROLayerSecurity
from mcp_security_framework.security.advanced.advanced_behavioral_analysis import AdvancedBehavioralAnalysis


class MockMCPSecurityFramework:
    """
    Mock implementation of the MCP Security Framework for demonstration purposes
    
    In a real implementation, this would be the actual framework instance
    with all security features enabled.
    """
    
    def __init__(self):
        """Initialize the mock framework"""
        self.name = "MCP Security Framework"
        self.version = "1.0.0"
        
        # Initialize core components
        self.identity_manager = IdentityManager()
        self.trust_calculator = TrustCalculator()
        self.policy_engine = PolicyEngine()
        self.tool_registry = ToolRegistry()
        
        # Initialize enhanced security components
        self.dynamic_trust_manager = DynamicTrustManager()
        self.maestro_security = MAESTROLayerSecurity()
        self.behavioral_analyzer = AdvancedBehavioralAnalysis()
        
        # Initialize the enhanced security gateway
        self.security_gateway = EnhancedMCPSecurityGateway(
            identity_manager=self.identity_manager,
            trust_calculator=self.trust_calculator,
            policy_engine=self.policy_engine,
            tool_registry=self.tool_registry,
            enable_dynamic_trust=True,
            enable_maestro_security=True,
            enable_behavioral_analysis=True
        )
        
        # Initialize some mock data
        self._initialize_mock_data()
    
    def _initialize_mock_data(self):
        """Initialize mock data for testing"""
        # Register some mock agents
        for i in range(10):
            agent_id = f"agent_{i}"
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"mock_public_key_{i}",
                metadata={"role": "user", "department": "engineering"}
            )
        
        # Register some mock tools
        for i in range(5):
            tool_id = f"tool_{i}"
            self.tool_registry.register_tool(
                tool_id=tool_id,
                name=f"Mock Tool {i}",
                description=f"Mock tool for testing {i}",
                security_level="standard"
            )
    
    async def process_request(self, agent_id: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a request through the security gateway
        
        Args:
            agent_id: ID of the agent making the request
            request: Request data
            
        Returns:
            Response data
        """
        # Simulate request processing through the security gateway
        response = await self.security_gateway.process_request(agent_id, request)
        return response
    
    async def authenticate_agent(self, agent_id: str, credentials: Dict[str, Any]) -> bool:
        """
        Authenticate an agent
        
        Args:
            agent_id: Agent ID
            credentials: Authentication credentials
            
        Returns:
            True if authentication successful, False otherwise
        """
        # Simulate authentication
        await asyncio.sleep(0.001)  # Simulate processing time
        return True
    
    async def calculate_trust_score(self, agent_id: str) -> float:
        """
        Calculate trust score for an agent
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Trust score (0.0 to 1.0)
        """
        # Simulate trust calculation
        await asyncio.sleep(0.005)  # Simulate processing time
        return 0.85  # Mock trust score
    
    async def evaluate_policy(self, agent_id: str, action: str, resource: str) -> bool:
        """
        Evaluate policy for an action
        
        Args:
            agent_id: Agent ID
            action: Action to perform
            resource: Resource to access
            
        Returns:
            True if action is allowed, False otherwise
        """
        # Simulate policy evaluation
        await asyncio.sleep(0.002)  # Simulate processing time
        return True
    
    async def execute_tool(self, tool_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool
        
        Args:
            tool_id: Tool ID
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Simulate tool execution
        await asyncio.sleep(0.010)  # Simulate processing time
        return {"result": "success", "data": "mock_result"}


async def run_security_benchmark_demo():
    """Run security benchmark demo"""
    print("🔒 Running Security Benchmark Demo...")
    
    # Create framework instance
    framework = MockMCPSecurityFramework()
    
    # Create benchmark configuration for security testing
    config = BenchmarkConfig(
        scope=BenchmarkScope.SECURITY_ONLY,
        iterations=5,  # Reduced for demo
        security_tests=["sybil_001", "collusion_001", "prompt_injection_001"],
        report_formats=[ReportFormat.JSON]
    )
    
    # Create benchmark runner
    runner = BenchmarkRunner(config)
    
    # Run security benchmark
    start_time = time.time()
    results = await runner.run_benchmark(framework, config)
    end_time = time.time()
    
    print(f"✅ Security benchmark completed in {end_time - start_time:.2f} seconds")
    print(f"📊 Results: {json.dumps(results, indent=2)}")
    
    return results


async def run_performance_benchmark_demo():
    """Run performance benchmark demo"""
    print("⚡ Running Performance Benchmark Demo...")
    
    # Create framework instance
    framework = MockMCPSecurityFramework()
    
    # Create benchmark configuration for performance testing
    config = BenchmarkConfig(
        scope=BenchmarkScope.PERFORMANCE_ONLY,
        iterations=3,  # Reduced for demo
        performance_tests=["auth_normal_load", "trust_calc_normal", "policy_eval_normal"],
        warmup_duration=30,  # Reduced for demo
        report_formats=[ReportFormat.JSON]
    )
    
    # Create benchmark runner
    runner = BenchmarkRunner(config)
    
    # Run performance benchmark
    start_time = time.time()
    results = await runner.run_benchmark(framework, config)
    end_time = time.time()
    
    print(f"✅ Performance benchmark completed in {end_time - start_time:.2f} seconds")
    print(f"📊 Results: {json.dumps(results, indent=2)}")
    
    return results


async def run_compliance_benchmark_demo():
    """Run compliance benchmark demo"""
    print("📋 Running Compliance Benchmark Demo...")
    
    # Create framework instance
    framework = MockMCPSecurityFramework()
    
    # Create benchmark configuration for compliance testing
    config = BenchmarkConfig(
        scope=BenchmarkScope.COMPLIANCE_ONLY,
        compliance_standards=[
            ComplianceStandard.GDPR,
            ComplianceStandard.HIPAA,
            ComplianceStandard.ISO_27001
        ],
        report_formats=[ReportFormat.JSON]
    )
    
    # Create benchmark runner
    runner = BenchmarkRunner(config)
    
    # Run compliance benchmark
    start_time = time.time()
    results = await runner.run_benchmark(framework, config)
    end_time = time.time()
    
    print(f"✅ Compliance benchmark completed in {end_time - start_time:.2f} seconds")
    print(f"📊 Results: {json.dumps(results, indent=2)}")
    
    return results


async def run_comprehensive_benchmark_demo():
    """Run comprehensive benchmark demo"""
    print("🎯 Running Comprehensive Benchmark Demo...")
    
    # Create framework instance
    framework = MockMCPSecurityFramework()
    
    # Create benchmark configuration for comprehensive testing
    config = BenchmarkConfig(
        scope=BenchmarkScope.COMPREHENSIVE,
        iterations=3,  # Reduced for demo
        warmup_duration=30,  # Reduced for demo
        security_tests=["sybil_001", "prompt_injection_001"],
        performance_tests=["auth_normal_load", "trust_calc_normal"],
        compliance_standards=[ComplianceStandard.GDPR, ComplianceStandard.ISO_27001],
        report_formats=[ReportFormat.JSON, ReportFormat.HTML],
        output_directory="./demo_benchmark_results"
    )
    
    # Create benchmark runner
    runner = BenchmarkRunner(config)
    
    # Run comprehensive benchmark
    start_time = time.time()
    results = await runner.run_benchmark(framework, config)
    end_time = time.time()
    
    print(f"✅ Comprehensive benchmark completed in {end_time - start_time:.2f} seconds")
    
    # Print summary
    summary = runner.get_benchmark_summary()
    print(f"📈 Benchmark Summary:")
    print(f"   - Total executions: {summary['total_executions']}")
    print(f"   - Successful executions: {summary['successful_executions']}")
    print(f"   - Overall score: {summary['metrics_summary']['overall_score']:.2f}")
    
    return results


async def run_custom_benchmark_demo():
    """Run custom benchmark demo"""
    print("🔧 Running Custom Benchmark Demo...")
    
    # Create framework instance
    framework = MockMCPSecurityFramework()
    
    # Create custom benchmark configuration
    config = BenchmarkConfig(
        scope=BenchmarkScope.CUSTOM,
        iterations=2,  # Reduced for demo
        security_tests=["sybil_001"],  # Only sybil attack testing
        performance_tests=["auth_normal_load"],  # Only authentication testing
        compliance_standards=[ComplianceStandard.GDPR],  # Only GDPR compliance
        report_formats=[ReportFormat.JSON],
        output_directory="./custom_benchmark_results"
    )
    
    # Create benchmark runner
    runner = BenchmarkRunner(config)
    
    # Run custom benchmark
    start_time = time.time()
    results = await runner.run_benchmark(framework, config)
    end_time = time.time()
    
    print(f"✅ Custom benchmark completed in {end_time - start_time:.2f} seconds")
    print(f"📊 Results: {json.dumps(results, indent=2)}")
    
    return results


async def run_benchmarking_metrics_demo():
    """Run benchmarking metrics demo"""
    print("📊 Running Benchmarking Metrics Demo...")
    
    # Create framework instance
    framework = MockMCPSecurityFramework()
    
    # Create benchmark runner
    runner = BenchmarkRunner()
    
    # Run a quick benchmark to collect metrics
    config = BenchmarkConfig(
        scope=BenchmarkScope.SECURITY_ONLY,
        iterations=2,
        security_tests=["sybil_001"],
        report_formats=[ReportFormat.JSON]
    )
    
    await runner.run_benchmark(framework, config)
    
    # Export metrics
    metrics_file = "./demo_metrics.json"
    runner.export_metrics(metrics_file)
    print(f"📁 Metrics exported to: {metrics_file}")
    
    # Get benchmark summary
    summary = runner.get_benchmark_summary()
    print(f"📈 Benchmark Summary:")
    print(f"   - Total executions: {summary['total_executions']}")
    print(f"   - Available security tests: {len(summary['available_tests']['security_tests'])}")
    print(f"   - Available performance tests: {len(summary['available_tests']['performance_tests'])}")
    print(f"   - Available compliance standards: {len(summary['available_tests']['compliance_standards'])}")
    
    # Get execution history
    history = runner.get_execution_history()
    print(f"📚 Execution History:")
    for execution in history:
        print(f"   - {execution['execution_id']}: {execution['status']} ({execution['duration']:.2f}s)")
    
    return summary


async def main():
    """Main demo function"""
    print("🚀 MCP Security Framework Benchmarking Demo")
    print("=" * 50)
    
    try:
        # Run individual benchmark demos
        print("\n1. Security Benchmark Demo")
        await run_security_benchmark_demo()
        
        print("\n2. Performance Benchmark Demo")
        await run_performance_benchmark_demo()
        
        print("\n3. Compliance Benchmark Demo")
        await run_compliance_benchmark_demo()
        
        print("\n4. Custom Benchmark Demo")
        await run_custom_benchmark_demo()
        
        print("\n5. Benchmarking Metrics Demo")
        await run_benchmarking_metrics_demo()
        
        print("\n6. Comprehensive Benchmark Demo")
        await run_comprehensive_benchmark_demo()
        
        print("\n✅ All benchmarking demos completed successfully!")
        print("\n📁 Check the following directories for results:")
        print("   - ./demo_benchmark_results/")
        print("   - ./custom_benchmark_results/")
        print("   - ./demo_metrics.json")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
