#!/usr/bin/env python3
"""
Run the real MCP Security Framework with benchmarking
"""

import asyncio
import sys
import os
import json
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def run_comprehensive_test():
    """Run comprehensive test of the real framework"""
    print("🚀 Starting MCP Security Framework with Real Models")
    print("=" * 60)
    
    try:
        # Import framework components
        from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
        from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
        from mcp_security_framework.benchmarking.real_benchmarker import RealBenchmarkRunner
        from mcp_security_framework.benchmarking import BenchmarkConfig, BenchmarkScope
        
        print("✅ Framework components imported successfully")
        
        # Initialize framework
        print("🔄 Initializing framework components...")
        identity_manager = IdentityManager()
        trust_calculator = TrustCalculator()
        policy_engine = PolicyEngine()
        tool_registry = ToolRegistry()
        
        framework = RealMCPSecurityGateway(
            identity_manager=identity_manager,
            trust_calculator=trust_calculator,
            policy_engine=policy_engine,
            tool_registry=tool_registry
        )
        
        print("✅ Framework initialized successfully")
        
        # Register test agents
        print("🔄 Registering test agents...")
        for i in range(10):
            agent_id = f"agent_{i}"
            identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"public_key_{i}",
                metadata={"role": "user", "department": "engineering"}
            )
        
        print("✅ Test agents registered")
        
        # Run comprehensive benchmark
        print("🔄 Running comprehensive benchmark...")
        benchmark_config = BenchmarkConfig(
            scope=BenchmarkScope.COMPREHENSIVE,
            iterations=3  # Reduced for faster execution
        )
        
        benchmark_runner = RealBenchmarkRunner(benchmark_config)
        results = await benchmark_runner.run_real_benchmark(framework)
        
        print("✅ Benchmark completed successfully")
        
        # Display results
        print("\n📊 BENCHMARK RESULTS")
        print("=" * 40)
        
        # Security Results
        security = results['security_results']
        print(f"🔒 Security Results:")
        print(f"   - Total Tests: {security['total_tests']}")
        print(f"   - Threats Detected: {security['threats_detected']}")
        print(f"   - Detection Accuracy: {security['detection_accuracy']:.2%}")
        print(f"   - False Positives: {security['false_positives']}")
        print(f"   - False Negatives: {security['false_negatives']}")
        
        # Performance Results
        performance = results['performance_results']
        print(f"\n⚡ Performance Results:")
        print(f"   - Total Requests: {performance['total_requests']}")
        print(f"   - Successful Requests: {performance['successful_requests']}")
        print(f"   - Throughput: {performance['throughput']:.2f} req/s")
        print(f"   - Average Response Time: {performance['average_response_time']:.3f}s")
        print(f"   - Duration: {performance['duration']:.2f}s")
        
        # Trust Results
        trust = results['trust_results']
        print(f"\n🤝 Trust Results:")
        print(f"   - Average Trust Score: {trust['average_trust']:.3f}")
        print(f"   - Trust Variance: {trust['trust_variance']:.3f}")
        print(f"   - Individual Scores: {trust['trust_scores']}")
        
        # Real Metrics
        real_metrics = results['real_metrics']
        print(f"\n📈 Real-time Metrics:")
        print(f"   - Framework Metrics: {real_metrics['framework_metrics']}")
        print(f"   - Model Performance: {real_metrics['model_performance']}")
        print(f"   - System Metrics: {real_metrics['system_metrics']}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"real_framework_results_{timestamp}.json"
        
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: {results_file}")
        
        # Calculate overall score
        overall_score = (
            security['detection_accuracy'] * 0.4 +
            min(1.0, performance['throughput'] / 1000) * 0.3 +
            trust['average_trust'] * 0.3
        )
        
        print(f"\n🎯 Overall Framework Score: {overall_score:.2%}")
        
        if overall_score >= 0.8:
            print("🌟 EXCELLENT: Framework performs above industry standards!")
        elif overall_score >= 0.6:
            print("✅ GOOD: Framework meets industry standards")
        elif overall_score >= 0.4:
            print("⚠️  ACCEPTABLE: Framework needs some improvements")
        else:
            print("❌ NEEDS IMPROVEMENT: Framework requires significant enhancements")
        
        return results
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("💡 Make sure you have installed all dependencies:")
        print("   pip install -r requirements_real.txt")
        return None
        
    except Exception as e:
        print(f"❌ Error running framework: {e}")
        import traceback
        traceback.print_exc()
        return None

async def run_quick_test():
    """Run a quick test without full benchmarking"""
    print("🚀 Quick Test of MCP Security Framework")
    print("=" * 40)
    
    try:
        from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
        from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
        from mcp_security_framework.core.gateway import RequestContext
        
        # Initialize framework
        identity_manager = IdentityManager()
        trust_calculator = TrustCalculator()
        policy_engine = PolicyEngine()
        tool_registry = ToolRegistry()
        
        framework = RealMCPSecurityGateway(
            identity_manager=identity_manager,
            trust_calculator=trust_calculator,
            policy_engine=policy_engine,
            tool_registry=tool_registry
        )
        
        # Register a test agent
        from mcp_security_framework.core.identity import AgentType
        identity_manager.register_agent(
            agent_id="test_agent",
            public_key=b"test_public_key",
            agent_type=AgentType.WORKER,
            capabilities=["basic_operations"],
            metadata={"role": "user", "department": "testing"}
        )
        
        # Test a request
        request = RequestContext(
            operation="test_operation",
            resource="test_resource",
            agent_id="test_agent"
        )
        
        response = await framework.process_request("test_agent", request)
        
        print(f"✅ Request processed successfully")
        print(f"   Status: {response.status}")
        print(f"   Message: {response.message}")
        
        # Get metrics
        metrics = framework.get_real_time_metrics()
        print(f"📊 Real-time Metrics: {metrics}")
        
        return True
        
    except Exception as e:
        print(f"❌ Quick test failed: {e}")
        return False

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        # Run quick test
        success = asyncio.run(run_quick_test())
        sys.exit(0 if success else 1)
    else:
        # Run comprehensive test
        results = asyncio.run(run_comprehensive_test())
        sys.exit(0 if results else 1)

if __name__ == "__main__":
    main()
