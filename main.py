import asyncio
import logging
import json
from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
from mcp_security_framework.benchmarking.real_benchmarker import RealBenchmarkRunner
from mcp_security_framework.benchmarking import BenchmarkConfig, BenchmarkScope

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    """Main application with real framework"""
    
    # 1. Initialize real framework components
    logger.info("Initializing MCP Security Framework...")
    
    identity_manager = IdentityManager()
    trust_calculator = TrustCalculator()
    policy_engine = PolicyEngine()
    tool_registry = ToolRegistry()
    
    # 2. Create real security gateway
    framework = RealMCPSecurityGateway(
        identity_manager=identity_manager,
        trust_calculator=trust_calculator,
        policy_engine=policy_engine,
        tool_registry=tool_registry
    )
    
    # 3. Register some test agents
    from mcp_security_framework.core.identity import AgentType
    for i in range(5):
        agent_id = f"agent_{i}"
        identity_manager.register_agent(
            agent_id=agent_id,
            public_key=f"public_key_{i}".encode(),
            agent_type=AgentType.WORKER,
            capabilities=["basic_operations"],
            metadata={"role": "user", "department": "engineering"}
        )
    
    # 4. Run real benchmark
    logger.info("Running real benchmark...")
    
    benchmark_config = BenchmarkConfig(
        scope=BenchmarkScope.COMPREHENSIVE,
        iterations=5
    )
    
    benchmark_runner = RealBenchmarkRunner(benchmark_config)
    results = await benchmark_runner.run_real_benchmark(framework)
    
    # 5. Display results
    logger.info("Benchmark Results:")
    logger.info(f"Security Results: {results['security_results']}")
    logger.info(f"Performance Results: {results['performance_results']}")
    logger.info(f"Trust Results: {results['trust_results']}")
    logger.info(f"Real Metrics: {results['real_metrics']}")
    
    # 6. Save results
    with open("real_benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    logger.info("Results saved to real_benchmark_results.json")

if __name__ == "__main__":
    asyncio.run(main())
