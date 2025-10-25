import asyncio
import time
from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry

async def monitor_framework():
    """Monitor framework in real-time"""
    
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
    
    print("🔍 Starting real-time framework monitoring...")
    print("Press Ctrl+C to stop monitoring")
    
    try:
        while True:
            metrics = framework.get_real_time_metrics()
            print(f"📊 Real-time Metrics: {metrics}")
            await asyncio.sleep(5)  # Update every 5 seconds
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user")

if __name__ == "__main__":
    asyncio.run(monitor_framework())
