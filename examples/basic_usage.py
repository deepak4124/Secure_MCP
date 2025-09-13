"""
Basic Usage Example for MCP Security Framework

This example demonstrates the basic usage of the MCP Security Framework
with identity management, trust calculation, and secure tool execution.
"""

import asyncio
import time
from mcp_security_framework import (
    IdentityManager, TrustCalculator, MCPSecurityGateway,
    PolicyEngine, ToolRegistry, LangGraphSecurityAdapter,
    AgentType, TrustEventType
)


async def main():
    """Main example function"""
    print("🚀 MCP Security Framework - Basic Usage Example")
    print("=" * 50)
    
    # Initialize core components
    print("📦 Initializing core components...")
    identity_manager = IdentityManager()
    trust_calculator = TrustCalculator()
    mcp_gateway = MCPSecurityGateway()
    policy_engine = PolicyEngine()
    tool_registry = ToolRegistry()
    
    # Create security adapter
    security_adapter = LangGraphSecurityAdapter(
        identity_manager=identity_manager,
        trust_calculator=trust_calculator,
        policy_engine=policy_engine,
        mcp_gateway=mcp_gateway,
        tool_registry=tool_registry
    )
    
    print("✅ Core components initialized")
    
    # Register agents
    print("\n👥 Registering agents...")
    agents = [
        {
            "agent_id": "researcher_001",
            "agent_type": "worker",
            "capabilities": ["data_analysis", "report_generation", "tool_execution"],
            "metadata": {"department": "research", "clearance_level": "confidential"}
        },
        {
            "agent_id": "coordinator_001",
            "agent_type": "coordinator",
            "capabilities": ["task_coordination", "resource_management", "tool_execution"],
            "metadata": {"department": "management", "clearance_level": "secret"}
        },
        {
            "agent_id": "monitor_001",
            "agent_type": "monitor",
            "capabilities": ["security_monitoring", "audit_logging", "tool_execution"],
            "metadata": {"department": "security", "clearance_level": "top_secret"}
        }
    ]
    
    for agent_info in agents:
        success, message = await security_adapter.register_agent(**agent_info)
        if success:
            print(f"✅ Registered {agent_info['agent_id']}: {message}")
        else:
            print(f"❌ Failed to register {agent_info['agent_id']}: {message}")
    
    # Authenticate agents
    print("\n🔐 Authenticating agents...")
    for agent_info in agents:
        authenticated = await security_adapter.authenticate_agent(
            agent_id=agent_info["agent_id"],
            credentials={"auth_token": f"langgraph_{agent_info['agent_id']}"}
        )
        if authenticated:
            print(f"✅ Authenticated {agent_info['agent_id']}")
        else:
            print(f"❌ Authentication failed for {agent_info['agent_id']}")
    
    # Register and verify tools
    print("\n🔧 Registering and verifying tools...")
    from mcp_security_framework.core.registry import ToolManifest, ToolStatus
    
    tools = [
        ToolManifest(
            tool_id="data_analyzer",
            name="Data Analyzer",
            version="1.0.0",
            description="Analyzes datasets and generates insights",
            author="Research Team",
            capabilities=["data_analysis", "statistical_computation"],
            parameters={
                "dataset": {"type": "string", "required": True},
                "analysis_type": {"type": "string", "required": True}
            },
            risk_level="low",
            security_requirements=["data_encryption", "access_logging"],
            dependencies=["pandas", "numpy"]
        ),
        ToolManifest(
            tool_id="report_generator",
            name="Report Generator",
            version="1.0.0",
            description="Generates formatted reports from analysis results",
            author="Research Team",
            capabilities=["report_generation", "document_creation"],
            parameters={
                "data": {"type": "object", "required": True},
                "format": {"type": "string", "required": True}
            },
            risk_level="low",
            security_requirements=["access_logging"],
            dependencies=["jinja2", "markdown"]
        ),
        ToolManifest(
            tool_id="system_monitor",
            name="System Monitor",
            version="1.0.0",
            description="Monitors system resources and performance",
            author="Security Team",
            capabilities=["system_monitoring", "performance_analysis"],
            parameters={
                "metrics": {"type": "array", "required": True},
                "duration": {"type": "integer", "required": True}
            },
            risk_level="medium",
            security_requirements=["privileged_access", "audit_logging"],
            dependencies=["psutil", "prometheus_client"]
        )
    ]
    
    for tool in tools:
        success, message = tool_registry.register_tool(tool)
        if success:
            print(f"✅ Registered tool {tool.tool_id}: {message}")
            
            # Verify tool
            verified, verify_message = tool_registry.verify_tool(tool.tool_id)
            if verified:
                print(f"✅ Verified tool {tool.tool_id}: {verify_message}")
            else:
                print(f"⚠️ Tool verification failed {tool.tool_id}: {verify_message}")
        else:
            print(f"❌ Failed to register tool {tool.tool_id}: {message}")
    
    # Simulate trust events
    print("\n📊 Simulating trust events...")
    trust_events = [
        {
            "agent_id": "researcher_001",
            "event_type": "task_success",
            "event_data": {
                "value": 0.8,
                "context": {"task": "data_analysis", "quality": "high", "timeliness": "excellent"}
            }
        },
        {
            "agent_id": "researcher_001",
            "event_type": "cooperation_positive",
            "event_data": {
                "value": 0.7,
                "context": {"collaboration": "team_work", "helpfulness": "high"},
                "source_agent": "coordinator_001"
            }
        },
        {
            "agent_id": "coordinator_001",
            "event_type": "task_success",
            "event_data": {
                "value": 0.9,
                "context": {"task": "resource_allocation", "efficiency": "excellent"}
            }
        },
        {
            "agent_id": "monitor_001",
            "event_type": "security_violation",
            "event_data": {
                "value": 0.1,
                "context": {"violation": "unauthorized_access_attempt", "severity": "medium"}
            }
        }
    ]
    
    for event in trust_events:
        success = await security_adapter.report_trust_event(**event)
        if success:
            print(f"✅ Reported trust event for {event['agent_id']}: {event['event_type']}")
        else:
            print(f"❌ Failed to report trust event for {event['agent_id']}")
    
    # Display trust scores
    print("\n📈 Current trust scores:")
    for agent_info in agents:
        trust_score = trust_calculator.get_trust_score(agent_info["agent_id"])
        if trust_score:
            print(f"  {agent_info['agent_id']}: {trust_score.overall_score:.3f} "
                  f"(confidence: {trust_score.confidence:.3f}, events: {trust_score.event_count})")
        else:
            print(f"  {agent_info['agent_id']}: No trust score available")
    
    # Test tool access control
    print("\n🔒 Testing tool access control...")
    test_cases = [
        {
            "agent_id": "researcher_001",
            "tool_id": "data_analyzer",
            "operation": "execute",
            "parameters": {"dataset": "research_data.csv", "analysis_type": "statistical"}
        },
        {
            "agent_id": "researcher_001",
            "tool_id": "system_monitor",
            "operation": "execute",
            "parameters": {"metrics": ["cpu", "memory"], "duration": 60}
        },
        {
            "agent_id": "monitor_001",
            "tool_id": "system_monitor",
            "operation": "execute",
            "parameters": {"metrics": ["cpu", "memory", "network"], "duration": 300}
        }
    ]
    
    for test_case in test_cases:
        allowed, reason = await security_adapter.request_tool_access(**test_case)
        status = "✅ ALLOWED" if allowed else "❌ DENIED"
        print(f"  {test_case['agent_id']} -> {test_case['tool_id']}: {status} ({reason})")
    
    # Test secure tool execution
    print("\n⚡ Testing secure tool execution...")
    execution_test = {
        "agent_id": "researcher_001",
        "tool_id": "data_analyzer",
        "parameters": {"dataset": "sample_data.csv", "analysis_type": "descriptive"}
    }
    
    result = await security_adapter.execute_tool(**execution_test)
    if result.get("success"):
        print(f"✅ Tool execution successful: {result.get('result', 'No result data')}")
    else:
        print(f"❌ Tool execution failed: {result.get('error', 'Unknown error')}")
    
    # Display security events
    print("\n📋 Security events log:")
    events = security_adapter.get_security_events(limit=10)
    for event in events[-5:]:  # Show last 5 events
        timestamp = time.strftime("%H:%M:%S", time.localtime(event["timestamp"]))
        print(f"  [{timestamp}] {event['event_type']} - {event['agent_id']}: {event['details']}")
    
    # Display framework statistics
    print("\n📊 Framework statistics:")
    print(f"  Active agents: {len(security_adapter.list_active_agents())}")
    print(f"  Verified tools: {len(tool_registry.get_verified_tools())}")
    print(f"  Security events: {len(security_adapter.get_security_events())}")
    
    # Trust ranking
    print("\n🏆 Trust ranking:")
    ranking = trust_calculator.get_trust_ranking(limit=5)
    for i, (agent_id, score) in enumerate(ranking, 1):
        print(f"  {i}. {agent_id}: {score:.3f}")
    
    print("\n🎉 Basic usage example completed successfully!")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
