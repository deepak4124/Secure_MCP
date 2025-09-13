"""
MCP Security Framework Demo
A simplified demonstration of the framework capabilities without full installation
"""

import sys
import os
import time
import json
from typing import Dict, List, Any, Optional

# Add the framework to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mcp_security_framework'))

print("🚀 MCP Security Framework - Demo")
print("=" * 50)

# Simulate the framework components
class DemoIdentityManager:
    """Demo Identity Manager"""
    
    def __init__(self):
        self.identities = {}
        self.revoked_identities = set()
    
    def register_agent(self, agent_id: str, agent_type: str, capabilities: List[str]) -> tuple:
        """Register a new agent"""
        if agent_id in self.identities:
            return False, "Agent ID already exists"
        
        self.identities[agent_id] = {
            "agent_id": agent_id,
            "agent_type": agent_type,
            "capabilities": capabilities,
            "trust_score": 0.5,
            "status": "active",
            "created_at": time.time()
        }
        
        return True, "Agent registered successfully"
    
    def get_agent_identity(self, agent_id: str) -> Optional[Dict]:
        """Get agent identity"""
        return self.identities.get(agent_id)

class DemoTrustCalculator:
    """Demo Trust Calculator"""
    
    def __init__(self):
        self.trust_events = {}
        self.trust_scores = {}
    
    def add_trust_event(self, agent_id: str, event_type: str, value: float) -> bool:
        """Add trust event"""
        if agent_id not in self.trust_events:
            self.trust_events[agent_id] = []
        
        event = {
            "event_type": event_type,
            "value": value,
            "timestamp": time.time()
        }
        
        self.trust_events[agent_id].append(event)
        
        # Calculate new trust score
        events = self.trust_events[agent_id]
        if len(events) >= 3:
            avg_score = sum(e["value"] for e in events[-5:]) / min(5, len(events))
            self.trust_scores[agent_id] = max(0.0, min(1.0, avg_score))
        
        return True
    
    def get_trust_score(self, agent_id: str) -> Optional[Dict]:
        """Get trust score"""
        if agent_id in self.trust_scores:
            return {
                "agent_id": agent_id,
                "overall_score": self.trust_scores[agent_id],
                "confidence": min(1.0, len(self.trust_events.get(agent_id, [])) / 10),
                "event_count": len(self.trust_events.get(agent_id, []))
            }
        return None

class DemoMCPSecurityGateway:
    """Demo MCP Security Gateway"""
    
    def __init__(self):
        self.verified_tools = {}
        self.audit_log = []
    
    def register_tool(self, tool_id: str, name: str, risk_level: str) -> bool:
        """Register a tool"""
        self.verified_tools[tool_id] = {
            "tool_id": tool_id,
            "name": name,
            "risk_level": risk_level,
            "status": "verified",
            "verified_at": time.time()
        }
        return True
    
    def execute_tool(self, tool_id: str, agent_id: str, parameters: Dict) -> Dict:
        """Execute a tool"""
        if tool_id not in self.verified_tools:
            return {"success": False, "error": "Tool not found"}
        
        # Log execution
        self.audit_log.append({
            "timestamp": time.time(),
            "agent_id": agent_id,
            "tool_id": tool_id,
            "parameters": parameters,
            "action": "tool_execution"
        })
        
        return {
            "success": True,
            "result": f"Tool {tool_id} executed successfully by {agent_id}",
            "execution_time": time.time()
        }

class DemoPolicyEngine:
    """Demo Policy Engine"""
    
    def __init__(self):
        self.policies = [
            {
                "name": "Trust Threshold Policy",
                "condition": "agent_trust_score < 0.3",
                "action": "deny",
                "reason": "Insufficient trust score"
            },
            {
                "name": "High Risk Tool Policy", 
                "condition": "tool_risk_level == 'critical'",
                "action": "deny",
                "reason": "Critical risk tool access denied"
            }
        ]
    
    def evaluate_access(self, agent_id: str, tool_id: str, agent_trust_score: float, tool_risk_level: str) -> tuple:
        """Evaluate access request"""
        # Check trust threshold
        if agent_trust_score < 0.3:
            return False, "Insufficient trust score"
        
        # Check high risk tools
        if tool_risk_level == "critical":
            return False, "Critical risk tool access denied"
        
        return True, "Access granted"

def main():
    """Main demo function"""
    print("📦 Initializing demo components...")
    
    # Initialize components
    identity_manager = DemoIdentityManager()
    trust_calculator = DemoTrustCalculator()
    mcp_gateway = DemoMCPSecurityGateway()
    policy_engine = DemoPolicyEngine()
    
    print("✅ Demo components initialized")
    
    # Register agents
    print("\n👥 Registering agents...")
    agents = [
        ("researcher_001", "worker", ["data_analysis", "report_generation"]),
        ("coordinator_001", "coordinator", ["task_coordination", "resource_management"]),
        ("monitor_001", "monitor", ["security_monitoring", "audit_logging"])
    ]
    
    for agent_id, agent_type, capabilities in agents:
        success, message = identity_manager.register_agent(agent_id, agent_type, capabilities)
        if success:
            print(f"✅ Registered {agent_id}: {message}")
        else:
            print(f"❌ Failed to register {agent_id}: {message}")
    
    # Register tools
    print("\n🔧 Registering tools...")
    tools = [
        ("data_analyzer", "Data Analyzer", "low"),
        ("report_generator", "Report Generator", "low"),
        ("system_monitor", "System Monitor", "high")
    ]
    
    for tool_id, name, risk_level in tools:
        success = mcp_gateway.register_tool(tool_id, name, risk_level)
        if success:
            print(f"✅ Registered tool {tool_id}: {name} (risk: {risk_level})")
        else:
            print(f"❌ Failed to register tool {tool_id}")
    
    # Simulate trust events
    print("\n📊 Simulating trust events...")
    trust_events = [
        ("researcher_001", "task_success", 0.8),
        ("researcher_001", "cooperation_positive", 0.7),
        ("coordinator_001", "task_success", 0.9),
        ("monitor_001", "security_violation", 0.1)
    ]
    
    for agent_id, event_type, value in trust_events:
        success = trust_calculator.add_trust_event(agent_id, event_type, value)
        if success:
            print(f"✅ Reported trust event for {agent_id}: {event_type} (value: {value})")
        else:
            print(f"❌ Failed to report trust event for {agent_id}")
    
    # Display trust scores
    print("\n📈 Current trust scores:")
    for agent_id, _, _ in agents:
        trust_score = trust_calculator.get_trust_score(agent_id)
        if trust_score:
            print(f"  {agent_id}: {trust_score['overall_score']:.3f} "
                  f"(confidence: {trust_score['confidence']:.3f}, events: {trust_score['event_count']})")
        else:
            print(f"  {agent_id}: No trust score available")
    
    # Test access control
    print("\n🔒 Testing access control...")
    test_cases = [
        ("researcher_001", "data_analyzer", "low"),
        ("researcher_001", "system_monitor", "high"),
        ("monitor_001", "system_monitor", "high")
    ]
    
    for agent_id, tool_id, tool_risk in test_cases:
        agent_identity = identity_manager.get_agent_identity(agent_id)
        trust_score = trust_calculator.get_trust_score(agent_id)
        
        if agent_identity and trust_score:
            allowed, reason = policy_engine.evaluate_access(
                agent_id, tool_id, trust_score['overall_score'], tool_risk
            )
            status = "✅ ALLOWED" if allowed else "❌ DENIED"
            print(f"  {agent_id} -> {tool_id}: {status} ({reason})")
        else:
            print(f"  {agent_id} -> {tool_id}: ❌ DENIED (No identity or trust score)")
    
    # Test tool execution
    print("\n⚡ Testing tool execution...")
    execution_test = ("researcher_001", "data_analyzer", {"dataset": "sample_data.csv"})
    
    agent_id, tool_id, parameters = execution_test
    result = mcp_gateway.execute_tool(tool_id, agent_id, parameters)
    
    if result.get("success"):
        print(f"✅ Tool execution successful: {result.get('result')}")
    else:
        print(f"❌ Tool execution failed: {result.get('error')}")
    
    # Display audit log
    print("\n📋 Audit log:")
    for log_entry in mcp_gateway.audit_log[-3:]:  # Show last 3 entries
        timestamp = time.strftime("%H:%M:%S", time.localtime(log_entry["timestamp"]))
        print(f"  [{timestamp}] {log_entry['action']} - {log_entry['agent_id']} -> {log_entry['tool_id']}")
    
    # Framework statistics
    print("\n📊 Framework statistics:")
    print(f"  Registered agents: {len(identity_manager.identities)}")
    print(f"  Verified tools: {len(mcp_gateway.verified_tools)}")
    print(f"  Audit log entries: {len(mcp_gateway.audit_log)}")
    print(f"  Trust events: {sum(len(events) for events in trust_calculator.trust_events.values())}")
    
    print("\n🎉 Demo completed successfully!")
    print("=" * 50)
    print("\nThis demo shows the core capabilities of the MCP Security Framework:")
    print("• Identity management and agent registration")
    print("• Trust calculation and behavioral analysis")
    print("• Tool verification and secure execution")
    print("• Policy-based access control")
    print("• Comprehensive audit logging")
    print("\nThe full framework includes additional features like:")
    print("• Cryptographic identity verification")
    print("• Advanced sybil and collusion detection")
    print("• Multi-MAS framework adapters (LangGraph, AutoGen, CrewAI)")
    print("• Real-time threat detection and monitoring")
    print("• Production-ready deployment and scaling")

if __name__ == "__main__":
    main()
