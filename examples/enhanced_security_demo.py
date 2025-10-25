"""
Enhanced Security Demo for MCP Security Framework

This demo showcases the new advanced security features:
- Dynamic Trust Allocation
- MAESTRO Multi-Layer Security
- Advanced Behavioral Analysis
"""

import asyncio
import time
import json
from typing import Dict, List, Any

# Import enhanced security components
from mcp_security_framework.core.enhanced_gateway import (
    EnhancedMCPSecurityGateway,
    SecurityLevel,
    EnhancedSecurityContext
)

from mcp_security_framework.security.advanced import (
    DynamicTrustManager,
    TrustContext,
    TrustContextData,
    MAESTROLayerSecurity,
    SecurityLayer,
    AdvancedBehavioralAnalysis,
    BehaviorEvent,
    BehaviorSequence,
    BehaviorType
)


async def demo_dynamic_trust_allocation():
    """Demonstrate dynamic trust allocation system"""
    print("\n🔐 Dynamic Trust Allocation Demo")
    print("=" * 50)
    
    # Initialize dynamic trust manager
    trust_manager = DynamicTrustManager()
    
    # Simulate adding trust context data for different agents
    agents = ["agent_001", "agent_002", "agent_003"]
    
    for agent_id in agents:
        print(f"\n📊 Adding trust context for {agent_id}")
        
        # Add different types of trust context
        contexts = [
            TrustContextData(
                context_type=TrustContext.BEHAVIORAL,
                value=0.8 if agent_id == "agent_001" else 0.3,
                confidence=0.9,
                timestamp=time.time(),
                metadata={"source": "behavior_analysis"}
            ),
            TrustContextData(
                context_type=TrustContext.DEVICE,
                value=0.7 if agent_id == "agent_001" else 0.5,
                confidence=0.8,
                timestamp=time.time(),
                metadata={"device_type": "secure_server"}
            ),
            TrustContextData(
                context_type=TrustContext.NETWORK,
                value=0.9 if agent_id == "agent_001" else 0.4,
                confidence=0.7,
                timestamp=time.time(),
                metadata={"network_security": "encrypted"}
            )
        ]
        
        for context in contexts:
            trust_manager.add_trust_context(agent_id, context)
        
        # Get dynamic trust score
        trust_score = trust_manager.get_dynamic_trust_score(agent_id)
        if trust_score:
            print(f"  Overall Trust: {trust_score.overall_trust:.2f}")
            print(f"  Allocation Level: {trust_score.allocation_level.value}")
            print(f"  Confidence: {trust_score.confidence:.2f}")
            print(f"  Trust Trend: {trust_score.trust_trend:.2f}")
            print(f"  Risk Factors: {trust_score.risk_factors}")
    
    # Demonstrate permission allocation
    print(f"\n🔑 Permission Allocation Demo")
    requested_permissions = ["read_data", "write_data", "execute_tool", "admin_access"]
    
    for agent_id in agents:
        print(f"\n  Agent {agent_id} requesting permissions:")
        allocations = trust_manager.allocate_trust_based_permissions(agent_id, requested_permissions)
        
        for permission, granted in allocations.items():
            status = "✅ GRANTED" if granted else "❌ DENIED"
            print(f"    {permission}: {status}")
    
    # Get trust allocation analytics
    analytics = trust_manager.get_trust_allocation_analytics()
    print(f"\n📈 Trust Allocation Analytics:")
    print(f"  Total Agents: {analytics['total_agents']}")
    print(f"  Average Trust: {analytics['average_trust']:.2f}")
    print(f"  High Risk Agents: {analytics['high_risk_agents']}")
    print(f"  Risk Distribution: {analytics['risk_distribution']}")


async def demo_maestro_layer_security():
    """Demonstrate MAESTRO multi-layer security framework"""
    print("\n🏗️ MAESTRO Multi-Layer Security Demo")
    print("=" * 50)
    
    # Initialize MAESTRO security framework
    maestro_security = MAESTROLayerSecurity()
    
    # Prepare system data for assessment
    system_data = {
        'foundation_models': {
            'model_integrity': True,
            'prompt_validation': True,
            'output_filtering': True,
            'model_poisoning_detection': True
        },
        'agent_core': {
            'agent_authentication': True,
            'agent_authorization': True,
            'agent_isolation': True,
            'agent_monitoring': True
        },
        'tool_integration': {
            'tool_verification': True,
            'tool_sandboxing': True,
            'tool_monitoring': True,
            'tool_attestation': True
        },
        'operational_context': {
            'context_validation': True,
            'context_encryption': True,
            'context_monitoring': True,
            'context_isolation': True
        },
        'multi_agent_interaction': {
            'communication_encryption': True,
            'agent_authentication': True,
            'collusion_detection': True,
            'interaction_monitoring': True
        },
        'deployment_environment': {
            'infrastructure_hardening': True,
            'network_segmentation': True,
            'access_controls': True,
            'environment_monitoring': True
        },
        'agent_ecosystem': {
            'ecosystem_monitoring': True,
            'threat_intelligence': True,
            'incident_response': True,
            'governance_framework': True
        }
    }
    
    # Perform comprehensive security assessment
    print("🔍 Performing MAESTRO security assessment...")
    assessment = maestro_security.assess_security_across_layers(system_data)
    
    print(f"\n📊 MAESTRO Assessment Results:")
    print(f"  Overall Security Score: {assessment.overall_security_score:.2f}")
    print(f"  Critical Threats: {len(assessment.critical_threats)}")
    print(f"  Security Gaps: {len(assessment.security_gaps)}")
    
    print(f"\n🏗️ Layer-by-Layer Assessment:")
    for layer, layer_assessment in assessment.layer_assessments.items():
        print(f"  {layer.value}:")
        print(f"    Security Score: {layer_assessment.security_score:.2f}")
        print(f"    Vulnerabilities: {len(layer_assessment.vulnerabilities)}")
        print(f"    Controls Implemented: {len(layer_assessment.controls_implemented)}")
        print(f"    Controls Missing: {len(layer_assessment.controls_missing)}")
    
    print(f"\n⚠️ Critical Threats:")
    for threat in assessment.critical_threats:
        print(f"  - {threat.threat_type}: {threat.description}")
        print(f"    Severity: {threat.severity.value}")
        print(f"    Mitigation: {', '.join(threat.mitigation_strategies[:2])}")
    
    print(f"\n🔧 Priority Recommendations:")
    for i, recommendation in enumerate(assessment.priority_recommendations[:5], 1):
        print(f"  {i}. {recommendation}")
    
    # Get security trends
    trends = maestro_security.get_security_trends()
    print(f"\n📈 Security Trends:")
    print(f"  Trend: {trends['trend']}")
    print(f"  Trend Score: {trends['trend_score']:.2f}")


async def demo_advanced_behavioral_analysis():
    """Demonstrate advanced behavioral analysis system"""
    print("\n🧠 Advanced Behavioral Analysis Demo")
    print("=" * 50)
    
    # Initialize behavioral analyzer
    behavioral_analyzer = AdvancedBehavioralAnalysis()
    
    # Simulate different types of agent behavior
    agents = [
        {"id": "normal_agent", "behavior_type": "normal"},
        {"id": "suspicious_agent", "behavior_type": "suspicious"},
        {"id": "deceptive_agent", "behavior_type": "deceptive"}
    ]
    
    for agent in agents:
        print(f"\n🔍 Analyzing behavior for {agent['id']}")
        
        # Create behavior events based on agent type
        events = []
        base_time = time.time()
        
        if agent['behavior_type'] == "normal":
            # Normal behavior: regular, consistent patterns
            for i in range(10):
                events.append(BehaviorEvent(
                    event_id=f"event_{i}",
                    agent_id=agent['id'],
                    event_type="data_access",
                    timestamp=base_time + i * 60,  # Every minute
                    data={"action": "read", "resource": f"data_{i}"}
                ))
        
        elif agent['behavior_type'] == "suspicious":
            # Suspicious behavior: unusual timing and patterns
            for i in range(10):
                events.append(BehaviorEvent(
                    event_id=f"event_{i}",
                    agent_id=agent['id'],
                    event_type="data_access",
                    timestamp=base_time + i * 5,  # Every 5 seconds (unusual)
                    data={"action": "read", "resource": f"sensitive_data_{i}"}
                ))
        
        elif agent['behavior_type'] == "deceptive":
            # Deceptive behavior: inconsistent and evasive
            event_types = ["data_access", "tool_execution", "authentication"]
            for i in range(15):
                events.append(BehaviorEvent(
                    event_id=f"event_{i}",
                    agent_id=agent['id'],
                    event_type=event_types[i % len(event_types)],
                    timestamp=base_time + i * 30 + (i % 3) * 10,  # Irregular timing
                    data={"action": "mixed", "resource": f"data_{i}"}
                ))
        
        # Create behavior sequence
        behavior_sequence = BehaviorSequence(
            agent_id=agent['id'],
            events=events,
            start_time=base_time,
            end_time=base_time + len(events) * 60,
            sequence_type="analysis_demo"
        )
        
        # Perform behavioral analysis
        deception_assessment = behavioral_analyzer.analyze_behavior(behavior_sequence)
        
        print(f"  Deception Score: {deception_assessment.deception_score:.2f}")
        print(f"  Risk Level: {deception_assessment.risk_level}")
        print(f"  Confidence: {deception_assessment.confidence:.2f}")
        print(f"  Deception Indicators: {[ind.value for ind in deception_assessment.deception_indicators]}")
        print(f"  Evidence: {deception_assessment.evidence[:2]}")  # Show first 2 pieces of evidence
        
        # Predict behavioral evolution
        prediction = behavioral_analyzer.predict_behavioral_evolution(agent['id'], time_horizon=24)
        print(f"  Predicted Behavior: {prediction.predicted_behavior.value}")
        print(f"  Prediction Confidence: {prediction.confidence:.2f}")
        print(f"  Risk Assessment: {prediction.risk_assessment}")
    
    # Get behavioral analytics
    analytics = behavioral_analyzer.get_behavioral_analytics()
    print(f"\n📊 Behavioral Analytics:")
    print(f"  Total Agents: {analytics['total_agents']}")
    print(f"  Average Deception Score: {analytics['average_deception_score']:.2f}")
    print(f"  High Risk Agents: {analytics['high_risk_agents']}")
    print(f"  Risk Distribution: {analytics['risk_distribution']}")
    print(f"  Deception Indicators: {analytics['deception_indicators']}")


async def demo_enhanced_security_gateway():
    """Demonstrate enhanced security gateway with all advanced features"""
    print("\n🚀 Enhanced Security Gateway Demo")
    print("=" * 50)
    
    # Initialize enhanced security gateway
    gateway = EnhancedMCPSecurityGateway(
        security_level=SecurityLevel.ENHANCED,
        enable_dynamic_trust=True,
        enable_maestro_security=True,
        enable_behavioral_analysis=True
    )
    
    # Simulate different types of requests
    test_requests = [
        {
            "type": "authentication",
            "agent_id": "trusted_agent",
            "credentials": "valid_credentials",
            "complexity": "low"
        },
        {
            "type": "tool_execution",
            "agent_id": "suspicious_agent",
            "tool": "sensitive_tool",
            "parameters": {"access_level": "high"},
            "complexity": "high"
        },
        {
            "type": "data_access",
            "agent_id": "new_agent",
            "resource": "public_data",
            "complexity": "medium"
        }
    ]
    
    print("🔐 Processing requests through enhanced security gateway...")
    
    for i, request in enumerate(test_requests, 1):
        print(f"\n📝 Request {i}: {request['type']} from {request['agent_id']}")
        
        # Process request through enhanced gateway
        response = await gateway.process_request(request['agent_id'], request)
        
        print(f"  Success: {response.get('success', False)}")
        print(f"  Security Context:")
        security_context = response.get('security_context', {})
        print(f"    Request ID: {security_context.get('request_id', 'N/A')}")
        print(f"    Security Level: {security_context.get('security_level', 'N/A')}")
        print(f"    Dynamic Trust Score: {security_context.get('dynamic_trust_score', 'N/A')}")
        print(f"    Risk Factors: {security_context.get('risk_factors', [])}")
        print(f"    Recommendations: {security_context.get('recommendations', [])[:2]}")  # Show first 2
    
    # Get enhanced security analytics
    analytics = gateway.get_enhanced_security_analytics()
    print(f"\n📊 Enhanced Security Analytics:")
    print(f"  Security Level: {analytics['security_level']}")
    print(f"  Advanced Features: {analytics['advanced_features']}")
    print(f"  Security Metrics:")
    for metric, value in analytics['security_metrics'].items():
        print(f"    {metric}: {value}")
    
    if 'dynamic_trust_analytics' in analytics:
        print(f"  Dynamic Trust Analytics:")
        trust_analytics = analytics['dynamic_trust_analytics']
        print(f"    Total Agents: {trust_analytics['total_agents']}")
        print(f"    Average Trust: {trust_analytics['average_trust']:.2f}")
        print(f"    High Risk Agents: {trust_analytics['high_risk_agents']}")
    
    if 'maestro_analytics' in analytics:
        print(f"  MAESTRO Analytics:")
        maestro_analytics = analytics['maestro_analytics']
        print(f"    Security Trend: {maestro_analytics['security_trends']['trend']}")
        print(f"    Critical Threats: {maestro_analytics['critical_threats']}")
    
    if 'behavioral_analytics' in analytics:
        print(f"  Behavioral Analytics:")
        behavioral_analytics = analytics['behavioral_analytics']
        print(f"    Total Agents: {behavioral_analytics['total_agents']}")
        print(f"    High Risk Agents: {behavioral_analytics['high_risk_agents']}")
    
    # Get security recommendations
    recommendations = gateway.get_security_recommendations()
    print(f"\n🔧 Security Recommendations:")
    for i, recommendation in enumerate(recommendations[:5], 1):
        print(f"  {i}. {recommendation}")


async def main():
    """Main demo function"""
    print("🛡️ MCP Security Framework - Enhanced Security Demo")
    print("=" * 60)
    print("This demo showcases the new advanced security features:")
    print("• Dynamic Trust Allocation System")
    print("• MAESTRO Multi-Layer Security Framework")
    print("• Advanced Behavioral Analysis System")
    print("• Enhanced Security Gateway Integration")
    
    try:
        # Run individual demos
        await demo_dynamic_trust_allocation()
        await demo_maestro_layer_security()
        await demo_advanced_behavioral_analysis()
        await demo_enhanced_security_gateway()
        
        print("\n✅ Enhanced Security Demo Completed Successfully!")
        print("\n🎯 Key Benefits Demonstrated:")
        print("• Context-aware trust allocation with dynamic adjustment")
        print("• Comprehensive 7-layer security assessment")
        print("• Advanced behavioral analysis with deception detection")
        print("• Integrated security gateway with multiple protection layers")
        print("• Real-time security analytics and recommendations")
        
    except Exception as e:
        print(f"\n❌ Demo Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
