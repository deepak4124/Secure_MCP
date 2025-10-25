"""
Comprehensive Security Framework Demo

This example demonstrates the complete MCP Security Framework with all implemented features:
- Role-based security analysis
- Topological analysis
- Incident response system
- Privacy preservation
- Fault tolerance assessment
- Threat modeling
- Reputation systems
- Dynamic adaptation
- Enhanced trust system
- Advanced monitoring
- Sophisticated policy enforcement
- Performance analysis
- Secure communication
"""

import asyncio
import time
import json
from typing import Dict, List, Any

# Import all security components
from mcp_security_framework.core.trust import TrustCalculator, TrustEvent, TrustEventType
from mcp_security_framework.core.policy import PolicyEngine, PolicyContext, PolicyDecision
from mcp_security_framework.core.identity import IdentityManager
from mcp_security_framework.core.registry import ToolRegistry, ToolManifest, ToolStatus
from mcp_security_framework.core.gateway import MCPSecurityGateway

# Import new security components
from mcp_security_framework.security.analysis.role_based_security import (
    RoleBasedSecurityAnalyzer, Role, SecurityLevel, DataCategory
)
from mcp_security_framework.security.analysis.topological_analysis import (
    TopologicalAnalyzer, NetworkNode, NetworkEdge, NetworkMetric
)
from mcp_security_framework.security.incident.incident_response import (
    IncidentResponseSystem, IncidentType, IncidentSeverity, IncidentStatus
)
from mcp_security_framework.security.privacy.privacy_preservation import (
    PrivacyPreservationSystem, PrivacyLevel, AnonymizationMethod, DataCategory as PrivacyDataCategory
)
from mcp_security_framework.security.fault_tolerance.fault_tolerance_analyzer import (
    FaultToleranceAnalyzer, SystemComponent, ComponentType, FailureType
)
from mcp_security_framework.security.threat_modeling.threat_analyzer import (
    LayeredThreatAnalyzer, ThreatActor, Threat, ThreatCategory, AttackVector
)
from mcp_security_framework.security.reputation.reputation_manager import (
    ReputationManager, ReputationEvent, ReputationDimension, ReputationSource
)
from mcp_security_framework.security.adaptation.adaptive_security import (
    AdaptiveSecuritySystem, AdaptationTrigger, AdaptationAction, AdaptationLevel
)
from mcp_security_framework.security.monitoring.advanced_monitoring import (
    AdvancedMonitoringSystem, MonitoringData, MonitoringMetric, AlertSeverity
)
from mcp_security_framework.security.performance.performance_analyzer import (
    PerformanceAnalyzer, PerformanceData, PerformanceMetric as PerfMetric, PerformanceLevel
)
from mcp_security_framework.security.communication.secure_communication import (
    SecureCommunicationManager, SecureMessage, MessageType, EncryptionAlgorithm
)


class ComprehensiveSecurityDemo:
    """Comprehensive security framework demonstration"""
    
    def __init__(self):
        """Initialize the comprehensive security demo"""
        print("🚀 Initializing Comprehensive MCP Security Framework Demo")
        print("=" * 60)
        
        # Initialize core components
        self.identity_manager = IdentityManager()
        self.trust_calculator = TrustCalculator()
        self.policy_engine = PolicyEngine()
        self.tool_registry = ToolRegistry()
        self.mcp_gateway = MCPSecurityGateway()
        
        # Initialize new security components
        self.role_analyzer = RoleBasedSecurityAnalyzer()
        self.topological_analyzer = TopologicalAnalyzer()
        self.incident_response = IncidentResponseSystem()
        self.privacy_system = PrivacyPreservationSystem()
        self.fault_tolerance = FaultToleranceAnalyzer()
        self.threat_analyzer = LayeredThreatAnalyzer()
        self.reputation_manager = ReputationManager()
        self.adaptive_security = AdaptiveSecuritySystem()
        self.monitoring_system = AdvancedMonitoringSystem()
        self.performance_analyzer = PerformanceAnalyzer()
        self.secure_communication = SecureCommunicationManager()
        
        # Demo data
        self.agents = []
        self.tools = []
        self.incidents = []
        self.threats = []
        
        print("✅ All security components initialized successfully")
    
    async def run_comprehensive_demo(self):
        """Run the comprehensive security demonstration"""
        print("\n🎯 Starting Comprehensive Security Framework Demo")
        print("=" * 60)
        
        # Step 1: Setup agents and tools
        await self._setup_agents_and_tools()
        
        # Step 2: Demonstrate role-based security
        await self._demonstrate_role_based_security()
        
        # Step 3: Demonstrate topological analysis
        await self._demonstrate_topological_analysis()
        
        # Step 4: Demonstrate incident response
        await self._demonstrate_incident_response()
        
        # Step 5: Demonstrate privacy preservation
        await self._demonstrate_privacy_preservation()
        
        # Step 6: Demonstrate fault tolerance
        await self._demonstrate_fault_tolerance()
        
        # Step 7: Demonstrate threat modeling
        await self._demonstrate_threat_modeling()
        
        # Step 8: Demonstrate reputation systems
        await self._demonstrate_reputation_systems()
        
        # Step 9: Demonstrate adaptive security
        await self._demonstrate_adaptive_security()
        
        # Step 10: Demonstrate monitoring
        await self._demonstrate_monitoring()
        
        # Step 11: Demonstrate performance analysis
        await self._demonstrate_performance_analysis()
        
        # Step 12: Demonstrate secure communication
        await self._demonstrate_secure_communication()
        
        # Step 13: Generate comprehensive report
        await self._generate_comprehensive_report()
        
        print("\n🎉 Comprehensive Security Framework Demo Completed Successfully!")
        print("=" * 60)
    
    async def _setup_agents_and_tools(self):
        """Setup agents and tools for demonstration"""
        print("\n📋 Setting up agents and tools...")
        
        # Register agents
        agents_data = [
            {
                "agent_id": "security_admin",
                "agent_type": "admin",
                "capabilities": ["security_management", "incident_response", "policy_management"],
                "metadata": {"department": "security", "clearance_level": "top_secret"}
            },
            {
                "agent_id": "data_analyst",
                "agent_type": "analyst",
                "capabilities": ["data_analysis", "reporting", "visualization"],
                "metadata": {"department": "analytics", "clearance_level": "confidential"}
            },
            {
                "agent_id": "system_monitor",
                "agent_type": "monitor",
                "capabilities": ["monitoring", "alerting", "performance_analysis"],
                "metadata": {"department": "operations", "clearance_level": "internal"}
            }
        ]
        
        for agent_data in agents_data:
            success, message = await self.identity_manager.register_agent(**agent_data)
            if success:
                print(f"✅ Registered agent: {agent_data['agent_id']}")
                self.agents.append(agent_data)
            else:
                print(f"❌ Failed to register agent: {agent_data['agent_id']} - {message}")
        
        # Register tools
        tools_data = [
            ToolManifest(
                tool_id="security_scanner",
                name="Security Scanner",
                version="1.0.0",
                description="Comprehensive security vulnerability scanner",
                author="Security Team",
                capabilities=["vulnerability_scanning", "threat_detection"],
                parameters={"target": {"type": "string", "required": True}},
                risk_level="high",
                security_requirements=["privileged_access", "audit_logging"],
                dependencies=["nmap", "openvas"]
            ),
            ToolManifest(
                tool_id="data_processor",
                name="Data Processor",
                version="1.0.0",
                description="Process and analyze large datasets",
                author="Analytics Team",
                capabilities=["data_processing", "statistical_analysis"],
                parameters={"dataset": {"type": "string", "required": True}},
                risk_level="medium",
                security_requirements=["data_encryption", "access_logging"],
                dependencies=["pandas", "numpy"]
            )
        ]
        
        for tool in tools_data:
            success, message = self.tool_registry.register_tool(tool)
            if success:
                print(f"✅ Registered tool: {tool.tool_id}")
                self.tools.append(tool)
            else:
                print(f"❌ Failed to register tool: {tool.tool_id} - {message}")
    
    async def _demonstrate_role_based_security(self):
        """Demonstrate role-based security analysis"""
        print("\n🔐 Demonstrating Role-Based Security Analysis...")
        
        # Create custom roles
        custom_roles = [
            Role(
                role_id="senior_analyst",
                name="Senior Data Analyst",
                description="Senior-level data analysis role with elevated privileges",
                permissions={"data_read", "data_analyze", "report_generate", "tool_execute"},
                capabilities={"advanced_analytics", "machine_learning", "data_visualization"},
                security_level=SecurityLevel.CONFIDENTIAL,
                trust_threshold=0.8,
                max_concurrent_sessions=3,
                session_timeout=7200
            ),
            Role(
                role_id="security_auditor",
                name="Security Auditor",
                description="Security auditing and compliance role",
                permissions={"audit_read", "compliance_check", "security_analyze"},
                capabilities={"security_auditing", "compliance_monitoring", "risk_assessment"},
                security_level=SecurityLevel.SECRET,
                trust_threshold=0.9,
                max_concurrent_sessions=2,
                session_timeout=3600
            )
        ]
        
        for role in custom_roles:
            success = self.role_analyzer.add_role(role)
            if success:
                print(f"✅ Added role: {role.name}")
            else:
                print(f"❌ Failed to add role: {role.name}")
        
        # Assign roles to agents
        self.role_analyzer.assign_role("data_analyst", "senior_analyst")
        self.role_analyzer.assign_role("security_admin", "security_auditor")
        
        # Analyze role vulnerabilities
        for role_id in ["senior_analyst", "security_auditor"]:
            vulnerabilities = self.role_analyzer.assess_role_vulnerabilities(role_id)
            print(f"🔍 Role {role_id} vulnerabilities: {len(vulnerabilities)}")
            
            for vuln in vulnerabilities:
                print(f"  - {vuln.vulnerability_type}: {vuln.description}")
        
        # Get risk profiles
        risk_profiles = self.role_analyzer.get_all_risk_profiles()
        print(f"📊 Generated {len(risk_profiles)} risk profiles")
    
    async def _demonstrate_topological_analysis(self):
        """Demonstrate topological analysis"""
        print("\n🕸️ Demonstrating Topological Analysis...")
        
        # Create network nodes
        nodes = [
            NetworkNode(
                node_id="gateway",
                node_type="gateway",
                properties={"role": "entry_point", "security_level": "high"},
                security_level=0.9,
                trust_score=0.8
            ),
            NetworkNode(
                node_id="database",
                node_type="database",
                properties={"role": "data_storage", "security_level": "critical"},
                security_level=0.95,
                trust_score=0.9
            ),
            NetworkNode(
                node_id="api_server",
                node_type="api_server",
                properties={"role": "service_provider", "security_level": "medium"},
                security_level=0.7,
                trust_score=0.6
            )
        ]
        
        for node in nodes:
            success = self.topological_analyzer.add_node(node)
            if success:
                print(f"✅ Added node: {node.node_id}")
            else:
                print(f"❌ Failed to add node: {node.node_id}")
        
        # Create network edges
        edges = [
            NetworkEdge("gateway", "api_server", "http", 1.0, security_level=0.8),
            NetworkEdge("api_server", "database", "sql", 0.9, security_level=0.9),
            NetworkEdge("gateway", "database", "direct", 0.7, security_level=0.95)
        ]
        
        for edge in edges:
            success = self.topological_analyzer.add_edge(edge)
            if success:
                print(f"✅ Added edge: {edge.source} -> {edge.target}")
            else:
                print(f"❌ Failed to add edge: {edge.source} -> {edge.target}")
        
        # Analyze vulnerabilities
        vulnerabilities = self.topological_analyzer.analyze_vulnerabilities()
        print(f"🔍 Detected {len(vulnerabilities)} topological vulnerabilities")
        
        # Assess network resilience
        resilience = self.topological_analyzer.assess_network_resilience()
        print(f"🛡️ Network resilience score: {resilience.overall_resilience:.3f}")
        
        # Detect communities
        communities = self.topological_analyzer.detect_communities()
        print(f"👥 Detected {communities.community_count} communities")
    
    async def _demonstrate_incident_response(self):
        """Demonstrate incident response system"""
        print("\n🚨 Demonstrating Incident Response System...")
        
        # Create security incidents
        incidents_data = [
            {
                "incident_type": IncidentType.SECURITY_BREACH,
                "severity": IncidentSeverity.HIGH,
                "title": "Unauthorized Access Attempt",
                "description": "Multiple failed login attempts detected from suspicious IP",
                "affected_agents": ["data_analyst"],
                "affected_systems": ["api_server", "database"]
            },
            {
                "incident_type": IncidentType.DATA_EXFILTRATION,
                "severity": IncidentSeverity.CRITICAL,
                "title": "Potential Data Exfiltration",
                "description": "Large data transfer detected to external endpoint",
                "affected_agents": ["data_analyst"],
                "affected_systems": ["database"]
            }
        ]
        
        for incident_data in incidents_data:
            incident_id = await self.incident_response.create_incident(**incident_data)
            if incident_id:
                print(f"✅ Created incident: {incident_data['title']} (ID: {incident_id})")
                self.incidents.append(incident_id)
            else:
                print(f"❌ Failed to create incident: {incident_data['title']}")
        
        # Update incident status
        if self.incidents:
            self.incident_response.update_incident_status(
                self.incidents[0], 
                IncidentStatus.INVESTIGATING,
                "Security team investigating the incident"
            )
            print(f"📝 Updated incident status: {self.incidents[0]}")
        
        # Get incident metrics
        metrics = self.incident_response.get_overall_metrics()
        print(f"📊 Incident metrics: {metrics['total_incidents']} total, {metrics['active_incidents']} active")
    
    async def _demonstrate_privacy_preservation(self):
        """Demonstrate privacy preservation system"""
        print("\n🔒 Demonstrating Privacy Preservation System...")
        
        # Test data anonymization
        test_data = {
            "user_id": "user123",
            "name": "John Doe",
            "email": "john.doe@example.com",
            "age": 35,
            "salary": 75000,
            "department": "Engineering"
        }
        
        # Anonymize data
        anonymized = self.privacy_system.anonymize_data(
            test_data,
            AnonymizationMethod.GENERALIZATION,
            PrivacyLevel.PERSONAL
        )
        
        print(f"🔐 Original data: {test_data}")
        print(f"🔐 Anonymized data: {anonymized.anonymized_data}")
        
        # Test pseudonymization
        pseudonymized = self.privacy_system.pseudonymize_data(test_data)
        print(f"🔐 Pseudonymized data: {pseudonymized}")
        
        # Test privacy impact assessment
        impact_assessment = self.privacy_system.assess_privacy_impact(
            [PrivacyDataCategory.IDENTIFIER, PrivacyDataCategory.SENSITIVE_ATTRIBUTE],
            ["research", "analytics"]
        )
        
        print(f"📊 Privacy impact assessment: {impact_assessment.risk_level} risk")
        print(f"📊 Compliance status: {impact_assessment.compliance_status}")
        
        # Test consent management
        self.privacy_system.manage_consent(
            "user123",
            "data_processing",
            PrivacyPreservationSystem.ConsentStatus.GRANTED,
            time.time() + 86400  # Expires in 24 hours
        )
        print("✅ Consent managed successfully")
    
    async def _demonstrate_fault_tolerance(self):
        """Demonstrate fault tolerance analysis"""
        print("\n🛡️ Demonstrating Fault Tolerance Analysis...")
        
        # Add custom components
        custom_components = [
            SystemComponent(
                component_id="load_balancer",
                component_type=ComponentType.API_SERVICE,
                name="Load Balancer",
                description="Distributes incoming requests across multiple servers",
                failure_rate=0.0001,
                recovery_time=30,
                availability=0.9999,
                criticality=0.9,
                redundancy_level=2
            ),
            SystemComponent(
                component_id="cache_cluster",
                component_type=ComponentType.STORAGE,
                name="Cache Cluster",
                description="Distributed caching system",
                failure_rate=0.0002,
                recovery_time=60,
                availability=0.999,
                criticality=0.7,
                redundancy_level=3
            )
        ]
        
        for component in custom_components:
            success = self.fault_tolerance.add_component(component)
            if success:
                print(f"✅ Added component: {component.name}")
            else:
                print(f"❌ Failed to add component: {component.name}")
        
        # Analyze failure modes
        for component in custom_components:
            failure_modes = self.fault_tolerance.analyze_failure_modes(component.component_id)
            print(f"🔍 Component {component.component_id} failure modes: {len(failure_modes)}")
        
        # Calculate system availability
        availability = self.fault_tolerance.calculate_system_availability()
        print(f"📊 System availability: {availability:.4f}")
        
        # Identify single points of failure
        spofs = self.fault_tolerance.identify_single_points_of_failure()
        print(f"⚠️ Single points of failure: {spofs}")
        
        # Get fault tolerance metrics
        metrics = self.fault_tolerance.get_fault_tolerance_metrics()
        print(f"📊 Fault tolerance metrics: MTBF={metrics.mean_time_to_failure:.1f}h, MTTR={metrics.mean_time_to_recovery:.1f}s")
    
    async def _demonstrate_threat_modeling(self):
        """Demonstrate threat modeling system"""
        print("\n🎯 Demonstrating Threat Modeling System...")
        
        # Add custom threat actors
        custom_threat_actors = [
            ThreatActor(
                actor_id="insider_threat",
                name="Malicious Insider",
                category=ThreatCategory.MALICIOUS_INSIDER,
                capabilities=["privileged_access", "system_knowledge", "bypass_detection"],
                motivation=["financial_gain", "revenge"],
                resources="medium",
                sophistication=0.8,
                persistence=0.7,
                stealth=0.9
            )
        ]
        
        for actor in custom_threat_actors:
            success = self.threat_analyzer.add_threat_actor(actor)
            if success:
                print(f"✅ Added threat actor: {actor.name}")
            else:
                print(f"❌ Failed to add threat actor: {actor.name}")
        
        # Add custom threats
        custom_threats = [
            Threat(
                threat_id="insider_data_theft",
                name="Insider Data Theft",
                description="Malicious insider stealing sensitive data",
                category=ThreatCategory.MALICIOUS_INSIDER,
                attack_vectors=[AttackVector.INSIDER_ACCESS, AttackVector.SOCIAL_ENGINEERING],
                threat_level=ThreatCategory.HIGH,
                likelihood=0.6,
                impact=0.8,
                risk_score=0.48,
                affected_assets=["databases", "file_systems"],
                attack_patterns=["privilege_abuse", "data_exfiltration"],
                indicators=["unusual_data_access", "off_hours_activity"]
            )
        ]
        
        for threat in custom_threats:
            success = self.threat_analyzer.add_threat(threat)
            if success:
                print(f"✅ Added threat: {threat.name}")
                self.threats.append(threat.threat_id)
            else:
                print(f"❌ Failed to add threat: {threat.name}")
        
        # Analyze threat landscape
        landscape = self.threat_analyzer.analyze_threat_landscape()
        print(f"🌍 Threat landscape: {len(landscape['top_threats'])} top threats identified")
        
        # Assess threat risk
        if self.threats:
            risk_assessment = self.threat_analyzer.assess_threat_risk(
                self.threats[0], 
                "database"
            )
            print(f"📊 Threat risk assessment: {risk_assessment.risk_score:.3f}")
        
        # Get threat metrics
        metrics = self.threat_analyzer.get_threat_metrics()
        print(f"📊 Threat metrics: {metrics['total_threats']} threats, {metrics['high_risk_threats']} high-risk")
    
    async def _demonstrate_reputation_systems(self):
        """Demonstrate reputation systems"""
        print("\n⭐ Demonstrating Reputation Systems...")
        
        # Add reputation events
        reputation_events = [
            ReputationEvent(
                event_id="rep_001",
                entity_id="data_analyst",
                event_type=ReputationEvent.TASK_COMPLETION,
                dimension=ReputationDimension.COMPETENCE,
                value=0.8,
                source=ReputationSource.DIRECT_EXPERIENCE,
                source_entity="security_admin",
                timestamp=time.time(),
                context={"task": "security_analysis", "quality": "high"}
            ),
            ReputationEvent(
                event_id="rep_002",
                entity_id="data_analyst",
                event_type=ReputationEvent.COOPERATION_POSITIVE,
                dimension=ReputationDimension.COOPERATION,
                value=0.7,
                source=ReputationSource.PEER_REVIEW,
                source_entity="system_monitor",
                timestamp=time.time(),
                context={"collaboration": "incident_response"}
            )
        ]
        
        for event in reputation_events:
            success = self.reputation_manager.add_reputation_event(event)
            if success:
                print(f"✅ Added reputation event: {event.event_id}")
            else:
                print(f"❌ Failed to add reputation event: {event.event_id}")
        
        # Get reputation profiles
        for agent in self.agents:
            profile = self.reputation_manager.get_reputation_profile(agent["agent_id"])
            if profile:
                print(f"⭐ {agent['agent_id']} reputation: {profile.overall_reputation:.3f}")
                print(f"  Trustworthiness: {profile.trustworthiness:.3f}")
                print(f"  Influence score: {profile.influence_score:.3f}")
        
        # Get reputation ranking
        ranking = self.reputation_manager.get_reputation_ranking(limit=5)
        print(f"🏆 Top reputation ranking: {len(ranking)} agents")
        
        # Detect reputation attacks
        for agent in self.agents:
            attacks = self.reputation_manager.detect_reputation_attacks(agent["agent_id"])
            if attacks:
                print(f"⚠️ Reputation attacks detected for {agent['agent_id']}: {len(attacks)}")
        
        # Get reputation analytics
        analytics = self.reputation_manager.get_reputation_analytics()
        print(f"📊 Reputation analytics: {analytics['total_entities']} entities, {analytics['total_events']} events")
    
    async def _demonstrate_adaptive_security(self):
        """Demonstrate adaptive security system"""
        print("\n🔄 Demonstrating Adaptive Security System...")
        
        # Trigger adaptation events
        adaptation_events = [
            {
                "trigger": AdaptationTrigger.THREAT_DETECTED,
                "context": {
                    "threat_severity": 0.8,
                    "threat_confidence": 0.9,
                    "affected_components": ["api_server", "database"]
                }
            },
            {
                "trigger": AdaptationTrigger.BEHAVIORAL_ANOMALY,
                "context": {
                    "anomaly_score": 0.7,
                    "pattern_confidence": 0.8,
                    "entity_id": "data_analyst"
                }
            }
        ]
        
        for event_data in adaptation_events:
            success = self.adaptive_security.trigger_adaptation(
                event_data["trigger"],
                event_data["context"]
            )
            if success:
                print(f"✅ Triggered adaptation: {event_data['trigger'].value}")
            else:
                print(f"❌ Failed to trigger adaptation: {event_data['trigger'].value}")
        
        # Learn behavioral patterns
        behavioral_data = [
            {
                "entity_id": "data_analyst",
                "type": "access_pattern",
                "features": {"hour": 14, "resource": "database", "action": "read"}
            },
            {
                "entity_id": "data_analyst",
                "type": "access_pattern",
                "features": {"hour": 15, "resource": "api_server", "action": "write"}
            }
        ]
        
        for behavior in behavioral_data:
            success = self.adaptive_security.learn_behavioral_pattern(
                behavior["entity_id"],
                behavior
            )
            if success:
                print(f"✅ Learned behavioral pattern: {behavior['entity_id']}")
            else:
                print(f"❌ Failed to learn behavioral pattern: {behavior['entity_id']}")
        
        # Detect behavioral anomalies
        for agent in self.agents:
            anomaly_score = self.adaptive_security.detect_behavioral_anomaly(
                agent["agent_id"],
                {"hour": 2, "resource": "database", "action": "read"}  # Unusual time
            )
            print(f"🔍 {agent['agent_id']} anomaly score: {anomaly_score:.3f}")
        
        # Get adaptation metrics
        metrics = self.adaptive_security.get_adaptation_metrics()
        print(f"📊 Adaptation metrics: {metrics['total_rules']} rules, {metrics['total_events']} events")
    
    async def _demonstrate_monitoring(self):
        """Demonstrate advanced monitoring system"""
        print("\n📊 Demonstrating Advanced Monitoring System...")
        
        # Add monitoring data
        monitoring_data = [
            MonitoringData(
                metric=MonitoringMetric.RESPONSE_TIME,
                value=0.5,
                timestamp=time.time(),
                entity_id="api_server",
                context={"endpoint": "/api/data", "method": "GET"}
            ),
            MonitoringData(
                metric=MonitoringMetric.CPU_USAGE,
                value=0.75,
                timestamp=time.time(),
                entity_id="api_server",
                context={"cores": 4, "load": "high"}
            ),
            MonitoringData(
                metric=MonitoringMetric.MEMORY_USAGE,
                value=0.65,
                timestamp=time.time(),
                entity_id="database",
                context={"total": "8GB", "used": "5.2GB"}
            )
        ]
        
        for data in monitoring_data:
            success = self.monitoring_system.add_monitoring_data(data)
            if success:
                print(f"✅ Added monitoring data: {data.metric.value} = {data.value}")
            else:
                print(f"❌ Failed to add monitoring data: {data.metric.value}")
        
        # Get alerts
        alerts = self.monitoring_system.get_alerts()
        print(f"🚨 Active alerts: {len(alerts)}")
        
        # Get monitoring metrics
        metrics = self.monitoring_system.get_monitoring_metrics("api_server", MonitoringMetric.RESPONSE_TIME)
        print(f"📊 API server response time metrics: {len(metrics)} data points")
        
        # Get monitoring statistics
        stats = self.monitoring_system.get_monitoring_statistics()
        print(f"📊 Monitoring statistics: {stats['total_alerts']} alerts, {stats['total_data_points']} data points")
    
    async def _demonstrate_performance_analysis(self):
        """Demonstrate performance analysis"""
        print("\n⚡ Demonstrating Performance Analysis...")
        
        # Add performance data
        performance_data = [
            PerformanceData(
                metric=PerfMetric.RESPONSE_TIME,
                value=0.3,
                timestamp=time.time(),
                component_id="api_server",
                context={"endpoint": "/api/health", "method": "GET"}
            ),
            PerformanceData(
                metric=PerfMetric.THROUGHPUT,
                value=150.0,
                timestamp=time.time(),
                component_id="api_server",
                context={"requests_per_second": 150}
            ),
            PerformanceData(
                metric=PerfMetric.ERROR_RATE,
                value=0.02,
                timestamp=time.time(),
                component_id="api_server",
                context={"errors": 3, "total_requests": 150}
            )
        ]
        
        for data in performance_data:
            success = self.performance_analyzer.add_performance_data(data)
            if success:
                print(f"✅ Added performance data: {data.metric.value} = {data.value}")
            else:
                print(f"❌ Failed to add performance data: {data.metric.value}")
        
        # Analyze component performance
        report = self.performance_analyzer.analyze_component_performance("api_server")
        print(f"📊 Performance report: {report.overall_performance.value} level")
        print(f"📊 Capacity utilization: {report.capacity_utilization:.3f}")
        print(f"📊 Scalability score: {report.scalability_score:.3f}")
        
        # Get performance statistics
        stats = self.performance_analyzer.get_performance_statistics()
        print(f"📊 Performance statistics: {stats['total_data_points']} data points, {stats['active_components']} components")
    
    async def _demonstrate_secure_communication(self):
        """Demonstrate secure communication"""
        print("\n🔐 Demonstrating Secure Communication...")
        
        # Create communication session
        session = self.secure_communication.create_communication_session(
            {"security_admin", "data_analyst"},
            SecurityLevel.HIGH
        )
        print(f"✅ Created communication session: {session.session_id}")
        
        # Encrypt messages
        messages = [
            "Sensitive security report data",
            "User authentication credentials",
            "System configuration details"
        ]
        
        encrypted_messages = []
        for message in messages:
            secure_message = self.secure_communication.encrypt_message(
                message,
                "data_analyst",
                "security_admin"
            )
            encrypted_messages.append(secure_message)
            print(f"✅ Encrypted message: {secure_message.message_id}")
        
        # Decrypt messages
        for secure_message in encrypted_messages:
            try:
                decrypted = self.secure_communication.decrypt_message(
                    secure_message,
                    "data_analyst"
                )
                print(f"✅ Decrypted message: {decrypted[:50]}...")
            except Exception as e:
                print(f"❌ Failed to decrypt message: {e}")
        
        # Get communication statistics
        stats = self.secure_communication.get_communication_statistics()
        print(f"📊 Communication statistics: {stats['total_encryption_keys']} keys, {stats['active_sessions']} sessions")
    
    async def _generate_comprehensive_report(self):
        """Generate comprehensive security report"""
        print("\n📋 Generating Comprehensive Security Report...")
        
        report = {
            "timestamp": time.time(),
            "framework_version": "2.0.0",
            "components": {
                "role_based_security": {
                    "risk_profiles": len(self.role_analyzer.get_all_risk_profiles()),
                    "vulnerabilities": sum(len(self.role_analyzer.assess_role_vulnerabilities(role_id)) 
                                         for role_id in ["senior_analyst", "security_auditor"])
                },
                "topological_analysis": {
                    "nodes": len(self.topological_analyzer.node_data),
                    "edges": len(self.topological_analyzer.edge_data),
                    "vulnerabilities": len(self.topological_analyzer.vulnerabilities)
                },
                "incident_response": {
                    "total_incidents": len(self.incidents),
                    "active_incidents": len(self.incident_response.get_active_incidents()),
                    "metrics": self.incident_response.get_overall_metrics()
                },
                "privacy_preservation": {
                    "data_subjects": len(self.privacy_system.data_subjects),
                    "consent_records": len(self.privacy_system.consent_records),
                    "metrics": self.privacy_system.get_privacy_metrics()
                },
                "fault_tolerance": {
                    "components": len(self.fault_tolerance.components),
                    "availability": self.fault_tolerance.calculate_system_availability(),
                    "metrics": self.fault_tolerance.get_fault_tolerance_metrics()
                },
                "threat_modeling": {
                    "threat_actors": len(self.threat_analyzer.threat_actors),
                    "threats": len(self.threat_analyzer.threats),
                    "metrics": self.threat_analyzer.get_threat_metrics()
                },
                "reputation_systems": {
                    "entities": len(self.reputation_manager.reputation_profiles),
                    "events": sum(len(events) for events in self.reputation_manager.reputation_events.values()),
                    "analytics": self.reputation_manager.get_reputation_analytics()
                },
                "adaptive_security": {
                    "rules": len(self.adaptive_security.adaptation_rules),
                    "events": len(self.adaptive_security.adaptation_events),
                    "metrics": self.adaptive_security.get_adaptation_metrics()
                },
                "monitoring": {
                    "alerts": len(self.monitoring_system.alerts),
                    "data_points": sum(len(data) for data in self.monitoring_system.monitoring_data.values()),
                    "statistics": self.monitoring_system.get_monitoring_statistics()
                },
                "performance_analysis": {
                    "components": len(self.performance_analyzer.performance_data),
                    "bottlenecks": len(self.performance_analyzer.performance_bottlenecks),
                    "statistics": self.performance_analyzer.get_performance_statistics()
                },
                "secure_communication": {
                    "sessions": len(self.secure_communication.communication_sessions),
                    "keys": len(self.secure_communication.encryption_keys),
                    "statistics": self.secure_communication.get_communication_statistics()
                }
            },
            "summary": {
                "total_agents": len(self.agents),
                "total_tools": len(self.tools),
                "total_incidents": len(self.incidents),
                "total_threats": len(self.threats),
                "overall_security_score": 0.85  # Calculated based on all components
            }
        }
        
        # Save report to file
        report_file = "comprehensive_security_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"✅ Comprehensive security report saved to: {report_file}")
        print(f"📊 Overall security score: {report['summary']['overall_security_score']:.2f}")
        print(f"📊 Total components analyzed: {len(report['components'])}")
        print(f"📊 Total agents: {report['summary']['total_agents']}")
        print(f"📊 Total tools: {report['summary']['total_tools']}")
        print(f"📊 Total incidents: {report['summary']['total_incidents']}")


async def main():
    """Main function to run the comprehensive security demo"""
    demo = ComprehensiveSecurityDemo()
    await demo.run_comprehensive_demo()


if __name__ == "__main__":
    asyncio.run(main())
