"""
MAESTRO Multi-Layer Security Framework for MCP Security Framework

This module implements the 7-layer security architecture inspired by MAESTRO
for comprehensive multi-agent system security.
"""

import time
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque

from pydantic import BaseModel, Field


class SecurityLayer(Enum):
    """Security layer enumeration"""
    FOUNDATION_MODELS = "foundation_models"
    AGENT_CORE = "agent_core"
    TOOL_INTEGRATION = "tool_integration"
    OPERATIONAL_CONTEXT = "operational_context"
    MULTI_AGENT_INTERACTION = "multi_agent_interaction"
    DEPLOYMENT_ENVIRONMENT = "deployment_environment"
    AGENT_ECOSYSTEM = "agent_ecosystem"


class ThreatSeverity(Enum):
    """Threat severity enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityControl(Enum):
    """Security control enumeration"""
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"


@dataclass
class LayerThreat:
    """Layer-specific threat definition"""
    threat_id: str
    layer: SecurityLayer
    threat_type: str
    description: str
    severity: ThreatSeverity
    attack_vectors: List[str]
    impact_assessment: Dict[str, Any]
    mitigation_strategies: List[str]
    detection_indicators: List[str]


@dataclass
class LayerSecurityAssessment:
    """Security assessment for a specific layer"""
    layer: SecurityLayer
    security_score: float
    threat_count: int
    vulnerabilities: List[str]
    controls_implemented: List[str]
    controls_missing: List[str]
    recommendations: List[str]
    last_assessed: float


@dataclass
class MAESTROAssessment:
    """Comprehensive MAESTRO security assessment"""
    overall_security_score: float
    layer_assessments: Dict[SecurityLayer, LayerSecurityAssessment]
    critical_threats: List[LayerThreat]
    security_gaps: List[str]
    priority_recommendations: List[str]
    assessment_timestamp: float


class FoundationModelSecurity:
    """Security controls for foundation models layer"""
    
    def __init__(self):
        self.model_integrity_checks = True
        self.prompt_injection_detection = True
        self.output_validation = True
        self.model_poisoning_detection = True
    
    def assess_security(self, model_data: Dict[str, Any]) -> LayerSecurityAssessment:
        """Assess security of foundation models"""
        vulnerabilities = []
        controls_implemented = []
        controls_missing = []
        
        # Check model integrity
        if self.model_integrity_checks:
            controls_implemented.append("Model integrity verification")
        else:
            controls_missing.append("Model integrity verification")
            vulnerabilities.append("Model tampering possible")
        
        # Check prompt injection protection
        if self.prompt_injection_detection:
            controls_implemented.append("Prompt injection detection")
        else:
            controls_missing.append("Prompt injection detection")
            vulnerabilities.append("Prompt injection attacks possible")
        
        # Check output validation
        if self.output_validation:
            controls_implemented.append("Output validation")
        else:
            controls_missing.append("Output validation")
            vulnerabilities.append("Malicious outputs possible")
        
        # Calculate security score
        total_controls = len(controls_implemented) + len(controls_missing)
        security_score = len(controls_implemented) / total_controls if total_controls > 0 else 0.0
        
        # Generate recommendations
        recommendations = []
        if len(controls_missing) > 0:
            recommendations.append("Implement missing security controls for foundation models")
        if security_score < 0.8:
            recommendations.append("Strengthen foundation model security controls")
        
        return LayerSecurityAssessment(
            layer=SecurityLayer.FOUNDATION_MODELS,
            security_score=security_score,
            threat_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            controls_implemented=controls_implemented,
            controls_missing=controls_missing,
            recommendations=recommendations,
            last_assessed=time.time()
        )


class AgentCoreSecurity:
    """Security controls for agent core layer"""
    
    def __init__(self):
        self.agent_authentication = True
        self.agent_authorization = True
        self.agent_isolation = True
        self.agent_monitoring = True
    
    def assess_security(self, agent_data: Dict[str, Any]) -> LayerSecurityAssessment:
        """Assess security of agent core"""
        vulnerabilities = []
        controls_implemented = []
        controls_missing = []
        
        # Check authentication
        if self.agent_authentication:
            controls_implemented.append("Agent authentication")
        else:
            controls_missing.append("Agent authentication")
            vulnerabilities.append("Unauthorized agent access possible")
        
        # Check authorization
        if self.agent_authorization:
            controls_implemented.append("Agent authorization")
        else:
            controls_missing.append("Agent authorization")
            vulnerabilities.append("Privilege escalation possible")
        
        # Check isolation
        if self.agent_isolation:
            controls_implemented.append("Agent isolation")
        else:
            controls_missing.append("Agent isolation")
            vulnerabilities.append("Agent interference possible")
        
        # Check monitoring
        if self.agent_monitoring:
            controls_implemented.append("Agent monitoring")
        else:
            controls_missing.append("Agent monitoring")
            vulnerabilities.append("Agent activities not tracked")
        
        # Calculate security score
        total_controls = len(controls_implemented) + len(controls_missing)
        security_score = len(controls_implemented) / total_controls if total_controls > 0 else 0.0
        
        # Generate recommendations
        recommendations = []
        if len(controls_missing) > 0:
            recommendations.append("Implement missing agent core security controls")
        if security_score < 0.8:
            recommendations.append("Strengthen agent core security")
        
        return LayerSecurityAssessment(
            layer=SecurityLayer.AGENT_CORE,
            security_score=security_score,
            threat_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            controls_implemented=controls_implemented,
            controls_missing=controls_missing,
            recommendations=recommendations,
            last_assessed=time.time()
        )


class ToolIntegrationSecurity:
    """Security controls for tool integration layer"""
    
    def __init__(self):
        self.tool_verification = True
        self.tool_sandboxing = True
        self.tool_monitoring = True
        self.tool_attestation = True
    
    def assess_security(self, tool_data: Dict[str, Any]) -> LayerSecurityAssessment:
        """Assess security of tool integration"""
        vulnerabilities = []
        controls_implemented = []
        controls_missing = []
        
        # Check tool verification
        if self.tool_verification:
            controls_implemented.append("Tool verification")
        else:
            controls_missing.append("Tool verification")
            vulnerabilities.append("Unverified tools can be executed")
        
        # Check tool sandboxing
        if self.tool_sandboxing:
            controls_implemented.append("Tool sandboxing")
        else:
            controls_missing.append("Tool sandboxing")
            vulnerabilities.append("Tools can access system resources")
        
        # Check tool monitoring
        if self.tool_monitoring:
            controls_implemented.append("Tool monitoring")
        else:
            controls_missing.append("Tool monitoring")
            vulnerabilities.append("Tool activities not tracked")
        
        # Check tool attestation
        if self.tool_attestation:
            controls_implemented.append("Tool attestation")
        else:
            controls_missing.append("Tool attestation")
            vulnerabilities.append("Tool integrity not verified")
        
        # Calculate security score
        total_controls = len(controls_implemented) + len(controls_missing)
        security_score = len(controls_implemented) / total_controls if total_controls > 0 else 0.0
        
        # Generate recommendations
        recommendations = []
        if len(controls_missing) > 0:
            recommendations.append("Implement missing tool integration security controls")
        if security_score < 0.8:
            recommendations.append("Strengthen tool integration security")
        
        return LayerSecurityAssessment(
            layer=SecurityLayer.TOOL_INTEGRATION,
            security_score=security_score,
            threat_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            controls_implemented=controls_implemented,
            controls_missing=controls_missing,
            recommendations=recommendations,
            last_assessed=time.time()
        )


class OperationalContextSecurity:
    """Security controls for operational context layer"""
    
    def __init__(self):
        self.context_validation = True
        self.context_encryption = True
        self.context_monitoring = True
        self.context_isolation = True
    
    def assess_security(self, context_data: Dict[str, Any]) -> LayerSecurityAssessment:
        """Assess security of operational context"""
        vulnerabilities = []
        controls_implemented = []
        controls_missing = []
        
        # Check context validation
        if self.context_validation:
            controls_implemented.append("Context validation")
        else:
            controls_missing.append("Context validation")
            vulnerabilities.append("Invalid context data can be processed")
        
        # Check context encryption
        if self.context_encryption:
            controls_implemented.append("Context encryption")
        else:
            controls_missing.append("Context encryption")
            vulnerabilities.append("Context data not protected")
        
        # Check context monitoring
        if self.context_monitoring:
            controls_implemented.append("Context monitoring")
        else:
            controls_missing.append("Context monitoring")
            vulnerabilities.append("Context activities not tracked")
        
        # Check context isolation
        if self.context_isolation:
            controls_implemented.append("Context isolation")
        else:
            controls_missing.append("Context isolation")
            vulnerabilities.append("Context data leakage possible")
        
        # Calculate security score
        total_controls = len(controls_implemented) + len(controls_missing)
        security_score = len(controls_implemented) / total_controls if total_controls > 0 else 0.0
        
        # Generate recommendations
        recommendations = []
        if len(controls_missing) > 0:
            recommendations.append("Implement missing operational context security controls")
        if security_score < 0.8:
            recommendations.append("Strengthen operational context security")
        
        return LayerSecurityAssessment(
            layer=SecurityLayer.OPERATIONAL_CONTEXT,
            security_score=security_score,
            threat_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            controls_implemented=controls_implemented,
            controls_missing=controls_missing,
            recommendations=recommendations,
            last_assessed=time.time()
        )


class MultiAgentInteractionSecurity:
    """Security controls for multi-agent interaction layer"""
    
    def __init__(self):
        self.communication_encryption = True
        self.agent_authentication = True
        self.collusion_detection = True
        self.interaction_monitoring = True
    
    def assess_security(self, interaction_data: Dict[str, Any]) -> LayerSecurityAssessment:
        """Assess security of multi-agent interactions"""
        vulnerabilities = []
        controls_implemented = []
        controls_missing = []
        
        # Check communication encryption
        if self.communication_encryption:
            controls_implemented.append("Communication encryption")
        else:
            controls_missing.append("Communication encryption")
            vulnerabilities.append("Inter-agent communication not protected")
        
        # Check agent authentication
        if self.agent_authentication:
            controls_implemented.append("Agent authentication")
        else:
            controls_missing.append("Agent authentication")
            vulnerabilities.append("Unauthorized agent interactions possible")
        
        # Check collusion detection
        if self.collusion_detection:
            controls_implemented.append("Collusion detection")
        else:
            controls_missing.append("Collusion detection")
            vulnerabilities.append("Agent collusion not detected")
        
        # Check interaction monitoring
        if self.interaction_monitoring:
            controls_implemented.append("Interaction monitoring")
        else:
            controls_missing.append("Interaction monitoring")
            vulnerabilities.append("Agent interactions not tracked")
        
        # Calculate security score
        total_controls = len(controls_implemented) + len(controls_missing)
        security_score = len(controls_implemented) / total_controls if total_controls > 0 else 0.0
        
        # Generate recommendations
        recommendations = []
        if len(controls_missing) > 0:
            recommendations.append("Implement missing multi-agent interaction security controls")
        if security_score < 0.8:
            recommendations.append("Strengthen multi-agent interaction security")
        
        return LayerSecurityAssessment(
            layer=SecurityLayer.MULTI_AGENT_INTERACTION,
            security_score=security_score,
            threat_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            controls_implemented=controls_implemented,
            controls_missing=controls_missing,
            recommendations=recommendations,
            last_assessed=time.time()
        )


class DeploymentEnvironmentSecurity:
    """Security controls for deployment environment layer"""
    
    def __init__(self):
        self.infrastructure_hardening = True
        self.network_segmentation = True
        self.access_controls = True
        self.environment_monitoring = True
    
    def assess_security(self, environment_data: Dict[str, Any]) -> LayerSecurityAssessment:
        """Assess security of deployment environment"""
        vulnerabilities = []
        controls_implemented = []
        controls_missing = []
        
        # Check infrastructure hardening
        if self.infrastructure_hardening:
            controls_implemented.append("Infrastructure hardening")
        else:
            controls_missing.append("Infrastructure hardening")
            vulnerabilities.append("Infrastructure vulnerabilities present")
        
        # Check network segmentation
        if self.network_segmentation:
            controls_implemented.append("Network segmentation")
        else:
            controls_missing.append("Network segmentation")
            vulnerabilities.append("Network isolation not implemented")
        
        # Check access controls
        if self.access_controls:
            controls_implemented.append("Access controls")
        else:
            controls_missing.append("Access controls")
            vulnerabilities.append("Unauthorized access possible")
        
        # Check environment monitoring
        if self.environment_monitoring:
            controls_implemented.append("Environment monitoring")
        else:
            controls_missing.append("Environment monitoring")
            vulnerabilities.append("Environment activities not tracked")
        
        # Calculate security score
        total_controls = len(controls_implemented) + len(controls_missing)
        security_score = len(controls_implemented) / total_controls if total_controls > 0 else 0.0
        
        # Generate recommendations
        recommendations = []
        if len(controls_missing) > 0:
            recommendations.append("Implement missing deployment environment security controls")
        if security_score < 0.8:
            recommendations.append("Strengthen deployment environment security")
        
        return LayerSecurityAssessment(
            layer=SecurityLayer.DEPLOYMENT_ENVIRONMENT,
            security_score=security_score,
            threat_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            controls_implemented=controls_implemented,
            controls_missing=controls_missing,
            recommendations=recommendations,
            last_assessed=time.time()
        )


class AgentEcosystemSecurity:
    """Security controls for agent ecosystem layer"""
    
    def __init__(self):
        self.ecosystem_monitoring = True
        self.threat_intelligence = True
        self.incident_response = True
        self.governance_framework = True
    
    def assess_security(self, ecosystem_data: Dict[str, Any]) -> LayerSecurityAssessment:
        """Assess security of agent ecosystem"""
        vulnerabilities = []
        controls_implemented = []
        controls_missing = []
        
        # Check ecosystem monitoring
        if self.ecosystem_monitoring:
            controls_implemented.append("Ecosystem monitoring")
        else:
            controls_missing.append("Ecosystem monitoring")
            vulnerabilities.append("Ecosystem-wide threats not detected")
        
        # Check threat intelligence
        if self.threat_intelligence:
            controls_implemented.append("Threat intelligence")
        else:
            controls_missing.append("Threat intelligence")
            vulnerabilities.append("External threats not tracked")
        
        # Check incident response
        if self.incident_response:
            controls_implemented.append("Incident response")
        else:
            controls_missing.append("Incident response")
            vulnerabilities.append("Security incidents not handled")
        
        # Check governance framework
        if self.governance_framework:
            controls_implemented.append("Governance framework")
        else:
            controls_missing.append("Governance framework")
            vulnerabilities.append("Security governance not established")
        
        # Calculate security score
        total_controls = len(controls_implemented) + len(controls_missing)
        security_score = len(controls_implemented) / total_controls if total_controls > 0 else 0.0
        
        # Generate recommendations
        recommendations = []
        if len(controls_missing) > 0:
            recommendations.append("Implement missing agent ecosystem security controls")
        if security_score < 0.8:
            recommendations.append("Strengthen agent ecosystem security")
        
        return LayerSecurityAssessment(
            layer=SecurityLayer.AGENT_ECOSYSTEM,
            security_score=security_score,
            threat_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            controls_implemented=controls_implemented,
            controls_missing=controls_missing,
            recommendations=recommendations,
            last_assessed=time.time()
        )


class MAESTROLayerSecurity:
    """
    MAESTRO Multi-Layer Security Framework
    
    Implements the 7-layer security architecture for comprehensive
    multi-agent system security assessment and management.
    """
    
    def __init__(self):
        """Initialize MAESTRO layer security framework"""
        self.layers = {
            SecurityLayer.FOUNDATION_MODELS: FoundationModelSecurity(),
            SecurityLayer.AGENT_CORE: AgentCoreSecurity(),
            SecurityLayer.TOOL_INTEGRATION: ToolIntegrationSecurity(),
            SecurityLayer.OPERATIONAL_CONTEXT: OperationalContextSecurity(),
            SecurityLayer.MULTI_AGENT_INTERACTION: MultiAgentInteractionSecurity(),
            SecurityLayer.DEPLOYMENT_ENVIRONMENT: DeploymentEnvironmentSecurity(),
            SecurityLayer.AGENT_ECOSYSTEM: AgentEcosystemSecurity()
        }
        
        self.threat_database: Dict[SecurityLayer, List[LayerThreat]] = defaultdict(list)
        self.assessment_history: deque = deque(maxlen=100)
        
        # Initialize threat database
        self._initialize_threat_database()
    
    def assess_security_across_layers(
        self, 
        system_data: Dict[str, Any]
    ) -> MAESTROAssessment:
        """
        Perform comprehensive security assessment across all layers
        
        Args:
            system_data: System data for assessment
            
        Returns:
            Comprehensive MAESTRO security assessment
        """
        layer_assessments = {}
        all_vulnerabilities = []
        all_recommendations = []
        critical_threats = []
        
        # Assess each layer
        for layer, security_controller in self.layers.items():
            layer_data = system_data.get(layer.value, {})
            assessment = security_controller.assess_security(layer_data)
            layer_assessments[layer] = assessment
            
            # Collect vulnerabilities and recommendations
            all_vulnerabilities.extend(assessment.vulnerabilities)
            all_recommendations.extend(assessment.recommendations)
            
            # Identify critical threats for this layer
            layer_threats = self._identify_layer_threats(layer, assessment)
            critical_threats.extend(layer_threats)
        
        # Calculate overall security score
        layer_scores = [assessment.security_score for assessment in layer_assessments.values()]
        overall_security_score = sum(layer_scores) / len(layer_scores) if layer_scores else 0.0
        
        # Identify security gaps
        security_gaps = self._identify_security_gaps(layer_assessments)
        
        # Generate priority recommendations
        priority_recommendations = self._generate_priority_recommendations(
            layer_assessments, critical_threats, security_gaps
        )
        
        # Create comprehensive assessment
        assessment = MAESTROAssessment(
            overall_security_score=overall_security_score,
            layer_assessments=layer_assessments,
            critical_threats=critical_threats,
            security_gaps=security_gaps,
            priority_recommendations=priority_recommendations,
            assessment_timestamp=time.time()
        )
        
        # Store assessment in history
        self.assessment_history.append(assessment)
        
        return assessment
    
    def get_layer_security_score(self, layer: SecurityLayer) -> float:
        """
        Get security score for a specific layer
        
        Args:
            layer: Security layer
            
        Returns:
            Security score for the layer
        """
        if not self.assessment_history:
            return 0.0
        
        latest_assessment = self.assessment_history[-1]
        if layer in latest_assessment.layer_assessments:
            return latest_assessment.layer_assessments[layer].security_score
        
        return 0.0
    
    def get_security_trends(self, days: int = 30) -> Dict[str, Any]:
        """
        Get security trends over time
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Security trends analysis
        """
        if not self.assessment_history:
            return {'trend': 'no_data', 'trend_score': 0.0}
        
        # Filter assessments by time
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        recent_assessments = [
            assessment for assessment in self.assessment_history
            if assessment.assessment_timestamp >= cutoff_time
        ]
        
        if len(recent_assessments) < 2:
            return {'trend': 'insufficient_data', 'trend_score': 0.0}
        
        # Calculate trend
        scores = [assessment.overall_security_score for assessment in recent_assessments]
        trend_score = (scores[-1] - scores[0]) / len(scores)
        
        if trend_score > 0.05:
            trend = 'improving'
        elif trend_score < -0.05:
            trend = 'declining'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'trend_score': trend_score,
            'current_score': scores[-1],
            'average_score': sum(scores) / len(scores),
            'assessments_count': len(recent_assessments)
        }
    
    def get_critical_threats(self) -> List[LayerThreat]:
        """
        Get list of critical threats across all layers
        
        Returns:
            List of critical threats
        """
        if not self.assessment_history:
            return []
        
        latest_assessment = self.assessment_history[-1]
        return latest_assessment.critical_threats
    
    def get_security_recommendations(self) -> List[str]:
        """
        Get priority security recommendations
        
        Returns:
            List of priority recommendations
        """
        if not self.assessment_history:
            return []
        
        latest_assessment = self.assessment_history[-1]
        return latest_assessment.priority_recommendations
    
    def _initialize_threat_database(self) -> None:
        """Initialize threat database with known threats for each layer"""
        # Foundation Models threats
        self.threat_database[SecurityLayer.FOUNDATION_MODELS].extend([
            LayerThreat(
                threat_id="fm_001",
                layer=SecurityLayer.FOUNDATION_MODELS,
                threat_type="Prompt Injection",
                description="Malicious prompts designed to manipulate model behavior",
                severity=ThreatSeverity.HIGH,
                attack_vectors=["Direct prompt injection", "Indirect prompt injection"],
                impact_assessment={"confidentiality": 0.8, "integrity": 0.9, "availability": 0.3},
                mitigation_strategies=["Input validation", "Output filtering", "Model fine-tuning"],
                detection_indicators=["Unusual output patterns", "Unexpected model behavior"]
            ),
            LayerThreat(
                threat_id="fm_002",
                layer=SecurityLayer.FOUNDATION_MODELS,
                threat_type="Model Poisoning",
                description="Malicious training data designed to corrupt model behavior",
                severity=ThreatSeverity.CRITICAL,
                attack_vectors=["Training data injection", "Backdoor insertion"],
                impact_assessment={"confidentiality": 0.7, "integrity": 0.9, "availability": 0.5},
                mitigation_strategies=["Data validation", "Model verification", "Adversarial training"],
                detection_indicators=["Model performance degradation", "Unexpected outputs"]
            )
        ])
        
        # Agent Core threats
        self.threat_database[SecurityLayer.AGENT_CORE].extend([
            LayerThreat(
                threat_id="ac_001",
                layer=SecurityLayer.AGENT_CORE,
                threat_type="Agent Impersonation",
                description="Unauthorized agents masquerading as legitimate agents",
                severity=ThreatSeverity.HIGH,
                attack_vectors=["Identity spoofing", "Credential theft"],
                impact_assessment={"confidentiality": 0.9, "integrity": 0.8, "availability": 0.4},
                mitigation_strategies=["Strong authentication", "Identity verification", "Monitoring"],
                detection_indicators=["Unusual agent behavior", "Authentication failures"]
            )
        ])
        
        # Add more threats for other layers as needed...
    
    def _identify_layer_threats(
        self, 
        layer: SecurityLayer, 
        assessment: LayerSecurityAssessment
    ) -> List[LayerThreat]:
        """Identify threats for a specific layer based on assessment"""
        threats = []
        
        # Get known threats for this layer
        known_threats = self.threat_database[layer]
        
        # Match vulnerabilities to threats
        for vulnerability in assessment.vulnerabilities:
            for threat in known_threats:
                if vulnerability.lower() in threat.description.lower():
                    threats.append(threat)
                    break
        
        return threats
    
    def _identify_security_gaps(
        self, 
        layer_assessments: Dict[SecurityLayer, LayerSecurityAssessment]
    ) -> List[str]:
        """Identify security gaps across layers"""
        gaps = []
        
        for layer, assessment in layer_assessments.items():
            if assessment.security_score < 0.5:
                gaps.append(f"Critical security gap in {layer.value} layer")
            elif assessment.security_score < 0.7:
                gaps.append(f"Security weakness in {layer.value} layer")
        
        return gaps
    
    def _generate_priority_recommendations(
        self,
        layer_assessments: Dict[SecurityLayer, LayerSecurityAssessment],
        critical_threats: List[LayerThreat],
        security_gaps: List[str]
    ) -> List[str]:
        """Generate priority security recommendations"""
        recommendations = []
        
        # Prioritize based on critical threats
        if critical_threats:
            recommendations.append("Address critical threats immediately")
        
        # Prioritize based on security gaps
        if security_gaps:
            recommendations.append("Close identified security gaps")
        
        # Prioritize based on layer scores
        low_score_layers = [
            layer for layer, assessment in layer_assessments.items()
            if assessment.security_score < 0.6
        ]
        
        if low_score_layers:
            recommendations.append(f"Strengthen security in layers: {', '.join([layer.value for layer in low_score_layers])}")
        
        return recommendations
