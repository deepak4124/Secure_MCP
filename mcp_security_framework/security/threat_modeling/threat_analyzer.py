"""
Layered Threat Analysis System for MCP Security Framework

This module provides comprehensive threat modeling capabilities including:
- Multi-layered threat analysis
- Attack surface mapping
- Threat intelligence integration
- Risk assessment and prioritization
- Mitigation strategy development
- Threat landscape monitoring
- Attack pattern recognition
"""

import time
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
import networkx as nx
import numpy as np
from scipy import stats

from pydantic import BaseModel, Field


class ThreatCategory(Enum):
    """Threat category enumeration"""
    MALICIOUS_INSIDER = "malicious_insider"
    EXTERNAL_ATTACKER = "external_attacker"
    ADVANCED_PERSISTENT_THREAT = "advanced_persistent_threat"
    NATION_STATE = "nation_state"
    CRIMINAL_ORGANIZATION = "criminal_organization"
    HACKTIVIST = "hacktivist"
    SCRIPT_KIDDIE = "script_kiddie"
    ACCIDENTAL_THREAT = "accidental_threat"
    SYSTEM_FAILURE = "system_failure"
    NATURAL_DISASTER = "natural_disaster"


class AttackVector(Enum):
    """Attack vector enumeration"""
    NETWORK = "network"
    PHYSICAL = "physical"
    SOCIAL_ENGINEERING = "social_engineering"
    MALWARE = "malware"
    INSIDER_ACCESS = "insider_access"
    SUPPLY_CHAIN = "supply_chain"
    CLOUD = "cloud"
    MOBILE = "mobile"
    WEB_APPLICATION = "web_application"
    DATABASE = "database"


class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MitigationStrategy(Enum):
    """Mitigation strategy enumeration"""
    PREVENTION = "prevention"
    DETECTION = "detection"
    RESPONSE = "response"
    RECOVERY = "recovery"
    ACCEPTANCE = "acceptance"
    TRANSFER = "transfer"
    AVOIDANCE = "avoidance"


@dataclass
class ThreatActor:
    """Threat actor representation"""
    actor_id: str
    name: str
    category: ThreatCategory
    capabilities: List[str]
    motivation: List[str]
    resources: str
    sophistication: float  # 0-1 scale
    persistence: float  # 0-1 scale
    stealth: float  # 0-1 scale
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Threat:
    """Threat definition"""
    threat_id: str
    name: str
    description: str
    category: ThreatCategory
    attack_vectors: List[AttackVector]
    threat_level: ThreatLevel
    likelihood: float  # 0-1 scale
    impact: float  # 0-1 scale
    risk_score: float  # Calculated from likelihood * impact
    affected_assets: List[str]
    attack_patterns: List[str]
    indicators: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSurface:
    """Attack surface definition"""
    surface_id: str
    name: str
    description: str
    entry_points: List[str]
    exposed_services: List[str]
    data_flows: List[Dict[str, Any]]
    vulnerabilities: List[str]
    protection_mechanisms: List[str]
    risk_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatScenario:
    """Threat scenario definition"""
    scenario_id: str
    name: str
    description: str
    threat_actor: ThreatActor
    attack_vector: AttackVector
    attack_steps: List[Dict[str, Any]]
    success_probability: float
    impact_assessment: Dict[str, float]
    detection_probability: float
    mitigation_effectiveness: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    intelligence_id: str
    source: str
    threat_type: str
    indicators: List[str]
    confidence: float
    relevance: float
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Risk assessment result"""
    assessment_id: str
    threat_id: str
    asset_id: str
    risk_score: float
    likelihood: float
    impact: float
    mitigation_effectiveness: float
    residual_risk: float
    recommendations: List[str]
    priority: int


class LayeredThreatAnalyzer:
    """
    Comprehensive layered threat analysis system
    
    Features:
    - Multi-layered threat analysis
    - Attack surface mapping
    - Threat intelligence integration
    - Risk assessment and prioritization
    - Mitigation strategy development
    - Threat landscape monitoring
    - Attack pattern recognition
    - Threat modeling automation
    """
    
    def __init__(self):
        """Initialize layered threat analyzer"""
        self.threat_actors: Dict[str, ThreatActor] = {}
        self.threats: Dict[str, Threat] = {}
        self.attack_surfaces: Dict[str, AttackSurface] = {}
        self.threat_scenarios: Dict[str, ThreatScenario] = {}
        self.threat_intelligence: List[ThreatIntelligence] = []
        self.risk_assessments: List[RiskAssessment] = []
        
        # Analysis parameters
        self.risk_threshold = 0.7
        self.intelligence_confidence_threshold = 0.6
        self.pattern_similarity_threshold = 0.8
        
        # Initialize default threat actors and threats
        self._initialize_default_threats()
    
    def _initialize_default_threats(self):
        """Initialize default threat actors and threats"""
        # Threat Actors
        threat_actors = [
            ThreatActor(
                actor_id="apt_group",
                name="Advanced Persistent Threat Group",
                category=ThreatCategory.ADVANCED_PERSISTENT_THREAT,
                capabilities=["spear_phishing", "zero_day_exploits", "persistence", "lateral_movement"],
                motivation=["espionage", "data_theft", "sabotage"],
                resources="high",
                sophistication=0.9,
                persistence=0.95,
                stealth=0.9
            ),
            ThreatActor(
                actor_id="insider_threat",
                name="Malicious Insider",
                category=ThreatCategory.MALICIOUS_INSIDER,
                capabilities=["privileged_access", "knowledge_of_systems", "bypass_detection"],
                motivation=["financial_gain", "revenge", "ideology"],
                resources="medium",
                sophistication=0.7,
                persistence=0.8,
                stealth=0.8
            ),
            ThreatActor(
                actor_id="criminal_group",
                name="Criminal Organization",
                category=ThreatCategory.CRIMINAL_ORGANIZATION,
                capabilities=["ransomware", "social_engineering", "botnets"],
                motivation=["financial_gain"],
                resources="high",
                sophistication=0.8,
                persistence=0.6,
                stealth=0.7
            ),
            ThreatActor(
                actor_id="script_kiddie",
                name="Script Kiddie",
                category=ThreatCategory.SCRIPT_KIDDIE,
                capabilities=["automated_tools", "known_exploits"],
                motivation=["curiosity", "recognition"],
                resources="low",
                sophistication=0.3,
                persistence=0.2,
                stealth=0.3
            )
        ]
        
        for actor in threat_actors:
            self.threat_actors[actor.actor_id] = actor
        
        # Threats
        threats = [
            Threat(
                threat_id="data_exfiltration",
                name="Data Exfiltration",
                description="Unauthorized extraction of sensitive data",
                category=ThreatCategory.EXTERNAL_ATTACKER,
                attack_vectors=[AttackVector.NETWORK, AttackVector.INSIDER_ACCESS],
                threat_level=ThreatLevel.HIGH,
                likelihood=0.7,
                impact=0.9,
                risk_score=0.63,
                affected_assets=["databases", "file_systems", "cloud_storage"],
                attack_patterns=["lateral_movement", "privilege_escalation", "data_encryption"],
                indicators=["unusual_data_access", "large_data_transfers", "off_hours_activity"]
            ),
            Threat(
                threat_id="privilege_escalation",
                name="Privilege Escalation",
                description="Gaining higher-level access than authorized",
                category=ThreatCategory.MALICIOUS_INSIDER,
                attack_vectors=[AttackVector.INSIDER_ACCESS, AttackVector.SOCIAL_ENGINEERING],
                threat_level=ThreatLevel.HIGH,
                likelihood=0.6,
                impact=0.8,
                risk_score=0.48,
                affected_assets=["user_accounts", "admin_interfaces", "service_accounts"],
                attack_patterns=["credential_theft", "vulnerability_exploitation", "misconfiguration"],
                indicators=["unusual_privilege_usage", "failed_authentication", "account_anomalies"]
            ),
            Threat(
                threat_id="denial_of_service",
                name="Denial of Service",
                description="Disrupting service availability",
                category=ThreatCategory.EXTERNAL_ATTACKER,
                attack_vectors=[AttackVector.NETWORK, AttackVector.MALWARE],
                threat_level=ThreatLevel.MEDIUM,
                likelihood=0.8,
                impact=0.6,
                risk_score=0.48,
                affected_assets=["web_services", "api_endpoints", "network_infrastructure"],
                attack_patterns=["traffic_flooding", "resource_exhaustion", "distributed_attacks"],
                indicators=["high_traffic_volume", "resource_utilization", "service_unavailability"]
            ),
            Threat(
                threat_id="malware_infection",
                name="Malware Infection",
                description="Malicious software installation and execution",
                category=ThreatCategory.EXTERNAL_ATTACKER,
                attack_vectors=[AttackVector.MALWARE, AttackVector.SOCIAL_ENGINEERING],
                threat_level=ThreatLevel.HIGH,
                likelihood=0.5,
                impact=0.8,
                risk_score=0.4,
                affected_assets=["endpoints", "servers", "mobile_devices"],
                attack_patterns=["phishing", "drive_by_downloads", "removable_media"],
                indicators=["suspicious_processes", "network_anomalies", "file_modifications"]
            )
        ]
        
        for threat in threats:
            self.threats[threat.threat_id] = threat
    
    def add_threat_actor(self, actor: ThreatActor) -> bool:
        """Add a threat actor"""
        if actor.actor_id in self.threat_actors:
            return False
        
        self.threat_actors[actor.actor_id] = actor
        return True
    
    def add_threat(self, threat: Threat) -> bool:
        """Add a threat"""
        if threat.threat_id in self.threats:
            return False
        
        self.threats[threat.threat_id] = threat
        return True
    
    def map_attack_surface(self, surface: AttackSurface) -> bool:
        """Map an attack surface"""
        if surface.surface_id in self.attack_surfaces:
            return False
        
        self.attack_surfaces[surface.surface_id] = surface
        return True
    
    def create_threat_scenario(self, scenario: ThreatScenario) -> bool:
        """Create a threat scenario"""
        if scenario.scenario_id in self.threat_scenarios:
            return False
        
        self.threat_scenarios[scenario.scenario_id] = scenario
        return True
    
    def add_threat_intelligence(self, intelligence: ThreatIntelligence) -> bool:
        """Add threat intelligence"""
        self.threat_intelligence.append(intelligence)
        return True
    
    def analyze_threat_landscape(self) -> Dict[str, Any]:
        """
        Analyze the overall threat landscape
        
        Returns:
            Threat landscape analysis
        """
        analysis = {
            "threat_distribution": defaultdict(int),
            "attack_vector_distribution": defaultdict(int),
            "threat_level_distribution": defaultdict(int),
            "top_threats": [],
            "emerging_threats": [],
            "threat_trends": {},
            "risk_landscape": {}
        }
        
        # Analyze threat distribution by category
        for threat in self.threats.values():
            analysis["threat_distribution"][threat.category.value] += 1
            analysis["threat_level_distribution"][threat.threat_level.value] += 1
            
            for vector in threat.attack_vectors:
                analysis["attack_vector_distribution"][vector.value] += 1
        
        # Identify top threats by risk score
        sorted_threats = sorted(self.threats.values(), key=lambda t: t.risk_score, reverse=True)
        analysis["top_threats"] = [
            {
                "threat_id": threat.threat_id,
                "name": threat.name,
                "risk_score": threat.risk_score,
                "threat_level": threat.threat_level.value
            }
            for threat in sorted_threats[:5]
        ]
        
        # Identify emerging threats (recent intelligence)
        current_time = time.time()
        recent_intelligence = [
            intel for intel in self.threat_intelligence
            if current_time - intel.timestamp < 86400  # Last 24 hours
        ]
        
        analysis["emerging_threats"] = [
            {
                "intelligence_id": intel.intelligence_id,
                "threat_type": intel.threat_type,
                "confidence": intel.confidence,
                "relevance": intel.relevance
            }
            for intel in recent_intelligence
        ]
        
        # Calculate threat trends
        analysis["threat_trends"] = self._calculate_threat_trends()
        
        # Assess risk landscape
        analysis["risk_landscape"] = self._assess_risk_landscape()
        
        return analysis
    
    def _calculate_threat_trends(self) -> Dict[str, Any]:
        """Calculate threat trends over time"""
        trends = {
            "increasing_threats": [],
            "decreasing_threats": [],
            "stable_threats": [],
            "new_threats": []
        }
        
        # Analyze intelligence over time
        intelligence_by_time = defaultdict(list)
        for intel in self.threat_intelligence:
            day = int(intel.timestamp // 86400)
            intelligence_by_time[day].append(intel)
        
        # Calculate trends for each threat type
        threat_types = set(intel.threat_type for intel in self.threat_intelligence)
        
        for threat_type in threat_types:
            type_intelligence = [intel for intel in self.threat_intelligence if intel.threat_type == threat_type]
            
            if len(type_intelligence) < 2:
                continue
            
            # Calculate trend
            timestamps = [intel.timestamp for intel in type_intelligence]
            confidences = [intel.confidence for intel in type_intelligence]
            
            # Simple linear trend
            if len(timestamps) > 1:
                slope = np.polyfit(timestamps, confidences, 1)[0]
                
                if slope > 0.1:
                    trends["increasing_threats"].append(threat_type)
                elif slope < -0.1:
                    trends["decreasing_threats"].append(threat_type)
                else:
                    trends["stable_threats"].append(threat_type)
        
        return trends
    
    def _assess_risk_landscape(self) -> Dict[str, Any]:
        """Assess overall risk landscape"""
        risk_landscape = {
            "overall_risk_score": 0.0,
            "high_risk_threats": 0,
            "medium_risk_threats": 0,
            "low_risk_threats": 0,
            "critical_assets_at_risk": [],
            "mitigation_coverage": 0.0
        }
        
        # Calculate overall risk score
        if self.threats:
            total_risk = sum(threat.risk_score for threat in self.threats.values())
            risk_landscape["overall_risk_score"] = total_risk / len(self.threats)
        
        # Count threats by risk level
        for threat in self.threats.values():
            if threat.risk_score > 0.7:
                risk_landscape["high_risk_threats"] += 1
            elif threat.risk_score > 0.4:
                risk_landscape["medium_risk_threats"] += 1
            else:
                risk_landscape["low_risk_threats"] += 1
        
        # Identify critical assets at risk
        critical_assets = set()
        for threat in self.threats.values():
            if threat.risk_score > 0.6:
                critical_assets.update(threat.affected_assets)
        
        risk_landscape["critical_assets_at_risk"] = list(critical_assets)
        
        # Calculate mitigation coverage
        mitigated_threats = sum(1 for threat in self.threats.values() if threat.risk_score < 0.5)
        risk_landscape["mitigation_coverage"] = mitigated_threats / len(self.threats) if self.threats else 0.0
        
        return risk_landscape
    
    def assess_threat_risk(self, threat_id: str, asset_id: str) -> RiskAssessment:
        """
        Assess risk for a specific threat against an asset
        
        Args:
            threat_id: Threat identifier
            asset_id: Asset identifier
            
        Returns:
            Risk assessment
        """
        if threat_id not in self.threats:
            raise ValueError(f"Threat {threat_id} not found")
        
        threat = self.threats[threat_id]
        
        # Calculate likelihood based on threat intelligence
        likelihood = self._calculate_threat_likelihood(threat_id)
        
        # Calculate impact based on asset criticality
        impact = self._calculate_asset_impact(asset_id, threat)
        
        # Calculate risk score
        risk_score = likelihood * impact
        
        # Calculate mitigation effectiveness
        mitigation_effectiveness = self._calculate_mitigation_effectiveness(threat_id, asset_id)
        
        # Calculate residual risk
        residual_risk = risk_score * (1.0 - mitigation_effectiveness)
        
        # Generate recommendations
        recommendations = self._generate_risk_recommendations(threat_id, asset_id, risk_score)
        
        # Determine priority
        priority = self._calculate_risk_priority(risk_score, impact, likelihood)
        
        assessment = RiskAssessment(
            assessment_id=str(uuid.uuid4()),
            threat_id=threat_id,
            asset_id=asset_id,
            risk_score=risk_score,
            likelihood=likelihood,
            impact=impact,
            mitigation_effectiveness=mitigation_effectiveness,
            residual_risk=residual_risk,
            recommendations=recommendations,
            priority=priority
        )
        
        self.risk_assessments.append(assessment)
        return assessment
    
    def _calculate_threat_likelihood(self, threat_id: str) -> float:
        """Calculate threat likelihood based on intelligence"""
        threat = self.threats[threat_id]
        base_likelihood = threat.likelihood
        
        # Adjust based on recent intelligence
        relevant_intelligence = [
            intel for intel in self.threat_intelligence
            if threat_id in intel.threat_type or any(pattern in intel.indicators for pattern in threat.attack_patterns)
        ]
        
        if relevant_intelligence:
            # Weight recent intelligence more heavily
            current_time = time.time()
            weighted_confidence = 0.0
            total_weight = 0.0
            
            for intel in relevant_intelligence:
                age = current_time - intel.timestamp
                weight = 1.0 / (1.0 + age / 86400)  # Decay over days
                weighted_confidence += intel.confidence * weight
                total_weight += weight
            
            if total_weight > 0:
                avg_confidence = weighted_confidence / total_weight
                # Adjust likelihood based on intelligence confidence
                adjusted_likelihood = base_likelihood * (0.5 + 0.5 * avg_confidence)
                return min(1.0, adjusted_likelihood)
        
        return base_likelihood
    
    def _calculate_asset_impact(self, asset_id: str, threat: Threat) -> float:
        """Calculate impact of threat on asset"""
        # Base impact from threat definition
        base_impact = threat.impact
        
        # Adjust based on asset criticality (simplified)
        asset_criticality = {
            "databases": 0.9,
            "admin_interfaces": 0.8,
            "user_accounts": 0.7,
            "file_systems": 0.8,
            "cloud_storage": 0.7,
            "web_services": 0.6,
            "api_endpoints": 0.7,
            "network_infrastructure": 0.8,
            "endpoints": 0.6,
            "servers": 0.8,
            "mobile_devices": 0.5
        }
        
        criticality = asset_criticality.get(asset_id, 0.5)
        
        # Check if asset is affected by this threat
        if asset_id in threat.affected_assets:
            impact_multiplier = 1.0
        else:
            impact_multiplier = 0.5  # Reduced impact for non-directly affected assets
        
        return base_impact * criticality * impact_multiplier
    
    def _calculate_mitigation_effectiveness(self, threat_id: str, asset_id: str) -> float:
        """Calculate effectiveness of existing mitigations"""
        # Simplified mitigation effectiveness calculation
        # In a real implementation, this would consider actual security controls
        
        threat = self.threats[threat_id]
        effectiveness = 0.0
        
        # Base effectiveness based on threat level
        if threat.threat_level == ThreatLevel.LOW:
            effectiveness = 0.8
        elif threat.threat_level == ThreatLevel.MEDIUM:
            effectiveness = 0.6
        elif threat.threat_level == ThreatLevel.HIGH:
            effectiveness = 0.4
        else:  # CRITICAL
            effectiveness = 0.2
        
        # Adjust based on attack vectors
        for vector in threat.attack_vectors:
            if vector == AttackVector.NETWORK:
                effectiveness += 0.1  # Network controls are common
            elif vector == AttackVector.INSIDER_ACCESS:
                effectiveness -= 0.1  # Insider threats are harder to mitigate
            elif vector == AttackVector.SOCIAL_ENGINEERING:
                effectiveness -= 0.05  # Social engineering is hard to prevent
        
        return max(0.0, min(1.0, effectiveness))
    
    def _generate_risk_recommendations(self, threat_id: str, asset_id: str, risk_score: float) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        threat = self.threats[threat_id]
        
        if risk_score > 0.7:
            recommendations.append("Implement immediate mitigation measures")
            recommendations.append("Increase monitoring and detection capabilities")
            recommendations.append("Consider threat-specific security controls")
        
        if risk_score > 0.5:
            recommendations.append("Review and update security policies")
            recommendations.append("Conduct security awareness training")
            recommendations.append("Implement additional access controls")
        
        # Threat-specific recommendations
        if threat.threat_id == "data_exfiltration":
            recommendations.extend([
                "Implement data loss prevention (DLP) solutions",
                "Encrypt sensitive data at rest and in transit",
                "Monitor data access patterns",
                "Implement data classification and labeling"
            ])
        elif threat.threat_id == "privilege_escalation":
            recommendations.extend([
                "Implement principle of least privilege",
                "Regular access reviews and audits",
                "Multi-factor authentication for privileged accounts",
                "Privileged access management (PAM) solution"
            ])
        elif threat.threat_id == "denial_of_service":
            recommendations.extend([
                "Implement DDoS protection",
                "Load balancing and traffic management",
                "Rate limiting and throttling",
                "Incident response procedures"
            ])
        elif threat.threat_id == "malware_infection":
            recommendations.extend([
                "Endpoint detection and response (EDR) solutions",
                "Regular security updates and patches",
                "Email security and web filtering",
                "User security awareness training"
            ])
        
        return recommendations
    
    def _calculate_risk_priority(self, risk_score: float, impact: float, likelihood: float) -> int:
        """Calculate risk priority (1-5, where 5 is highest priority)"""
        if risk_score > 0.8:
            return 5
        elif risk_score > 0.6:
            return 4
        elif risk_score > 0.4:
            return 3
        elif risk_score > 0.2:
            return 2
        else:
            return 1
    
    def detect_attack_patterns(self, indicators: List[str]) -> List[Dict[str, Any]]:
        """
        Detect attack patterns from indicators
        
        Args:
            indicators: List of security indicators
            
        Returns:
            List of detected attack patterns
        """
        detected_patterns = []
        
        for threat in self.threats.values():
            # Calculate similarity between indicators and threat indicators
            similarity = self._calculate_indicator_similarity(indicators, threat.indicators)
            
            if similarity > self.pattern_similarity_threshold:
                detected_patterns.append({
                    "threat_id": threat.threat_id,
                    "threat_name": threat.name,
                    "similarity_score": similarity,
                    "matched_indicators": list(set(indicators) & set(threat.indicators)),
                    "attack_patterns": threat.attack_patterns,
                    "risk_score": threat.risk_score
                })
        
        # Sort by similarity score
        detected_patterns.sort(key=lambda x: x["similarity_score"], reverse=True)
        
        return detected_patterns
    
    def _calculate_indicator_similarity(self, indicators1: List[str], indicators2: List[str]) -> float:
        """Calculate similarity between two sets of indicators"""
        if not indicators1 or not indicators2:
            return 0.0
        
        set1 = set(indicators1)
        set2 = set(indicators2)
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def prioritize_threats(self) -> List[Dict[str, Any]]:
        """Prioritize threats based on risk assessment"""
        if not self.risk_assessments:
            return []
        
        # Group assessments by threat
        threat_assessments = defaultdict(list)
        for assessment in self.risk_assessments:
            threat_assessments[assessment.threat_id].append(assessment)
        
        # Calculate priority for each threat
        threat_priorities = []
        
        for threat_id, assessments in threat_assessments.items():
            # Calculate average risk score
            avg_risk_score = sum(a.risk_score for a in assessments) / len(assessments)
            
            # Calculate average residual risk
            avg_residual_risk = sum(a.residual_risk for a in assessments) / len(assessments)
            
            # Calculate priority score
            priority_score = avg_risk_score * 0.7 + avg_residual_risk * 0.3
            
            threat_priorities.append({
                "threat_id": threat_id,
                "threat_name": self.threats[threat_id].name,
                "priority_score": priority_score,
                "avg_risk_score": avg_risk_score,
                "avg_residual_risk": avg_residual_risk,
                "assessment_count": len(assessments),
                "recommendations": list(set().union(*[a.recommendations for a in assessments]))
            })
        
        # Sort by priority score
        threat_priorities.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return threat_priorities
    
    def get_threat_metrics(self) -> Dict[str, Any]:
        """Get threat analysis metrics"""
        return {
            "total_threats": len(self.threats),
            "total_threat_actors": len(self.threat_actors),
            "total_attack_surfaces": len(self.attack_surfaces),
            "total_threat_scenarios": len(self.threat_scenarios),
            "total_intelligence_items": len(self.threat_intelligence),
            "total_risk_assessments": len(self.risk_assessments),
            "high_risk_threats": len([t for t in self.threats.values() if t.risk_score > 0.7]),
            "critical_threats": len([t for t in self.threats.values() if t.threat_level == ThreatLevel.CRITICAL]),
            "recent_intelligence": len([i for i in self.threat_intelligence if time.time() - i.timestamp < 86400])
        }
    
    def export_threat_analysis(self, file_path: str) -> bool:
        """Export threat analysis to file"""
        try:
            # Get threat landscape analysis
            landscape_analysis = self.analyze_threat_landscape()
            
            # Get threat priorities
            threat_priorities = self.prioritize_threats()
            
            # Get metrics
            metrics = self.get_threat_metrics()
            
            export_data = {
                "threat_actors": {
                    actor_id: {
                        "actor_id": actor.actor_id,
                        "name": actor.name,
                        "category": actor.category.value,
                        "capabilities": actor.capabilities,
                        "motivation": actor.motivation,
                        "resources": actor.resources,
                        "sophistication": actor.sophistication,
                        "persistence": actor.persistence,
                        "stealth": actor.stealth,
                        "metadata": actor.metadata
                    }
                    for actor_id, actor in self.threat_actors.items()
                },
                "threats": {
                    threat_id: {
                        "threat_id": threat.threat_id,
                        "name": threat.name,
                        "description": threat.description,
                        "category": threat.category.value,
                        "attack_vectors": [av.value for av in threat.attack_vectors],
                        "threat_level": threat.threat_level.value,
                        "likelihood": threat.likelihood,
                        "impact": threat.impact,
                        "risk_score": threat.risk_score,
                        "affected_assets": threat.affected_assets,
                        "attack_patterns": threat.attack_patterns,
                        "indicators": threat.indicators,
                        "metadata": threat.metadata
                    }
                    for threat_id, threat in self.threats.items()
                },
                "attack_surfaces": {
                    surface_id: {
                        "surface_id": surface.surface_id,
                        "name": surface.name,
                        "description": surface.description,
                        "entry_points": surface.entry_points,
                        "exposed_services": surface.exposed_services,
                        "data_flows": surface.data_flows,
                        "vulnerabilities": surface.vulnerabilities,
                        "protection_mechanisms": surface.protection_mechanisms,
                        "risk_score": surface.risk_score,
                        "metadata": surface.metadata
                    }
                    for surface_id, surface in self.attack_surfaces.items()
                },
                "threat_scenarios": {
                    scenario_id: {
                        "scenario_id": scenario.scenario_id,
                        "name": scenario.name,
                        "description": scenario.description,
                        "threat_actor": scenario.threat_actor.actor_id,
                        "attack_vector": scenario.attack_vector.value,
                        "attack_steps": scenario.attack_steps,
                        "success_probability": scenario.success_probability,
                        "impact_assessment": scenario.impact_assessment,
                        "detection_probability": scenario.detection_probability,
                        "mitigation_effectiveness": scenario.mitigation_effectiveness,
                        "metadata": scenario.metadata
                    }
                    for scenario_id, scenario in self.threat_scenarios.items()
                },
                "threat_intelligence": [
                    {
                        "intelligence_id": intel.intelligence_id,
                        "source": intel.source,
                        "threat_type": intel.threat_type,
                        "indicators": intel.indicators,
                        "confidence": intel.confidence,
                        "relevance": intel.relevance,
                        "timestamp": intel.timestamp,
                        "metadata": intel.metadata
                    }
                    for intel in self.threat_intelligence
                ],
                "risk_assessments": [
                    {
                        "assessment_id": assessment.assessment_id,
                        "threat_id": assessment.threat_id,
                        "asset_id": assessment.asset_id,
                        "risk_score": assessment.risk_score,
                        "likelihood": assessment.likelihood,
                        "impact": assessment.impact,
                        "mitigation_effectiveness": assessment.mitigation_effectiveness,
                        "residual_risk": assessment.residual_risk,
                        "recommendations": assessment.recommendations,
                        "priority": assessment.priority
                    }
                    for assessment in self.risk_assessments
                ],
                "landscape_analysis": landscape_analysis,
                "threat_priorities": threat_priorities,
                "metrics": metrics,
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting threat analysis: {e}")
            return False
