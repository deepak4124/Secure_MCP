"""
Security Analyzer - Main Coordinator

This module provides the main security analysis coordinator that integrates:
- Role-based security analysis
- Topological security analysis
- Comprehensive security reporting
- Security metrics aggregation
"""

import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from .role_based_security import RoleBasedSecurityAnalyzer, RoleType, PermissionType, RolePermission
from .topological_analysis import TopologicalSecurityAnalyzer, NetworkNode, NetworkNodeType, NetworkConnection, ConnectionType


class SecurityAnalysisType(Enum):
    """Security analysis type enumeration"""
    ROLE_BASED = "role_based"
    TOPOLOGICAL = "topological"
    COMPREHENSIVE = "comprehensive"
    VULNERABILITY = "vulnerability"
    RISK_ASSESSMENT = "risk_assessment"


@dataclass
class SecurityAnalysisResult:
    """Security analysis result data structure"""
    analysis_type: SecurityAnalysisType
    timestamp: float
    results: Dict[str, Any]
    recommendations: List[str]
    risk_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityMetrics:
    """Comprehensive security metrics"""
    overall_security_score: float  # 0.0 to 1.0
    role_security_score: float
    topology_security_score: float
    vulnerability_count: int
    critical_vulnerabilities: int
    high_risk_areas: int
    last_analyzed: float
    analysis_history: List[SecurityAnalysisResult] = field(default_factory=list)


class SecurityAnalyzer:
    """
    Main security analysis coordinator
    
    Features:
    - Integrates role-based and topological analysis
    - Provides comprehensive security assessment
    - Generates actionable security recommendations
    - Tracks security metrics over time
    """
    
    def __init__(self):
        """Initialize security analyzer"""
        self.role_analyzer = RoleBasedSecurityAnalyzer()
        self.topology_analyzer = TopologicalSecurityAnalyzer()
        self.analysis_history: List[SecurityAnalysisResult] = []
        self.metrics: Optional[SecurityMetrics] = None
        
        # Analysis configuration
        self.analysis_weights = {
            "role_based": 0.4,
            "topological": 0.3,
            "vulnerability": 0.2,
            "risk_assessment": 0.1
        }
        
        # Risk thresholds
        self.risk_thresholds = {
            "low": 0.8,
            "medium": 0.6,
            "high": 0.4,
            "critical": 0.2
        }
    
    def register_agent_role(self, agent_id: str, role_type: RoleType, 
                           capabilities: List[str], trust_score: float = 0.5,
                           metadata: Dict[str, Any] = None) -> bool:
        """
        Register an agent with a specific role
        
        Args:
            agent_id: Agent identifier
            role_type: Type of role
            capabilities: List of capabilities
            trust_score: Initial trust score
            metadata: Additional metadata
            
        Returns:
            True if registration successful
        """
        try:
            # Register role in role analyzer
            role_success = self.role_analyzer.register_role(
                agent_id, role_type, capabilities, metadata
            )
            
            # Register node in topology analyzer
            node = NetworkNode(
                node_id=agent_id,
                node_type=NetworkNodeType.AGENT,
                trust_score=trust_score,
                security_level="medium",
                capabilities=capabilities,
                metadata=metadata or {}
            )
            topology_success = self.topology_analyzer.add_node(node)
            
            return role_success and topology_success
            
        except Exception as e:
            print(f"Error registering agent role {agent_id}: {e}")
            return False
    
    def add_agent_permission(self, agent_id: str, permission: RolePermission) -> bool:
        """
        Add a permission to an agent's role
        
        Args:
            agent_id: Agent identifier
            permission: Permission to add
            
        Returns:
            True if permission added successfully
        """
        try:
            return self.role_analyzer.add_permission(agent_id, permission)
        except Exception as e:
            print(f"Error adding permission to agent {agent_id}: {e}")
            return False
    
    def add_network_connection(self, source_id: str, target_id: str, 
                              connection_type: ConnectionType, 
                              security_level: str = "medium",
                              metadata: Dict[str, Any] = None) -> bool:
        """
        Add a network connection between agents
        
        Args:
            source_id: Source agent identifier
            target_id: Target agent identifier
            connection_type: Type of connection
            security_level: Security level of connection
            metadata: Additional metadata
            
        Returns:
            True if connection added successfully
        """
        try:
            connection = NetworkConnection(
                source_id=source_id,
                target_id=target_id,
                connection_type=connection_type,
                security_level=security_level,
                metadata=metadata or {}
            )
            return self.topology_analyzer.add_connection(connection)
        except Exception as e:
            print(f"Error adding network connection {source_id}->{target_id}: {e}")
            return False
    
    def perform_comprehensive_analysis(self) -> SecurityAnalysisResult:
        """
        Perform comprehensive security analysis
        
        Returns:
            Comprehensive security analysis result
        """
        try:
            start_time = time.time()
            
            # Perform role-based analysis
            role_analysis = self._perform_role_based_analysis()
            
            # Perform topological analysis
            topology_analysis = self._perform_topological_analysis()
            
            # Perform vulnerability assessment
            vulnerability_analysis = self._perform_vulnerability_assessment()
            
            # Perform risk assessment
            risk_assessment = self._perform_risk_assessment()
            
            # Aggregate results
            comprehensive_results = {
                "role_analysis": role_analysis,
                "topology_analysis": topology_analysis,
                "vulnerability_analysis": vulnerability_analysis,
                "risk_assessment": risk_assessment,
                "analysis_duration": time.time() - start_time
            }
            
            # Calculate overall risk score
            risk_score = self._calculate_overall_risk_score(comprehensive_results)
            
            # Generate recommendations
            recommendations = self._generate_comprehensive_recommendations(comprehensive_results)
            
            # Create analysis result
            result = SecurityAnalysisResult(
                analysis_type=SecurityAnalysisType.COMPREHENSIVE,
                timestamp=time.time(),
                results=comprehensive_results,
                recommendations=recommendations,
                risk_score=risk_score,
                confidence=self._calculate_analysis_confidence(comprehensive_results),
                metadata={
                    "analysis_duration": time.time() - start_time,
                    "components_analyzed": ["role_based", "topological", "vulnerability", "risk_assessment"]
                }
            )
            
            # Store in history
            self.analysis_history.append(result)
            
            # Update metrics
            self._update_security_metrics(result)
            
            return result
            
        except Exception as e:
            print(f"Error performing comprehensive analysis: {e}")
            return SecurityAnalysisResult(
                analysis_type=SecurityAnalysisType.COMPREHENSIVE,
                timestamp=time.time(),
                results={"error": str(e)},
                recommendations=["Fix analysis errors and retry"],
                risk_score=1.0,  # High risk due to analysis failure
                confidence=0.0
            )
    
    def _perform_role_based_analysis(self) -> Dict[str, Any]:
        """Perform role-based security analysis"""
        try:
            role_analysis = {
                "roles_analyzed": 0,
                "vulnerabilities_found": 0,
                "high_risk_roles": 0,
                "security_scores": {},
                "recommendations": []
            }
            
            # Analyze each role
            for role_id in self.role_analyzer.roles:
                # Analyze vulnerabilities
                vulnerabilities = self.role_analyzer.analyze_role_vulnerabilities(role_id)
                
                # Calculate metrics
                metrics = self.role_analyzer.calculate_role_security_metrics(role_id)
                
                # Generate report
                report = self.role_analyzer.get_role_security_report(role_id)
                
                role_analysis["roles_analyzed"] += 1
                role_analysis["vulnerabilities_found"] += len(vulnerabilities)
                
                if metrics and metrics.security_score < 0.7:
                    role_analysis["high_risk_roles"] += 1
                
                role_analysis["security_scores"][role_id] = metrics.security_score if metrics else 0.0
            
            # Get overall summary
            summary = self.role_analyzer.get_all_roles_security_summary()
            role_analysis.update(summary)
            
            return role_analysis
            
        except Exception as e:
            print(f"Error performing role-based analysis: {e}")
            return {"error": str(e)}
    
    def _perform_topological_analysis(self) -> Dict[str, Any]:
        """Perform topological security analysis"""
        try:
            return self.topology_analyzer.analyze_network_topology()
        except Exception as e:
            print(f"Error performing topological analysis: {e}")
            return {"error": str(e)}
    
    def _perform_vulnerability_assessment(self) -> Dict[str, Any]:
        """Perform comprehensive vulnerability assessment"""
        try:
            vulnerability_assessment = {
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "vulnerability_types": {},
                "affected_components": [],
                "recommendations": []
            }
            
            # Collect role-based vulnerabilities
            for role_id in self.role_analyzer.roles:
                vulnerabilities = self.role_analyzer.vulnerabilities.get(role_id, [])
                for vuln in vulnerabilities:
                    vulnerability_assessment["total_vulnerabilities"] += 1
                    
                    # Count by severity
                    if vuln.risk_level.value == "critical":
                        vulnerability_assessment["critical_vulnerabilities"] += 1
                    elif vuln.risk_level.value == "high":
                        vulnerability_assessment["high_vulnerabilities"] += 1
                    elif vuln.risk_level.value == "medium":
                        vulnerability_assessment["medium_vulnerabilities"] += 1
                    else:
                        vulnerability_assessment["low_vulnerabilities"] += 1
                    
                    # Count by type
                    vuln_type = vuln.vulnerability_type
                    vulnerability_assessment["vulnerability_types"][vuln_type] = \
                        vulnerability_assessment["vulnerability_types"].get(vuln_type, 0) + 1
                    
                    # Track affected components
                    if role_id not in vulnerability_assessment["affected_components"]:
                        vulnerability_assessment["affected_components"].append(role_id)
            
            # Collect topology vulnerabilities
            topology_vulns = self.topology_analyzer._identify_topology_vulnerabilities()
            for vuln in topology_vulns:
                vulnerability_assessment["total_vulnerabilities"] += 1
                
                if vuln["risk_level"] == "critical":
                    vulnerability_assessment["critical_vulnerabilities"] += 1
                elif vuln["risk_level"] == "high":
                    vulnerability_assessment["high_vulnerabilities"] += 1
                elif vuln["risk_level"] == "medium":
                    vulnerability_assessment["medium_vulnerabilities"] += 1
                else:
                    vulnerability_assessment["low_vulnerabilities"] += 1
                
                vuln_type = vuln["type"]
                vulnerability_assessment["vulnerability_types"][vuln_type] = \
                    vulnerability_assessment["vulnerability_types"].get(vuln_type, 0) + 1
            
            # Generate recommendations
            if vulnerability_assessment["critical_vulnerabilities"] > 0:
                vulnerability_assessment["recommendations"].append(
                    f"URGENT: {vulnerability_assessment['critical_vulnerabilities']} critical vulnerabilities found"
                )
            
            if vulnerability_assessment["high_vulnerabilities"] > 3:
                vulnerability_assessment["recommendations"].append(
                    f"HIGH: {vulnerability_assessment['high_vulnerabilities']} high-risk vulnerabilities need attention"
                )
            
            return vulnerability_assessment
            
        except Exception as e:
            print(f"Error performing vulnerability assessment: {e}")
            return {"error": str(e)}
    
    def _perform_risk_assessment(self) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        try:
            risk_assessment = {
                "overall_risk_level": "low",
                "risk_factors": {},
                "risk_score": 0.0,
                "mitigation_priorities": [],
                "recommendations": []
            }
            
            # Calculate risk factors
            role_summary = self.role_analyzer.get_all_roles_security_summary()
            topology_analysis = self.topology_analyzer.analyze_network_topology()
            
            # Role-based risk factors
            role_risk = 1.0 - role_summary.get("overall_metrics", {}).get("average_security_score", 0.5)
            risk_assessment["risk_factors"]["role_security"] = role_risk
            
            # Topology-based risk factors
            resilience = topology_analysis.get("resilience_analysis", {}).get("overall_resilience", 0.5)
            topology_risk = 1.0 - resilience
            risk_assessment["risk_factors"]["topology_resilience"] = topology_risk
            
            # Centrality risk
            centrality_risk = 0.0
            centrality_analysis = topology_analysis.get("centrality_analysis", {})
            if centrality_analysis.get("risk_assessment", {}).get("overall_risk") == "high":
                centrality_risk = 0.8
            elif centrality_analysis.get("risk_assessment", {}).get("overall_risk") == "medium":
                centrality_risk = 0.5
            risk_assessment["risk_factors"]["centrality_risk"] = centrality_risk
            
            # Attack surface risk
            attack_surface = topology_analysis.get("attack_paths", {}).get("attack_surface", {})
            attack_surface_risk = attack_surface.get("attack_surface_score", 0.0)
            risk_assessment["risk_factors"]["attack_surface"] = attack_surface_risk
            
            # Calculate overall risk score
            risk_score = (
                role_risk * 0.3 +
                topology_risk * 0.25 +
                centrality_risk * 0.25 +
                attack_surface_risk * 0.2
            )
            risk_assessment["risk_score"] = round(risk_score, 3)
            
            # Determine risk level
            if risk_score >= 0.8:
                risk_assessment["overall_risk_level"] = "critical"
            elif risk_score >= 0.6:
                risk_assessment["overall_risk_level"] = "high"
            elif risk_score >= 0.4:
                risk_assessment["overall_risk_level"] = "medium"
            else:
                risk_assessment["overall_risk_level"] = "low"
            
            # Generate mitigation priorities
            if role_risk > 0.7:
                risk_assessment["mitigation_priorities"].append("Improve role security")
            if topology_risk > 0.7:
                risk_assessment["mitigation_priorities"].append("Enhance network resilience")
            if centrality_risk > 0.6:
                risk_assessment["mitigation_priorities"].append("Reduce network centralization")
            if attack_surface_risk > 0.6:
                risk_assessment["mitigation_priorities"].append("Reduce attack surface")
            
            return risk_assessment
            
        except Exception as e:
            print(f"Error performing risk assessment: {e}")
            return {"error": str(e)}
    
    def _calculate_overall_risk_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate overall risk score from analysis results"""
        try:
            # Extract individual risk scores
            role_analysis = analysis_results.get("role_analysis", {})
            topology_analysis = analysis_results.get("topology_analysis", {})
            vulnerability_analysis = analysis_results.get("vulnerability_analysis", {})
            risk_assessment = analysis_results.get("risk_assessment", {})
            
            # Role-based risk
            role_security_score = role_analysis.get("overall_metrics", {}).get("average_security_score", 0.5)
            role_risk = 1.0 - role_security_score
            
            # Topology risk
            resilience = topology_analysis.get("resilience_analysis", {}).get("overall_resilience", 0.5)
            topology_risk = 1.0 - resilience
            
            # Vulnerability risk
            total_vulns = vulnerability_analysis.get("total_vulnerabilities", 0)
            critical_vulns = vulnerability_analysis.get("critical_vulnerabilities", 0)
            vulnerability_risk = min(1.0, (critical_vulns * 0.5 + total_vulns * 0.1) / 10.0)
            
            # Risk assessment score
            risk_score = risk_assessment.get("risk_score", 0.5)
            
            # Calculate weighted overall risk
            overall_risk = (
                role_risk * self.analysis_weights["role_based"] +
                topology_risk * self.analysis_weights["topological"] +
                vulnerability_risk * self.analysis_weights["vulnerability"] +
                risk_score * self.analysis_weights["risk_assessment"]
            )
            
            return round(overall_risk, 3)
            
        except Exception as e:
            print(f"Error calculating overall risk score: {e}")
            return 0.5  # Default medium risk
    
    def _calculate_analysis_confidence(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate confidence in analysis results"""
        try:
            confidence_factors = []
            
            # Role analysis confidence
            role_analysis = analysis_results.get("role_analysis", {})
            roles_analyzed = role_analysis.get("roles_analyzed", 0)
            role_confidence = min(1.0, roles_analyzed / 5.0)  # More roles = higher confidence
            confidence_factors.append(role_confidence)
            
            # Topology analysis confidence
            topology_analysis = analysis_results.get("topology_analysis", {})
            total_nodes = topology_analysis.get("basic_metrics", {}).get("total_nodes", 0)
            topology_confidence = min(1.0, total_nodes / 10.0)  # More nodes = higher confidence
            confidence_factors.append(topology_confidence)
            
            # Vulnerability analysis confidence
            vulnerability_analysis = analysis_results.get("vulnerability_analysis", {})
            total_vulns = vulnerability_analysis.get("total_vulnerabilities", 0)
            vuln_confidence = min(1.0, total_vulns / 20.0)  # More vulnerabilities found = higher confidence
            confidence_factors.append(vuln_confidence)
            
            # Calculate average confidence
            overall_confidence = sum(confidence_factors) / len(confidence_factors)
            return round(overall_confidence, 3)
            
        except Exception as e:
            print(f"Error calculating analysis confidence: {e}")
            return 0.5  # Default medium confidence
    
    def _generate_comprehensive_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate comprehensive security recommendations"""
        recommendations = []
        
        try:
            # Role-based recommendations
            role_analysis = analysis_results.get("role_analysis", {})
            if role_analysis.get("overall_metrics", {}).get("average_security_score", 1.0) < 0.7:
                recommendations.append("HIGH: Improve role security scores - implement least privilege principle")
            
            # Topology recommendations
            topology_analysis = analysis_results.get("topology_analysis", {})
            resilience = topology_analysis.get("resilience_analysis", {}).get("overall_resilience", 1.0)
            if resilience < 0.6:
                recommendations.append("HIGH: Improve network resilience - add redundant connections")
            
            # Vulnerability recommendations
            vulnerability_analysis = analysis_results.get("vulnerability_analysis", {})
            critical_vulns = vulnerability_analysis.get("critical_vulnerabilities", 0)
            if critical_vulns > 0:
                recommendations.append(f"CRITICAL: Address {critical_vulns} critical vulnerabilities immediately")
            
            # Risk assessment recommendations
            risk_assessment = analysis_results.get("risk_assessment", {})
            risk_level = risk_assessment.get("overall_risk_level", "low")
            if risk_level in ["high", "critical"]:
                recommendations.append(f"URGENT: Overall risk level is {risk_level.upper()}")
            
            # General recommendations
            recommendations.extend([
                "Implement regular security assessments",
                "Monitor security metrics continuously",
                "Update security policies based on analysis results",
                "Conduct penetration testing",
                "Implement security awareness training"
            ])
            
        except Exception as e:
            print(f"Error generating recommendations: {e}")
            recommendations.append("Error generating recommendations - check analysis results")
        
        return recommendations
    
    def _update_security_metrics(self, analysis_result: SecurityAnalysisResult):
        """Update security metrics based on analysis result"""
        try:
            # Calculate component scores
            role_analysis = analysis_result.results.get("role_analysis", {})
            topology_analysis = analysis_result.results.get("topology_analysis", {})
            vulnerability_analysis = analysis_result.results.get("vulnerability_analysis", {})
            
            role_score = role_analysis.get("overall_metrics", {}).get("average_security_score", 0.5)
            topology_score = topology_analysis.get("resilience_analysis", {}).get("overall_resilience", 0.5)
            
            # Calculate overall security score
            overall_score = (role_score + topology_score) / 2
            
            # Count vulnerabilities
            total_vulns = vulnerability_analysis.get("total_vulnerabilities", 0)
            critical_vulns = vulnerability_analysis.get("critical_vulnerabilities", 0)
            
            # Count high-risk areas
            high_risk_areas = 0
            if role_score < 0.7:
                high_risk_areas += 1
            if topology_score < 0.7:
                high_risk_areas += 1
            if critical_vulns > 0:
                high_risk_areas += 1
            
            # Create or update metrics
            self.metrics = SecurityMetrics(
                overall_security_score=overall_score,
                role_security_score=role_score,
                topology_security_score=topology_score,
                vulnerability_count=total_vulns,
                critical_vulnerabilities=critical_vulns,
                high_risk_areas=high_risk_areas,
                last_analyzed=time.time(),
                analysis_history=self.analysis_history[-10:]  # Keep last 10 analyses
            )
            
        except Exception as e:
            print(f"Error updating security metrics: {e}")
    
    def get_security_dashboard(self) -> Dict[str, Any]:
        """Generate security dashboard data"""
        try:
            dashboard = {
                "current_metrics": self.metrics.__dict__ if self.metrics else {},
                "recent_analysis": self.analysis_history[-5:] if self.analysis_history else [],
                "role_summary": self.role_analyzer.get_all_roles_security_summary(),
                "topology_summary": self.topology_analyzer.get_topology_security_report(),
                "alerts": self._generate_security_alerts(),
                "generated_at": time.time()
            }
            
            return dashboard
            
        except Exception as e:
            print(f"Error generating security dashboard: {e}")
            return {"error": str(e)}
    
    def _generate_security_alerts(self) -> List[Dict[str, Any]]:
        """Generate security alerts based on current state"""
        alerts = []
        
        try:
            if not self.metrics:
                return alerts
            
            # Critical vulnerabilities alert
            if self.metrics.critical_vulnerabilities > 0:
                alerts.append({
                    "level": "critical",
                    "message": f"{self.metrics.critical_vulnerabilities} critical vulnerabilities detected",
                    "action": "immediate_attention_required",
                    "timestamp": time.time()
                })
            
            # Low security score alert
            if self.metrics.overall_security_score < 0.5:
                alerts.append({
                    "level": "critical",
                    "message": "Overall security score is critically low",
                    "action": "comprehensive_security_review_required",
                    "timestamp": time.time()
                })
            elif self.metrics.overall_security_score < 0.7:
                alerts.append({
                    "level": "high",
                    "message": "Overall security score is below recommended threshold",
                    "action": "security_improvements_needed",
                    "timestamp": time.time()
                })
            
            # High-risk areas alert
            if self.metrics.high_risk_areas > 2:
                alerts.append({
                    "level": "high",
                    "message": f"{self.metrics.high_risk_areas} high-risk areas identified",
                    "action": "risk_mitigation_required",
                    "timestamp": time.time()
                })
            
        except Exception as e:
            print(f"Error generating security alerts: {e}")
        
        return alerts
    
    def export_analysis_report(self, format: str = "json") -> str:
        """Export comprehensive analysis report"""
        try:
            if format.lower() == "json":
                report = {
                    "security_metrics": self.metrics.__dict__ if self.metrics else {},
                    "analysis_history": [result.__dict__ for result in self.analysis_history],
                    "role_analysis": self.role_analyzer.get_all_roles_security_summary(),
                    "topology_analysis": self.topology_analyzer.get_topology_security_report(),
                    "exported_at": time.time()
                }
                return json.dumps(report, indent=2, default=str)
            else:
                return "Unsupported format. Use 'json'."
                
        except Exception as e:
            print(f"Error exporting analysis report: {e}")
            return f"Error: {str(e)}"
