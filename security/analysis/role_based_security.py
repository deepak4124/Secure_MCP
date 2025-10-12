"""
Role-Based Security Analysis

This module provides comprehensive role-based security analysis including:
- Role vulnerability assessment
- Role permission analysis
- Role escalation risk detection
- Role-based security metrics
"""

import time
import math
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict

from pydantic import BaseModel, Field


class RoleType(Enum):
    """Role type enumeration"""
    ADMIN = "admin"
    COORDINATOR = "coordinator"
    WORKER = "worker"
    MONITOR = "monitor"
    GATEWAY = "gateway"
    AUDITOR = "auditor"
    GUEST = "guest"


class PermissionType(Enum):
    """Permission type enumeration"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"
    AUDIT = "audit"


class SecurityRiskLevel(Enum):
    """Security risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RolePermission:
    """Role permission data structure"""
    permission_type: PermissionType
    resource: str
    conditions: Dict[str, Any] = field(default_factory=dict)
    granted: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoleVulnerability:
    """Role vulnerability data structure"""
    role_id: str
    vulnerability_type: str
    risk_level: SecurityRiskLevel
    description: str
    impact_score: float  # 0.0 to 1.0
    likelihood_score: float  # 0.0 to 1.0
    mitigation_suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoleSecurityMetrics:
    """Role security metrics data structure"""
    role_id: str
    total_permissions: int
    high_risk_permissions: int
    vulnerability_count: int
    escalation_risks: int
    access_frequency: float
    security_score: float  # 0.0 to 1.0
    last_analyzed: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class RoleBasedSecurityAnalyzer:
    """
    Comprehensive role-based security analysis system
    
    Features:
    - Role vulnerability assessment
    - Permission analysis and risk evaluation
    - Role escalation detection
    - Security metrics calculation
    - Risk prioritization and reporting
    """
    
    def __init__(self):
        """Initialize role-based security analyzer"""
        self.roles: Dict[str, Dict] = {}
        self.permissions: Dict[str, List[RolePermission]] = defaultdict(list)
        self.vulnerabilities: Dict[str, List[RoleVulnerability]] = defaultdict(list)
        self.metrics: Dict[str, RoleSecurityMetrics] = {}
        
        # Risk assessment parameters
        self.risk_weights = {
            "permission_scope": 0.3,
            "access_frequency": 0.2,
            "resource_sensitivity": 0.25,
            "escalation_potential": 0.25
        }
        
        # Permission risk levels
        self.permission_risks = {
            PermissionType.READ: 0.1,
            PermissionType.WRITE: 0.4,
            PermissionType.EXECUTE: 0.6,
            PermissionType.DELETE: 0.8,
            PermissionType.ADMIN: 0.9,
            PermissionType.AUDIT: 0.3
        }
        
        # Resource sensitivity levels
        self.resource_sensitivity = {
            "user_data": 0.9,
            "system_config": 0.8,
            "security_logs": 0.9,
            "trust_scores": 0.7,
            "agent_identities": 0.8,
            "mcp_tools": 0.6,
            "task_allocations": 0.5,
            "audit_logs": 0.8
        }
    
    def register_role(self, role_id: str, role_type: RoleType, 
                     capabilities: List[str], metadata: Dict[str, Any] = None) -> bool:
        """
        Register a new role in the system
        
        Args:
            role_id: Unique role identifier
            role_type: Type of role
            capabilities: List of role capabilities
            metadata: Additional role metadata
            
        Returns:
            True if role registered successfully
        """
        try:
            self.roles[role_id] = {
                "role_type": role_type,
                "capabilities": capabilities,
                "metadata": metadata or {},
                "created_at": time.time(),
                "last_updated": time.time()
            }
            
            # Initialize permissions and metrics
            self.permissions[role_id] = []
            self.vulnerabilities[role_id] = []
            self.metrics[role_id] = RoleSecurityMetrics(
                role_id=role_id,
                total_permissions=0,
                high_risk_permissions=0,
                vulnerability_count=0,
                escalation_risks=0,
                access_frequency=0.0,
                security_score=0.0,
                last_analyzed=time.time()
            )
            
            return True
            
        except Exception as e:
            print(f"Error registering role {role_id}: {e}")
            return False
    
    def add_permission(self, role_id: str, permission: RolePermission) -> bool:
        """
        Add a permission to a role
        
        Args:
            role_id: Role identifier
            permission: Permission to add
            
        Returns:
            True if permission added successfully
        """
        try:
            if role_id not in self.roles:
                return False
                
            self.permissions[role_id].append(permission)
            self.roles[role_id]["last_updated"] = time.time()
            
            return True
            
        except Exception as e:
            print(f"Error adding permission to role {role_id}: {e}")
            return False
    
    def analyze_role_vulnerabilities(self, role_id: str) -> List[RoleVulnerability]:
        """
        Analyze vulnerabilities for a specific role
        
        Args:
            role_id: Role identifier
            
        Returns:
            List of identified vulnerabilities
        """
        if role_id not in self.roles:
            return []
        
        vulnerabilities = []
        role_permissions = self.permissions.get(role_id, [])
        
        # Analyze permission-based vulnerabilities
        for permission in role_permissions:
            vuln = self._analyze_permission_vulnerability(role_id, permission)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Analyze role escalation risks
        escalation_vuln = self._analyze_escalation_risks(role_id)
        if escalation_vuln:
            vulnerabilities.extend(escalation_vuln)
        
        # Analyze privilege accumulation
        accumulation_vuln = self._analyze_privilege_accumulation(role_id)
        if accumulation_vuln:
            vulnerabilities.append(accumulation_vuln)
        
        # Store vulnerabilities
        self.vulnerabilities[role_id] = vulnerabilities
        
        return vulnerabilities
    
    def _analyze_permission_vulnerability(self, role_id: str, permission: RolePermission) -> Optional[RoleVulnerability]:
        """Analyze vulnerability for a specific permission"""
        try:
            # Calculate risk score
            permission_risk = self.permission_risks.get(permission.permission_type, 0.5)
            resource_risk = self.resource_sensitivity.get(permission.resource, 0.5)
            
            risk_score = (permission_risk + resource_risk) / 2
            
            # Determine risk level
            if risk_score >= 0.8:
                risk_level = SecurityRiskLevel.CRITICAL
            elif risk_score >= 0.6:
                risk_level = SecurityRiskLevel.HIGH
            elif risk_score >= 0.4:
                risk_level = SecurityRiskLevel.MEDIUM
            else:
                risk_level = SecurityRiskLevel.LOW
            
            # Generate mitigation suggestions
            mitigation_suggestions = self._generate_mitigation_suggestions(permission, risk_level)
            
            return RoleVulnerability(
                role_id=role_id,
                vulnerability_type="permission_risk",
                risk_level=risk_level,
                description=f"High-risk permission: {permission.permission_type.value} on {permission.resource}",
                impact_score=resource_risk,
                likelihood_score=permission_risk,
                mitigation_suggestions=mitigation_suggestions,
                metadata={
                    "permission_type": permission.permission_type.value,
                    "resource": permission.resource,
                    "risk_score": risk_score
                }
            )
            
        except Exception as e:
            print(f"Error analyzing permission vulnerability: {e}")
            return None
    
    def _analyze_escalation_risks(self, role_id: str) -> List[RoleVulnerability]:
        """Analyze role escalation risks"""
        vulnerabilities = []
        
        try:
            role_permissions = self.permissions.get(role_id, [])
            
            # Check for admin permissions
            admin_permissions = [p for p in role_permissions if p.permission_type == PermissionType.ADMIN]
            if admin_permissions:
                vulnerabilities.append(RoleVulnerability(
                    role_id=role_id,
                    vulnerability_type="escalation_risk",
                    risk_level=SecurityRiskLevel.HIGH,
                    description="Role has admin permissions - potential escalation risk",
                    impact_score=0.9,
                    likelihood_score=0.7,
                    mitigation_suggestions=[
                        "Implement principle of least privilege",
                        "Add additional approval for admin actions",
                        "Enable audit logging for admin operations"
                    ],
                    metadata={"admin_permission_count": len(admin_permissions)}
                ))
            
            # Check for excessive permissions
            if len(role_permissions) > 10:
                vulnerabilities.append(RoleVulnerability(
                    role_id=role_id,
                    vulnerability_type="excessive_permissions",
                    risk_level=SecurityRiskLevel.MEDIUM,
                    description=f"Role has {len(role_permissions)} permissions - may be excessive",
                    impact_score=0.6,
                    likelihood_score=0.5,
                    mitigation_suggestions=[
                        "Review and reduce unnecessary permissions",
                        "Implement role separation",
                        "Use temporary permissions where possible"
                    ],
                    metadata={"permission_count": len(role_permissions)}
                ))
            
        except Exception as e:
            print(f"Error analyzing escalation risks: {e}")
        
        return vulnerabilities
    
    def _analyze_privilege_accumulation(self, role_id: str) -> Optional[RoleVulnerability]:
        """Analyze privilege accumulation risks"""
        try:
            role_permissions = self.permissions.get(role_id, [])
            
            # Count high-risk permissions
            high_risk_count = sum(1 for p in role_permissions 
                                if self.permission_risks.get(p.permission_type, 0) > 0.6)
            
            if high_risk_count > 3:
                return RoleVulnerability(
                    role_id=role_id,
                    vulnerability_type="privilege_accumulation",
                    risk_level=SecurityRiskLevel.HIGH,
                    description=f"Role has {high_risk_count} high-risk permissions - privilege accumulation risk",
                    impact_score=0.8,
                    likelihood_score=0.6,
                    mitigation_suggestions=[
                        "Distribute high-risk permissions across multiple roles",
                        "Implement approval workflows for high-risk operations",
                        "Add additional monitoring for high-risk permissions"
                    ],
                    metadata={"high_risk_permission_count": high_risk_count}
                )
            
        except Exception as e:
            print(f"Error analyzing privilege accumulation: {e}")
        
        return None
    
    def _generate_mitigation_suggestions(self, permission: RolePermission, risk_level: SecurityRiskLevel) -> List[str]:
        """Generate mitigation suggestions for a permission"""
        suggestions = []
        
        if risk_level == SecurityRiskLevel.CRITICAL:
            suggestions.extend([
                "Implement multi-factor authentication for this permission",
                "Add approval workflow for critical operations",
                "Enable real-time monitoring and alerting",
                "Consider role separation for critical permissions"
            ])
        elif risk_level == SecurityRiskLevel.HIGH:
            suggestions.extend([
                "Add additional logging for this permission",
                "Implement time-based access controls",
                "Consider temporary permission grants",
                "Add approval for sensitive operations"
            ])
        elif risk_level == SecurityRiskLevel.MEDIUM:
            suggestions.extend([
                "Review permission necessity regularly",
                "Add basic monitoring",
                "Consider permission expiration"
            ])
        
        return suggestions
    
    def calculate_role_security_metrics(self, role_id: str) -> RoleSecurityMetrics:
        """
        Calculate comprehensive security metrics for a role
        
        Args:
            role_id: Role identifier
            
        Returns:
            Role security metrics
        """
        if role_id not in self.roles:
            return None
        
        try:
            role_permissions = self.permissions.get(role_id, [])
            vulnerabilities = self.vulnerabilities.get(role_id, [])
            
            # Calculate basic metrics
            total_permissions = len(role_permissions)
            high_risk_permissions = sum(1 for p in role_permissions 
                                      if self.permission_risks.get(p.permission_type, 0) > 0.6)
            vulnerability_count = len(vulnerabilities)
            escalation_risks = sum(1 for v in vulnerabilities if v.vulnerability_type == "escalation_risk")
            
            # Calculate access frequency (simplified)
            access_frequency = min(1.0, total_permissions / 20.0)  # Normalize to 0-1
            
            # Calculate security score
            security_score = self._calculate_security_score(
                total_permissions, high_risk_permissions, vulnerability_count, escalation_risks
            )
            
            # Create metrics object
            metrics = RoleSecurityMetrics(
                role_id=role_id,
                total_permissions=total_permissions,
                high_risk_permissions=high_risk_permissions,
                vulnerability_count=vulnerability_count,
                escalation_risks=escalation_risks,
                access_frequency=access_frequency,
                security_score=security_score,
                last_analyzed=time.time(),
                metadata={
                    "risk_weights": self.risk_weights,
                    "permission_risks": {k.value: v for k, v in self.permission_risks.items()}
                }
            )
            
            # Store metrics
            self.metrics[role_id] = metrics
            
            return metrics
            
        except Exception as e:
            print(f"Error calculating security metrics for role {role_id}: {e}")
            return None
    
    def _calculate_security_score(self, total_permissions: int, high_risk_permissions: int, 
                                 vulnerability_count: int, escalation_risks: int) -> float:
        """Calculate overall security score for a role"""
        try:
            # Base score
            base_score = 1.0
            
            # Penalize high-risk permissions
            risk_penalty = (high_risk_permissions / max(1, total_permissions)) * 0.3
            
            # Penalize vulnerabilities
            vulnerability_penalty = min(0.4, vulnerability_count * 0.1)
            
            # Penalize escalation risks
            escalation_penalty = escalation_risks * 0.2
            
            # Calculate final score
            security_score = max(0.0, base_score - risk_penalty - vulnerability_penalty - escalation_penalty)
            
            return round(security_score, 3)
            
        except Exception as e:
            print(f"Error calculating security score: {e}")
            return 0.0
    
    def get_role_security_report(self, role_id: str) -> Dict[str, Any]:
        """
        Generate comprehensive security report for a role
        
        Args:
            role_id: Role identifier
            
        Returns:
            Comprehensive security report
        """
        if role_id not in self.roles:
            return {}
        
        try:
            # Get role information
            role_info = self.roles[role_id]
            permissions = self.permissions.get(role_id, [])
            vulnerabilities = self.vulnerabilities.get(role_id, [])
            metrics = self.metrics.get(role_id)
            
            # Generate report
            report = {
                "role_id": role_id,
                "role_info": role_info,
                "permissions": [
                    {
                        "type": p.permission_type.value,
                        "resource": p.resource,
                        "risk_level": self.permission_risks.get(p.permission_type, 0.5),
                        "conditions": p.conditions,
                        "metadata": p.metadata
                    }
                    for p in permissions
                ],
                "vulnerabilities": [
                    {
                        "type": v.vulnerability_type,
                        "risk_level": v.risk_level.value,
                        "description": v.description,
                        "impact_score": v.impact_score,
                        "likelihood_score": v.likelihood_score,
                        "mitigation_suggestions": v.mitigation_suggestions,
                        "metadata": v.metadata
                    }
                    for v in vulnerabilities
                ],
                "metrics": {
                    "total_permissions": metrics.total_permissions if metrics else 0,
                    "high_risk_permissions": metrics.high_risk_permissions if metrics else 0,
                    "vulnerability_count": metrics.vulnerability_count if metrics else 0,
                    "escalation_risks": metrics.escalation_risks if metrics else 0,
                    "access_frequency": metrics.access_frequency if metrics else 0.0,
                    "security_score": metrics.security_score if metrics else 0.0,
                    "last_analyzed": metrics.last_analyzed if metrics else time.time()
                },
                "recommendations": self._generate_role_recommendations(role_id),
                "generated_at": time.time()
            }
            
            return report
            
        except Exception as e:
            print(f"Error generating security report for role {role_id}: {e}")
            return {}
    
    def _generate_role_recommendations(self, role_id: str) -> List[str]:
        """Generate security recommendations for a role"""
        recommendations = []
        
        try:
            metrics = self.metrics.get(role_id)
            vulnerabilities = self.vulnerabilities.get(role_id, [])
            
            if not metrics:
                return recommendations
            
            # Security score recommendations
            if metrics.security_score < 0.5:
                recommendations.append("CRITICAL: Role has very low security score - immediate review required")
            elif metrics.security_score < 0.7:
                recommendations.append("HIGH: Role security score is below recommended threshold")
            
            # Permission recommendations
            if metrics.high_risk_permissions > 3:
                recommendations.append("Reduce number of high-risk permissions")
            
            if metrics.total_permissions > 15:
                recommendations.append("Consider role separation - too many permissions")
            
            # Vulnerability recommendations
            if metrics.vulnerability_count > 5:
                recommendations.append("Address identified vulnerabilities immediately")
            
            if metrics.escalation_risks > 0:
                recommendations.append("Implement additional controls for escalation risks")
            
            # General recommendations
            recommendations.extend([
                "Regular security review of role permissions",
                "Implement principle of least privilege",
                "Enable comprehensive audit logging",
                "Consider time-based access controls"
            ])
            
        except Exception as e:
            print(f"Error generating recommendations: {e}")
        
        return recommendations
    
    def get_all_roles_security_summary(self) -> Dict[str, Any]:
        """Get security summary for all roles"""
        try:
            summary = {
                "total_roles": len(self.roles),
                "roles": {},
                "overall_metrics": {
                    "average_security_score": 0.0,
                    "total_vulnerabilities": 0,
                    "high_risk_roles": 0,
                    "critical_roles": 0
                },
                "generated_at": time.time()
            }
            
            total_score = 0.0
            total_vulnerabilities = 0
            high_risk_count = 0
            critical_count = 0
            
            for role_id in self.roles:
                metrics = self.metrics.get(role_id)
                vulnerabilities = self.vulnerabilities.get(role_id, [])
                
                if metrics:
                    total_score += metrics.security_score
                    total_vulnerabilities += metrics.vulnerability_count
                    
                    if metrics.security_score < 0.7:
                        high_risk_count += 1
                    if metrics.security_score < 0.5:
                        critical_count += 1
                
                summary["roles"][role_id] = {
                    "security_score": metrics.security_score if metrics else 0.0,
                    "vulnerability_count": len(vulnerabilities),
                    "permission_count": metrics.total_permissions if metrics else 0,
                    "risk_level": "critical" if metrics and metrics.security_score < 0.5 else
                                 "high" if metrics and metrics.security_score < 0.7 else
                                 "medium" if metrics and metrics.security_score < 0.8 else "low"
                }
            
            # Calculate overall metrics
            if len(self.roles) > 0:
                summary["overall_metrics"]["average_security_score"] = round(total_score / len(self.roles), 3)
            
            summary["overall_metrics"]["total_vulnerabilities"] = total_vulnerabilities
            summary["overall_metrics"]["high_risk_roles"] = high_risk_count
            summary["overall_metrics"]["critical_roles"] = critical_count
            
            return summary
            
        except Exception as e:
            print(f"Error generating security summary: {e}")
            return {}
