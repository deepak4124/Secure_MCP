"""
Role-Based Security Analysis for MCP Security Framework

This module provides comprehensive role-based security analysis including:
- Role vulnerability assessment
- Permission escalation detection
- Role-based attack surface analysis
- Dynamic role risk evaluation
- Role conflict detection
"""

import time
import math
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict

from pydantic import BaseModel, Field


class SecurityLevel(Enum):
    """Security level enumeration"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class RiskLevel(Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackVector(Enum):
    """Attack vector enumeration"""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    SERVICE_DISRUPTION = "service_disruption"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass
class Role:
    """Role definition data structure"""
    role_id: str
    name: str
    description: str
    permissions: Set[str]
    capabilities: Set[str]
    security_level: SecurityLevel
    trust_threshold: float
    max_concurrent_sessions: int
    session_timeout: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoleVulnerability:
    """Role vulnerability assessment result"""
    role_id: str
    vulnerability_type: str
    risk_level: RiskLevel
    attack_vectors: List[AttackVector]
    description: str
    mitigation_strategies: List[str]
    severity_score: float
    exploitability_score: float
    impact_score: float
    cvss_score: float


@dataclass
class RoleRiskProfile:
    """Comprehensive role risk profile"""
    role_id: str
    overall_risk_score: float
    vulnerabilities: List[RoleVulnerability]
    attack_surface: Dict[str, float]
    privilege_escalation_risk: float
    lateral_movement_risk: float
    data_access_risk: float
    last_assessed: float
    recommendations: List[str]


class RoleBasedSecurityAnalyzer:
    """
    Comprehensive role-based security analysis system
    
    Features:
    - Role vulnerability assessment
    - Permission escalation detection
    - Attack surface analysis
    - Dynamic risk evaluation
    - Role conflict detection
    - Threat modeling for roles
    """
    
    def __init__(self):
        """Initialize role-based security analyzer"""
        self.roles: Dict[str, Role] = {}
        self.role_assignments: Dict[str, Set[str]] = defaultdict(set)  # agent_id -> roles
        self.role_hierarchies: Dict[str, Set[str]] = defaultdict(set)  # role_id -> parent_roles
        self.vulnerability_patterns: Dict[str, Dict[str, Any]] = {}
        self.risk_profiles: Dict[str, RoleRiskProfile] = {}
        
        # Initialize vulnerability patterns
        self._initialize_vulnerability_patterns()
        
        # Initialize default roles
        self._initialize_default_roles()
    
    def _initialize_vulnerability_patterns(self):
        """Initialize known vulnerability patterns"""
        self.vulnerability_patterns = {
            "excessive_permissions": {
                "description": "Role has more permissions than necessary",
                "risk_factors": ["permission_count", "permission_criticality", "usage_frequency"],
                "attack_vectors": [AttackVector.PRIVILEGE_ESCALATION, AttackVector.UNAUTHORIZED_ACCESS],
                "severity_weights": {"permission_count": 0.3, "permission_criticality": 0.5, "usage_frequency": 0.2}
            },
            "weak_trust_threshold": {
                "description": "Role has low trust requirements",
                "risk_factors": ["trust_threshold", "security_level", "sensitivity"],
                "attack_vectors": [AttackVector.PRIVILEGE_ESCALATION],
                "severity_weights": {"trust_threshold": 0.6, "security_level": 0.3, "sensitivity": 0.1}
            },
            "long_session_timeout": {
                "description": "Role allows extended sessions",
                "risk_factors": ["session_timeout", "security_level", "activity_patterns"],
                "attack_vectors": [AttackVector.UNAUTHORIZED_ACCESS, AttackVector.LATERAL_MOVEMENT],
                "severity_weights": {"session_timeout": 0.5, "security_level": 0.3, "activity_patterns": 0.2}
            },
            "high_concurrency": {
                "description": "Role allows many concurrent sessions",
                "risk_factors": ["max_sessions", "session_management", "monitoring"],
                "attack_vectors": [AttackVector.LATERAL_MOVEMENT, AttackVector.SERVICE_DISRUPTION],
                "severity_weights": {"max_sessions": 0.4, "session_management": 0.4, "monitoring": 0.2}
            },
            "privilege_accumulation": {
                "description": "Role can accumulate additional privileges",
                "risk_factors": ["privilege_escalation", "role_hierarchy", "permission_inheritance"],
                "attack_vectors": [AttackVector.PRIVILEGE_ESCALATION, AttackVector.LATERAL_MOVEMENT],
                "severity_weights": {"privilege_escalation": 0.5, "role_hierarchy": 0.3, "permission_inheritance": 0.2}
            }
        }
    
    def _initialize_default_roles(self):
        """Initialize default system roles"""
        default_roles = [
            Role(
                role_id="admin",
                name="System Administrator",
                description="Full system access and management",
                permissions={"*"},
                capabilities={"system_management", "user_management", "security_management"},
                security_level=SecurityLevel.TOP_SECRET,
                trust_threshold=0.9,
                max_concurrent_sessions=5,
                session_timeout=1800,  # 30 minutes
                metadata={"department": "IT", "clearance_required": True}
            ),
            Role(
                role_id="security_analyst",
                name="Security Analyst",
                description="Security monitoring and analysis",
                permissions={"security_read", "security_analyze", "incident_manage"},
                capabilities={"security_monitoring", "threat_analysis", "incident_response"},
                security_level=SecurityLevel.SECRET,
                trust_threshold=0.8,
                max_concurrent_sessions=3,
                session_timeout=3600,  # 1 hour
                metadata={"department": "Security", "clearance_required": True}
            ),
            Role(
                role_id="researcher",
                name="Research Analyst",
                description="Data analysis and research",
                permissions={"data_read", "analysis_execute", "report_generate"},
                capabilities={"data_analysis", "research", "reporting"},
                security_level=SecurityLevel.CONFIDENTIAL,
                trust_threshold=0.6,
                max_concurrent_sessions=2,
                session_timeout=7200,  # 2 hours
                metadata={"department": "Research", "clearance_required": False}
            ),
            Role(
                role_id="coordinator",
                name="Task Coordinator",
                description="Task coordination and resource management",
                permissions={"task_manage", "resource_allocate", "workflow_control"},
                capabilities={"coordination", "resource_management", "workflow_management"},
                security_level=SecurityLevel.INTERNAL,
                trust_threshold=0.7,
                max_concurrent_sessions=3,
                session_timeout=3600,
                metadata={"department": "Management", "clearance_required": False}
            ),
            Role(
                role_id="monitor",
                name="System Monitor",
                description="System monitoring and alerting",
                permissions={"monitor_read", "alert_manage", "log_access"},
                capabilities={"monitoring", "alerting", "logging"},
                security_level=SecurityLevel.INTERNAL,
                trust_threshold=0.5,
                max_concurrent_sessions=5,
                session_timeout=7200,
                metadata={"department": "Operations", "clearance_required": False}
            )
        ]
        
        for role in default_roles:
            self.add_role(role)
    
    def add_role(self, role: Role) -> bool:
        """
        Add a new role
        
        Args:
            role: Role to add
            
        Returns:
            True if role added successfully
        """
        if role.role_id in self.roles:
            return False
        
        self.roles[role.role_id] = role
        self._assess_role_vulnerabilities(role.role_id)
        return True
    
    def assign_role(self, agent_id: str, role_id: str) -> bool:
        """
        Assign a role to an agent
        
        Args:
            agent_id: Agent identifier
            role_id: Role identifier
            
        Returns:
            True if role assigned successfully
        """
        if role_id not in self.roles:
            return False
        
        self.role_assignments[agent_id].add(role_id)
        return True
    
    def remove_role_assignment(self, agent_id: str, role_id: str) -> bool:
        """
        Remove role assignment from an agent
        
        Args:
            agent_id: Agent identifier
            role_id: Role identifier
            
        Returns:
            True if role removed successfully
        """
        if agent_id in self.role_assignments:
            self.role_assignments[agent_id].discard(role_id)
            return True
        return False
    
    def get_agent_roles(self, agent_id: str) -> Set[str]:
        """
        Get all roles assigned to an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Set of role IDs
        """
        return self.role_assignments.get(agent_id, set())
    
    def get_role_permissions(self, role_id: str) -> Set[str]:
        """
        Get all permissions for a role (including inherited)
        
        Args:
            role_id: Role identifier
            
        Returns:
            Set of permissions
        """
        if role_id not in self.roles:
            return set()
        
        permissions = set(self.roles[role_id].permissions)
        
        # Add inherited permissions
        for parent_role in self.role_hierarchies.get(role_id, set()):
            permissions.update(self.get_role_permissions(parent_role))
        
        return permissions
    
    def assess_role_vulnerabilities(self, role_id: str) -> List[RoleVulnerability]:
        """
        Assess vulnerabilities for a specific role
        
        Args:
            role_id: Role identifier
            
        Returns:
            List of identified vulnerabilities
        """
        if role_id not in self.roles:
            return []
        
        vulnerabilities = []
        role = self.roles[role_id]
        
        # Check each vulnerability pattern
        for pattern_id, pattern in self.vulnerability_patterns.items():
            vulnerability = self._check_vulnerability_pattern(role, pattern_id, pattern)
            if vulnerability:
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _assess_role_vulnerabilities(self, role_id: str):
        """Assess vulnerabilities for a role and update risk profile"""
        vulnerabilities = self.assess_role_vulnerabilities(role_id)
        
        # Calculate risk scores
        overall_risk = self._calculate_overall_risk_score(vulnerabilities)
        attack_surface = self._calculate_attack_surface(role_id)
        privilege_escalation_risk = self._calculate_privilege_escalation_risk(role_id)
        lateral_movement_risk = self._calculate_lateral_movement_risk(role_id)
        data_access_risk = self._calculate_data_access_risk(role_id)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(role_id, vulnerabilities)
        
        # Create risk profile
        risk_profile = RoleRiskProfile(
            role_id=role_id,
            overall_risk_score=overall_risk,
            vulnerabilities=vulnerabilities,
            attack_surface=attack_surface,
            privilege_escalation_risk=privilege_escalation_risk,
            lateral_movement_risk=lateral_movement_risk,
            data_access_risk=data_access_risk,
            last_assessed=time.time(),
            recommendations=recommendations
        )
        
        self.risk_profiles[role_id] = risk_profile
    
    def _check_vulnerability_pattern(self, role: Role, pattern_id: str, pattern: Dict[str, Any]) -> Optional[RoleVulnerability]:
        """Check if a role matches a vulnerability pattern"""
        if pattern_id == "excessive_permissions":
            return self._check_excessive_permissions(role, pattern)
        elif pattern_id == "weak_trust_threshold":
            return self._check_weak_trust_threshold(role, pattern)
        elif pattern_id == "long_session_timeout":
            return self._check_long_session_timeout(role, pattern)
        elif pattern_id == "high_concurrency":
            return self._check_high_concurrency(role, pattern)
        elif pattern_id == "privilege_accumulation":
            return self._check_privilege_accumulation(role, pattern)
        
        return None
    
    def _check_excessive_permissions(self, role: Role, pattern: Dict[str, Any]) -> Optional[RoleVulnerability]:
        """Check for excessive permissions vulnerability"""
        permission_count = len(role.permissions)
        critical_permissions = len([p for p in role.permissions if "admin" in p or "system" in p or "*" in p])
        
        # Calculate risk score
        risk_score = (permission_count * 0.1) + (critical_permissions * 0.3)
        
        if risk_score > 0.7:  # Threshold for excessive permissions
            return RoleVulnerability(
                role_id=role.role_id,
                vulnerability_type="excessive_permissions",
                risk_level=RiskLevel.HIGH if risk_score > 0.8 else RiskLevel.MEDIUM,
                attack_vectors=pattern["attack_vectors"],
                description=f"Role has {permission_count} permissions with {critical_permissions} critical permissions",
                mitigation_strategies=[
                    "Implement principle of least privilege",
                    "Regular permission audits",
                    "Role-based access reviews",
                    "Permission usage monitoring"
                ],
                severity_score=risk_score,
                exploitability_score=0.8,
                impact_score=0.9,
                cvss_score=self._calculate_cvss_score(risk_score, 0.8, 0.9)
            )
        
        return None
    
    def _check_weak_trust_threshold(self, role: Role, pattern: Dict[str, Any]) -> Optional[RoleVulnerability]:
        """Check for weak trust threshold vulnerability"""
        security_level_weights = {
            SecurityLevel.PUBLIC: 0.1,
            SecurityLevel.INTERNAL: 0.3,
            SecurityLevel.CONFIDENTIAL: 0.5,
            SecurityLevel.SECRET: 0.7,
            SecurityLevel.TOP_SECRET: 0.9
        }
        
        expected_trust = security_level_weights.get(role.security_level, 0.5)
        trust_gap = expected_trust - role.trust_threshold
        
        if trust_gap > 0.2:  # Significant trust gap
            return RoleVulnerability(
                role_id=role.role_id,
                vulnerability_type="weak_trust_threshold",
                risk_level=RiskLevel.HIGH if trust_gap > 0.4 else RiskLevel.MEDIUM,
                attack_vectors=pattern["attack_vectors"],
                description=f"Trust threshold {role.trust_threshold} is below expected {expected_trust} for {role.security_level.value} level",
                mitigation_strategies=[
                    "Increase trust threshold requirements",
                    "Implement additional authentication factors",
                    "Add behavioral monitoring",
                    "Regular trust score reviews"
                ],
                severity_score=trust_gap,
                exploitability_score=0.9,
                impact_score=0.7,
                cvss_score=self._calculate_cvss_score(trust_gap, 0.9, 0.7)
            )
        
        return None
    
    def _check_long_session_timeout(self, role: Role, pattern: Dict[str, Any]) -> Optional[RoleVulnerability]:
        """Check for long session timeout vulnerability"""
        # Define reasonable timeouts by security level
        max_timeouts = {
            SecurityLevel.PUBLIC: 14400,      # 4 hours
            SecurityLevel.INTERNAL: 7200,     # 2 hours
            SecurityLevel.CONFIDENTIAL: 3600, # 1 hour
            SecurityLevel.SECRET: 1800,       # 30 minutes
            SecurityLevel.TOP_SECRET: 900     # 15 minutes
        }
        
        max_timeout = max_timeouts.get(role.security_level, 3600)
        
        if role.session_timeout > max_timeout:
            risk_score = (role.session_timeout - max_timeout) / max_timeout
            
            return RoleVulnerability(
                role_id=role.role_id,
                vulnerability_type="long_session_timeout",
                risk_level=RiskLevel.MEDIUM if risk_score < 0.5 else RiskLevel.HIGH,
                attack_vectors=pattern["attack_vectors"],
                description=f"Session timeout {role.session_timeout}s exceeds recommended {max_timeout}s for {role.security_level.value} level",
                mitigation_strategies=[
                    "Reduce session timeout",
                    "Implement session activity monitoring",
                    "Add automatic session refresh",
                    "Implement session invalidation on inactivity"
                ],
                severity_score=risk_score,
                exploitability_score=0.6,
                impact_score=0.5,
                cvss_score=self._calculate_cvss_score(risk_score, 0.6, 0.5)
            )
        
        return None
    
    def _check_high_concurrency(self, role: Role, pattern: Dict[str, Any]) -> Optional[RoleVulnerability]:
        """Check for high concurrency vulnerability"""
        # Define reasonable concurrency limits by security level
        max_concurrent = {
            SecurityLevel.PUBLIC: 10,
            SecurityLevel.INTERNAL: 5,
            SecurityLevel.CONFIDENTIAL: 3,
            SecurityLevel.SECRET: 2,
            SecurityLevel.TOP_SECRET: 1
        }
        
        max_allowed = max_concurrent.get(role.security_level, 3)
        
        if role.max_concurrent_sessions > max_allowed:
            risk_score = (role.max_concurrent_sessions - max_allowed) / max_allowed
            
            return RoleVulnerability(
                role_id=role.role_id,
                vulnerability_type="high_concurrency",
                risk_level=RiskLevel.MEDIUM if risk_score < 0.5 else RiskLevel.HIGH,
                attack_vectors=pattern["attack_vectors"],
                description=f"Max concurrent sessions {role.max_concurrent_sessions} exceeds recommended {max_allowed} for {role.security_level.value} level",
                mitigation_strategies=[
                    "Reduce concurrent session limit",
                    "Implement session monitoring",
                    "Add session conflict detection",
                    "Implement automatic session termination"
                ],
                severity_score=risk_score,
                exploitability_score=0.7,
                impact_score=0.6,
                cvss_score=self._calculate_cvss_score(risk_score, 0.7, 0.6)
            )
        
        return None
    
    def _check_privilege_accumulation(self, role: Role, pattern: Dict[str, Any]) -> Optional[RoleVulnerability]:
        """Check for privilege accumulation vulnerability"""
        # Check if role can inherit from multiple parent roles
        parent_roles = self.role_hierarchies.get(role.role_id, set())
        
        if len(parent_roles) > 2:  # More than 2 parent roles
            risk_score = min(1.0, len(parent_roles) * 0.2)
            
            return RoleVulnerability(
                role_id=role.role_id,
                vulnerability_type="privilege_accumulation",
                risk_level=RiskLevel.HIGH if risk_score > 0.6 else RiskLevel.MEDIUM,
                attack_vectors=pattern["attack_vectors"],
                description=f"Role inherits from {len(parent_roles)} parent roles, creating privilege accumulation risk",
                mitigation_strategies=[
                    "Simplify role hierarchy",
                    "Implement privilege separation",
                    "Add privilege monitoring",
                    "Regular privilege audits"
                ],
                severity_score=risk_score,
                exploitability_score=0.8,
                impact_score=0.8,
                cvss_score=self._calculate_cvss_score(risk_score, 0.8, 0.8)
            )
        
        return None
    
    def _calculate_overall_risk_score(self, vulnerabilities: List[RoleVulnerability]) -> float:
        """Calculate overall risk score from vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        # Weight vulnerabilities by their CVSS scores
        total_weighted_score = sum(v.cvss_score for v in vulnerabilities)
        max_possible_score = len(vulnerabilities) * 10.0  # Max CVSS score is 10.0
        
        return min(1.0, total_weighted_score / max_possible_score)
    
    def _calculate_attack_surface(self, role_id: str) -> Dict[str, float]:
        """Calculate attack surface for a role"""
        if role_id not in self.roles:
            return {}
        
        role = self.roles[role_id]
        
        return {
            "permission_count": min(1.0, len(role.permissions) / 20.0),
            "capability_count": min(1.0, len(role.capabilities) / 10.0),
            "session_exposure": min(1.0, role.max_concurrent_sessions / 10.0),
            "time_exposure": min(1.0, role.session_timeout / 14400.0),  # 4 hours max
            "trust_gap": max(0.0, 0.8 - role.trust_threshold)  # Higher gap = higher risk
        }
    
    def _calculate_privilege_escalation_risk(self, role_id: str) -> float:
        """Calculate privilege escalation risk for a role"""
        if role_id not in self.roles:
            return 0.0
        
        role = self.roles[role_id]
        
        # Factors contributing to privilege escalation risk
        admin_permissions = len([p for p in role.permissions if "admin" in p.lower() or "*" in p])
        system_permissions = len([p for p in role.permissions if "system" in p.lower()])
        low_trust_threshold = max(0.0, 0.5 - role.trust_threshold)
        
        risk_score = (
            (admin_permissions * 0.4) +
            (system_permissions * 0.3) +
            (low_trust_threshold * 0.3)
        )
        
        return min(1.0, risk_score)
    
    def _calculate_lateral_movement_risk(self, role_id: str) -> float:
        """Calculate lateral movement risk for a role"""
        if role_id not in self.roles:
            return 0.0
        
        role = self.roles[role_id]
        
        # Factors contributing to lateral movement risk
        high_concurrency = max(0.0, (role.max_concurrent_sessions - 2) / 8.0)
        long_sessions = max(0.0, (role.session_timeout - 1800) / 7200.0)  # 30 min baseline
        network_permissions = len([p for p in role.permissions if "network" in p.lower() or "connect" in p.lower()])
        
        risk_score = (
            (high_concurrency * 0.4) +
            (long_sessions * 0.3) +
            (min(1.0, network_permissions / 5.0) * 0.3)
        )
        
        return min(1.0, risk_score)
    
    def _calculate_data_access_risk(self, role_id: str) -> float:
        """Calculate data access risk for a role"""
        if role_id not in self.roles:
            return 0.0
        
        role = self.roles[role_id]
        
        # Factors contributing to data access risk
        data_permissions = len([p for p in role.permissions if "data" in p.lower() or "read" in p.lower()])
        security_level_risk = {
            SecurityLevel.PUBLIC: 0.1,
            SecurityLevel.INTERNAL: 0.3,
            SecurityLevel.CONFIDENTIAL: 0.5,
            SecurityLevel.SECRET: 0.7,
            SecurityLevel.TOP_SECRET: 0.9
        }.get(role.security_level, 0.5)
        
        risk_score = (
            (min(1.0, data_permissions / 10.0) * 0.6) +
            (security_level_risk * 0.4)
        )
        
        return min(1.0, risk_score)
    
    def _generate_recommendations(self, role_id: str, vulnerabilities: List[RoleVulnerability]) -> List[str]:
        """Generate security recommendations for a role"""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("Role appears secure - continue monitoring")
            return recommendations
        
        # Generate recommendations based on vulnerability types
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        
        if "excessive_permissions" in vuln_types:
            recommendations.append("Review and reduce role permissions to minimum necessary")
        
        if "weak_trust_threshold" in vuln_types:
            recommendations.append("Increase trust threshold requirements for role")
        
        if "long_session_timeout" in vuln_types:
            recommendations.append("Reduce session timeout to appropriate level")
        
        if "high_concurrency" in vuln_types:
            recommendations.append("Limit concurrent sessions to reduce attack surface")
        
        if "privilege_accumulation" in vuln_types:
            recommendations.append("Simplify role hierarchy to prevent privilege accumulation")
        
        # General recommendations
        recommendations.extend([
            "Implement regular role access reviews",
            "Monitor role usage patterns for anomalies",
            "Add behavioral analysis for role activities",
            "Implement role-based audit logging"
        ])
        
        return recommendations
    
    def _calculate_cvss_score(self, severity: float, exploitability: float, impact: float) -> float:
        """Calculate CVSS-like score"""
        # Simplified CVSS calculation
        base_score = (severity * 0.4) + (exploitability * 0.3) + (impact * 0.3)
        return min(10.0, base_score * 10.0)
    
    def get_role_risk_profile(self, role_id: str) -> Optional[RoleRiskProfile]:
        """Get risk profile for a role"""
        return self.risk_profiles.get(role_id)
    
    def get_all_risk_profiles(self) -> Dict[str, RoleRiskProfile]:
        """Get all role risk profiles"""
        return self.risk_profiles.copy()
    
    def detect_role_conflicts(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Detect conflicts between roles assigned to an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of detected conflicts
        """
        agent_roles = self.get_agent_roles(agent_id)
        conflicts = []
        
        if len(agent_roles) < 2:
            return conflicts
        
        # Check for permission conflicts
        role_permissions = {}
        for role_id in agent_roles:
            role_permissions[role_id] = self.get_role_permissions(role_id)
        
        # Check for conflicting permissions
        for role1, perms1 in role_permissions.items():
            for role2, perms2 in role_permissions.items():
                if role1 >= role2:  # Avoid duplicate checks
                    continue
                
                # Check for conflicting security levels
                role1_obj = self.roles.get(role1)
                role2_obj = self.roles.get(role2)
                
                if role1_obj and role2_obj:
                    security_levels = [SecurityLevel.PUBLIC, SecurityLevel.INTERNAL, 
                                     SecurityLevel.CONFIDENTIAL, SecurityLevel.SECRET, SecurityLevel.TOP_SECRET]
                    
                    level1_idx = security_levels.index(role1_obj.security_level)
                    level2_idx = security_levels.index(role2_obj.security_level)
                    
                    if abs(level1_idx - level2_idx) > 2:  # Significant security level difference
                        conflicts.append({
                            "type": "security_level_conflict",
                            "roles": [role1, role2],
                            "description": f"Roles have conflicting security levels: {role1_obj.security_level.value} vs {role2_obj.security_level.value}",
                            "severity": "high" if abs(level1_idx - level2_idx) > 3 else "medium"
                        })
        
        return conflicts
    
    def export_role_analysis(self, file_path: str) -> bool:
        """Export role analysis to file"""
        try:
            analysis_data = {
                "roles": {
                    role_id: {
                        "role": {
                            "role_id": role.role_id,
                            "name": role.name,
                            "description": role.description,
                            "permissions": list(role.permissions),
                            "capabilities": list(role.capabilities),
                            "security_level": role.security_level.value,
                            "trust_threshold": role.trust_threshold,
                            "max_concurrent_sessions": role.max_concurrent_sessions,
                            "session_timeout": role.session_timeout,
                            "metadata": role.metadata
                        },
                        "risk_profile": {
                            "overall_risk_score": profile.overall_risk_score,
                            "vulnerabilities": [
                                {
                                    "vulnerability_type": v.vulnerability_type,
                                    "risk_level": v.risk_level.value,
                                    "attack_vectors": [av.value for av in v.attack_vectors],
                                    "description": v.description,
                                    "mitigation_strategies": v.mitigation_strategies,
                                    "severity_score": v.severity_score,
                                    "exploitability_score": v.exploitability_score,
                                    "impact_score": v.impact_score,
                                    "cvss_score": v.cvss_score
                                }
                                for v in profile.vulnerabilities
                            ],
                            "attack_surface": profile.attack_surface,
                            "privilege_escalation_risk": profile.privilege_escalation_risk,
                            "lateral_movement_risk": profile.lateral_movement_risk,
                            "data_access_risk": profile.data_access_risk,
                            "last_assessed": profile.last_assessed,
                            "recommendations": profile.recommendations
                        }
                    }
                    for role_id, role in self.roles.items()
                    for profile in [self.risk_profiles.get(role_id)]
                    if profile
                },
                "role_assignments": {
                    agent_id: list(roles) for agent_id, roles in self.role_assignments.items()
                },
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(analysis_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting role analysis: {e}")
            return False
