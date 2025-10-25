"""
Enhanced MCP Security Gateway

This module provides an enhanced security gateway that integrates advanced security
features including Dynamic Trust Allocation, MAESTRO Multi-Layer Security, and
Advanced Behavioral Analysis.
"""

import time
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

from pydantic import BaseModel, Field

from .gateway import MCPSecurityGateway, RequestContext, ResponseContext
from .identity import IdentityManager
from .trust import TrustCalculator
from .policy import PolicyEngine
from .registry import ToolRegistry

# Import advanced security components
from ..security.advanced.dynamic_trust_manager import DynamicTrustManager
from ..security.advanced.maestro_layer_security import MAESTROLayerSecurity
from ..security.advanced.advanced_behavioral_analysis import AdvancedBehavioralAnalysis


class SecurityLevel(Enum):
    """Security level enumeration"""
    MINIMAL = "minimal"
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"


@dataclass
class SecurityAssessment:
    """Security assessment result"""
    overall_score: float
    details: str
    threats_detected: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_level: str = "low"


class EnhancedMCPSecurityGateway(MCPSecurityGateway):
    """
    Enhanced MCP Security Gateway with advanced security features
    
    Integrates Dynamic Trust Allocation, MAESTRO Multi-Layer Security,
    and Advanced Behavioral Analysis for comprehensive security.
    """
    
    def __init__(
        self,
        identity_manager: IdentityManager = None,
        trust_calculator: TrustCalculator = None,
        policy_engine: PolicyEngine = None,
        tool_registry: ToolRegistry = None,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
        enable_dynamic_trust: bool = False,
        enable_maestro_security: bool = False,
        enable_behavioral_analysis: bool = False,
        **kwargs
    ):
        """
        Initialize enhanced security gateway
        
        Args:
            identity_manager: Identity manager instance
            trust_calculator: Trust calculator instance
            policy_engine: Policy engine instance
            tool_registry: Tool registry instance
            security_level: Security level configuration
            enable_dynamic_trust: Enable dynamic trust allocation
            enable_maestro_security: Enable MAESTRO multi-layer security
            enable_behavioral_analysis: Enable advanced behavioral analysis
            **kwargs: Additional arguments
        """
        super().__init__(
            identity_manager=identity_manager,
            trust_calculator=trust_calculator,
            policy_engine=policy_engine,
            tool_registry=tool_registry,
            **kwargs
        )
        
        self.security_level = security_level
        self.enable_dynamic_trust = enable_dynamic_trust
        self.enable_maestro_security = enable_maestro_security
        self.enable_behavioral_analysis = enable_behavioral_analysis
        
        # Initialize advanced security components
        self.dynamic_trust_manager = DynamicTrustManager() if enable_dynamic_trust else None
        self.maestro_security = MAESTROLayerSecurity() if enable_maestro_security else None
        self.behavioral_analyzer = AdvancedBehavioralAnalysis() if enable_behavioral_analysis else None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Security statistics
        self.security_stats = {
            "requests_processed": 0,
            "threats_detected": 0,
            "security_violations": 0,
            "trust_adjustments": 0
        }
    
    async def process_request(self, agent_id: str, request: RequestContext) -> ResponseContext:
        """
        Process request with enhanced security features
        
        Args:
            agent_id: Agent ID
            request: Request context
            
        Returns:
            Response context with security assessment
        """
        start_time = time.time()
        self.security_stats["requests_processed"] += 1
        
        try:
            # Perform enhanced security checks
            security_assessment = await self._perform_enhanced_security_checks(
                agent_id, request
            )
            
            # Check if request should be blocked
            if security_assessment.risk_level == "critical":
                self.security_stats["security_violations"] += 1
                return ResponseContext(
                    status="blocked",
                    message="Request blocked due to security concerns",
                    security_assessment=security_assessment
                )
            
            # Process request through base gateway
            response = await super().process_request(agent_id, request)
            
            # Add security assessment to response
            response.security_assessment = security_assessment
            
            # Update security statistics
            if security_assessment.threats_detected:
                self.security_stats["threats_detected"] += 1
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseContext(
                status="error",
                message=f"Request processing failed: {str(e)}",
                security_assessment=SecurityAssessment(
                    overall_score=0.0,
                    details="Request processing error",
                    risk_level="high"
                )
            )
    
    async def _perform_enhanced_security_checks(
        self,
        agent_id: str,
        request: RequestContext
    ) -> SecurityAssessment:
        """
        Perform enhanced security checks
        
        Args:
            agent_id: Agent ID
            request: Request context
            
        Returns:
            Security assessment result
        """
        threats_detected = []
        recommendations = []
        overall_score = 1.0
        
        # 1. Dynamic Trust Assessment
        if self.enable_dynamic_trust and self.dynamic_trust_manager:
            trust_assessment = await self._assess_dynamic_trust(agent_id, request)
            if trust_assessment["risk_level"] == "high":
                threats_detected.append("Low trust score")
                recommendations.append("Increase trust through positive interactions")
                overall_score *= 0.7
        
        # 2. MAESTRO Multi-Layer Security Assessment
        if self.enable_maestro_security and self.maestro_security:
            maestro_assessment = await self._assess_maestro_security(agent_id, request)
            if maestro_assessment["threats"]:
                threats_detected.extend(maestro_assessment["threats"])
                recommendations.extend(maestro_assessment["recommendations"])
                overall_score *= 0.8
        
        # 3. Advanced Behavioral Analysis
        if self.enable_behavioral_analysis and self.behavioral_analyzer:
            behavioral_assessment = await self._assess_behavioral_patterns(agent_id, request)
            if behavioral_assessment["anomaly_score"] > 0.7:
                threats_detected.append("Behavioral anomaly detected")
                recommendations.append("Review agent behavior patterns")
                overall_score *= 0.6
        
        # 4. Security Level Specific Checks
        security_level_checks = await self._perform_security_level_checks(
            agent_id, request
        )
        if security_level_checks["threats"]:
            threats_detected.extend(security_level_checks["threats"])
            recommendations.extend(security_level_checks["recommendations"])
            overall_score *= security_level_checks["score_multiplier"]
        
        # Determine risk level
        if overall_score >= 0.9:
            risk_level = "low"
        elif overall_score >= 0.7:
            risk_level = "medium"
        elif overall_score >= 0.5:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        return SecurityAssessment(
            overall_score=overall_score,
            details=f"Security assessment completed with {len(threats_detected)} threats detected",
            threats_detected=threats_detected,
            recommendations=recommendations,
            risk_level=risk_level
        )
    
    async def _assess_dynamic_trust(
        self,
        agent_id: str,
        request: RequestContext
    ) -> Dict[str, Any]:
        """
        Assess dynamic trust for agent
        
        Args:
            agent_id: Agent ID
            request: Request context
            
        Returns:
            Trust assessment result
        """
        try:
            # Get dynamic trust score
            trust_score = self.dynamic_trust_manager.get_dynamic_trust_score(agent_id)
            
            # Add trust context
            from ..security.advanced.dynamic_trust_manager import TrustContextData, TrustContext
            context_data = TrustContextData(
                context=TrustContext.BEHAVIORAL,
                score=trust_score.overall_score,
                timestamp=time.time(),
                metadata={"request_type": request.operation}
            )
            self.dynamic_trust_manager.add_trust_context(agent_id, context_data)
            
            # Determine risk level
            if trust_score.overall_score >= 0.8:
                risk_level = "low"
            elif trust_score.overall_score >= 0.6:
                risk_level = "medium"
            else:
                risk_level = "high"
            
            return {
                "trust_score": trust_score.overall_score,
                "risk_level": risk_level,
                "context_scores": trust_score.contextual_scores
            }
            
        except Exception as e:
            self.logger.error(f"Error assessing dynamic trust: {e}")
            return {"trust_score": 0.5, "risk_level": "medium", "context_scores": {}}
    
    async def _assess_maestro_security(
        self,
        agent_id: str,
        request: RequestContext
    ) -> Dict[str, Any]:
        """
        Assess MAESTRO multi-layer security
        
        Args:
            agent_id: Agent ID
            request: Request context
            
        Returns:
            MAESTRO security assessment result
        """
        try:
            # Prepare system data for assessment
            system_data = {
                "agent_id": agent_id,
                "request": request,
                "timestamp": time.time(),
                "security_level": self.security_level.value
            }
            
            # Perform MAESTRO security assessment
            assessment = self.maestro_security.assess_security_across_layers(system_data)
            
            # Identify security gaps
            gaps = self.maestro_security.identify_security_gaps(assessment)
            
            # Get recommendations
            recommendations = self.maestro_security.get_priority_recommendations(gaps)
            
            # Extract threats and recommendations
            threats = []
            recs = []
            
            for gap in gaps:
                if gap.severity == "critical":
                    threats.append(f"Critical security gap: {gap.description}")
                elif gap.severity == "high":
                    threats.append(f"High severity gap: {gap.description}")
            
            for rec in recommendations:
                recs.append(rec.description)
            
            return {
                "overall_score": assessment.overall_security_score,
                "threats": threats,
                "recommendations": recs,
                "layer_scores": assessment.layer_scores
            }
            
        except Exception as e:
            self.logger.error(f"Error assessing MAESTRO security: {e}")
            return {
                "overall_score": 0.5,
                "threats": [],
                "recommendations": [],
                "layer_scores": {}
            }
    
    async def _assess_behavioral_patterns(
        self,
        agent_id: str,
        request: RequestContext
    ) -> Dict[str, Any]:
        """
        Assess behavioral patterns for anomalies
        
        Args:
            agent_id: Agent ID
            request: Request context
            
        Returns:
            Behavioral assessment result
        """
        try:
            # Create behavior sequence from request
            from ..security.advanced.advanced_behavioral_analysis import BehaviorSequence, BehaviorEvent
            behavior_events = [
                BehaviorEvent(
                    event_type="request",
                    timestamp=time.time(),
                    agent_id=agent_id,
                    data={"operation": request.operation, "resource": request.resource}
                )
            ]
            
            behavior_sequence = BehaviorSequence(
                agent_id=agent_id,
                events=behavior_events,
                start_time=time.time(),
                end_time=time.time()
            )
            
            # Perform behavioral analysis
            assessment = self.behavioral_analyzer.analyze_behavior(agent_id, behavior_sequence)
            
            return {
                "anomaly_score": assessment.anomaly_score,
                "deception_score": assessment.deception_score,
                "behavioral_assessment": assessment
            }
            
        except Exception as e:
            self.logger.error(f"Error assessing behavioral patterns: {e}")
            return {
                "anomaly_score": 0.0,
                "deception_score": 0.0,
                "behavioral_assessment": None
            }
    
    async def _perform_security_level_checks(
        self,
        agent_id: str,
        request: RequestContext
    ) -> Dict[str, Any]:
        """
        Perform security level specific checks
        
        Args:
            agent_id: Agent ID
            request: Request context
            
        Returns:
            Security level check results
        """
        threats = []
        recommendations = []
        score_multiplier = 1.0
        
        if self.security_level == SecurityLevel.MINIMAL:
            # Minimal security checks
            if request.operation in ["admin", "root"]:
                threats.append("Admin operation with minimal security")
                recommendations.append("Upgrade to higher security level")
                score_multiplier = 0.8
        
        elif self.security_level == SecurityLevel.STANDARD:
            # Standard security checks
            if request.operation in ["sensitive_data_access", "system_config"]:
                threats.append("Sensitive operation detected")
                recommendations.append("Consider enhanced security level")
                score_multiplier = 0.9
        
        elif self.security_level == SecurityLevel.ENHANCED:
            # Enhanced security checks
            if request.operation in ["data_export", "bulk_operations"]:
                threats.append("High-risk operation detected")
                recommendations.append("Monitor operation closely")
                score_multiplier = 0.95
        
        elif self.security_level == SecurityLevel.MAXIMUM:
            # Maximum security checks
            if request.operation in ["system_shutdown", "security_disable"]:
                threats.append("Critical system operation")
                recommendations.append("Require additional authorization")
                score_multiplier = 0.98
        
        return {
            "threats": threats,
            "recommendations": recommendations,
            "score_multiplier": score_multiplier
        }
    
    def get_security_statistics(self) -> Dict[str, Any]:
        """
        Get security statistics
        
        Returns:
            Dictionary containing security statistics
        """
        return {
            "security_level": self.security_level.value,
            "features_enabled": {
                "dynamic_trust": self.enable_dynamic_trust,
                "maestro_security": self.enable_maestro_security,
                "behavioral_analysis": self.enable_behavioral_analysis
            },
            "statistics": self.security_stats.copy(),
            "security_effectiveness": self._calculate_security_effectiveness()
        }
    
    def _calculate_security_effectiveness(self) -> float:
        """
        Calculate security effectiveness score
        
        Returns:
            Security effectiveness score (0.0 to 1.0)
        """
        if self.security_stats["requests_processed"] == 0:
            return 1.0
        
        # Calculate effectiveness based on threat detection rate
        threat_detection_rate = self.security_stats["threats_detected"] / self.security_stats["requests_processed"]
        
        # Calculate effectiveness based on security violation rate
        violation_rate = self.security_stats["security_violations"] / self.security_stats["requests_processed"]
        
        # Combine metrics (lower violation rate and higher detection rate is better)
        effectiveness = 1.0 - violation_rate + (threat_detection_rate * 0.5)
        
        return max(0.0, min(1.0, effectiveness))
    
    async def update_security_level(self, new_level: SecurityLevel) -> bool:
        """
        Update security level
        
        Args:
            new_level: New security level
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            self.security_level = new_level
            self.logger.info(f"Security level updated to: {new_level.value}")
            return True
        except Exception as e:
            self.logger.error(f"Error updating security level: {e}")
            return False
    
    async def enable_advanced_features(
        self,
        dynamic_trust: bool = None,
        maestro_security: bool = None,
        behavioral_analysis: bool = None
    ) -> bool:
        """
        Enable or disable advanced security features
        
        Args:
            dynamic_trust: Enable/disable dynamic trust
            maestro_security: Enable/disable MAESTRO security
            behavioral_analysis: Enable/disable behavioral analysis
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            if dynamic_trust is not None:
                self.enable_dynamic_trust = dynamic_trust
                if dynamic_trust and not self.dynamic_trust_manager:
                    self.dynamic_trust_manager = DynamicTrustManager()
            
            if maestro_security is not None:
                self.enable_maestro_security = maestro_security
                if maestro_security and not self.maestro_security:
                    self.maestro_security = MAESTROLayerSecurity()
            
            if behavioral_analysis is not None:
                self.enable_behavioral_analysis = behavioral_analysis
                if behavioral_analysis and not self.behavioral_analyzer:
                    self.behavioral_analyzer = AdvancedBehavioralAnalysis()
            
            self.logger.info("Advanced security features updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating advanced features: {e}")
            return False