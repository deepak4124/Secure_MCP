"""
Dynamic Trust Allocation System for MCP Security Framework

This module provides dynamic trust allocation inspired by zero-trust principles
but with adaptive trust mechanisms rather than complete zero-trust.
"""

import time
import math
import statistics
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from collections import defaultdict, deque
import json

from pydantic import BaseModel, Field


class TrustContext(Enum):
    """Trust context enumeration"""
    NETWORK = "network"
    DEVICE = "device"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    SPATIAL = "spatial"
    OPERATIONAL = "operational"


class TrustAllocationLevel(Enum):
    """Trust allocation level enumeration"""
    MINIMAL = "minimal"      # 0.0 - 0.2
    LOW = "low"             # 0.2 - 0.4
    MODERATE = "moderate"    # 0.4 - 0.6
    HIGH = "high"           # 0.6 - 0.8
    MAXIMAL = "maximal"     # 0.8 - 1.0


@dataclass
class TrustContextData:
    """Trust context data structure"""
    context_type: TrustContext
    value: float
    confidence: float
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DynamicTrustScore:
    """Dynamic trust score data structure"""
    agent_id: str
    overall_trust: float
    context_scores: Dict[TrustContext, float]
    allocation_level: TrustAllocationLevel
    confidence: float
    last_updated: float
    trust_trend: float
    risk_factors: List[str] = field(default_factory=list)
    security_recommendations: List[str] = field(default_factory=list)


class DynamicTrustManager:
    """
    Dynamic Trust Allocation System
    
    Features:
    - Context-aware trust allocation
    - Adaptive trust mechanisms
    - Risk-based trust adjustment
    - Continuous trust evaluation
    - Dynamic permission scaling
    """
    
    def __init__(
        self,
        base_trust_threshold: float = 0.5,
        trust_decay_rate: float = 0.95,
        context_weights: Optional[Dict[TrustContext, float]] = None,
        risk_tolerance: float = 0.3
    ):
        """
        Initialize dynamic trust manager
        
        Args:
            base_trust_threshold: Base threshold for trust allocation
            trust_decay_rate: Rate of trust decay over time
            context_weights: Weights for different trust contexts
            risk_tolerance: Risk tolerance level
        """
        self.base_trust_threshold = base_trust_threshold
        self.trust_decay_rate = trust_decay_rate
        self.risk_tolerance = risk_tolerance
        
        # Default context weights
        self.context_weights = context_weights or {
            TrustContext.BEHAVIORAL: 0.3,
            TrustContext.DEVICE: 0.2,
            TrustContext.NETWORK: 0.15,
            TrustContext.TEMPORAL: 0.15,
            TrustContext.SPATIAL: 0.1,
            TrustContext.OPERATIONAL: 0.1
        }
        
        # Trust data storage
        self.trust_contexts: Dict[str, Dict[TrustContext, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=100))
        )
        self.dynamic_trust_scores: Dict[str, DynamicTrustScore] = {}
        self.trust_allocation_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=50)
        )
        
        # Risk assessment data
        self.risk_indicators: Dict[str, List[str]] = defaultdict(list)
        self.security_recommendations: Dict[str, List[str]] = defaultdict(list)
    
    def add_trust_context(
        self, 
        agent_id: str, 
        context_data: TrustContextData
    ) -> bool:
        """
        Add trust context data for an agent
        
        Args:
            agent_id: Agent identifier
            context_data: Trust context data
            
        Returns:
            True if context added successfully
        """
        if not self._validate_context_data(context_data):
            return False
        
        # Add context data
        self.trust_contexts[agent_id][context_data.context_type].append(context_data)
        
        # Recalculate dynamic trust score
        self._calculate_dynamic_trust_score(agent_id)
        
        return True
    
    def get_dynamic_trust_score(self, agent_id: str) -> Optional[DynamicTrustScore]:
        """
        Get current dynamic trust score for an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Dynamic trust score or None if not found
        """
        return self.dynamic_trust_scores.get(agent_id)
    
    def allocate_trust_based_permissions(
        self, 
        agent_id: str, 
        requested_permissions: List[str]
    ) -> Dict[str, bool]:
        """
        Allocate permissions based on dynamic trust score
        
        Args:
            agent_id: Agent identifier
            requested_permissions: List of requested permissions
            
        Returns:
            Dictionary mapping permissions to allocation decisions
        """
        trust_score = self.get_dynamic_trust_score(agent_id)
        if not trust_score:
            return {perm: False for perm in requested_permissions}
        
        permission_allocations = {}
        
        for permission in requested_permissions:
            # Determine permission level required
            required_trust = self._get_permission_trust_requirement(permission)
            
            # Check if agent's trust meets requirement
            if trust_score.overall_trust >= required_trust:
                # Additional risk-based checks
                risk_factor = self._assess_permission_risk(permission, trust_score)
                if risk_factor <= self.risk_tolerance:
                    permission_allocations[permission] = True
                else:
                    permission_allocations[permission] = False
            else:
                permission_allocations[permission] = False
        
        # Record allocation decision
        self.trust_allocation_history[agent_id].append({
            'timestamp': time.time(),
            'permissions': requested_permissions,
            'allocations': permission_allocations,
            'trust_score': trust_score.overall_trust
        })
        
        return permission_allocations
    
    def assess_trust_risk(self, agent_id: str) -> Dict[str, Any]:
        """
        Assess trust-related risks for an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Risk assessment results
        """
        trust_score = self.get_dynamic_trust_score(agent_id)
        if not trust_score:
            return {'risk_level': 'unknown', 'risk_factors': [], 'recommendations': []}
        
        risk_factors = []
        risk_score = 0.0
        
        # Assess different risk dimensions
        if trust_score.overall_trust < 0.3:
            risk_factors.append("Very low trust score")
            risk_score += 0.4
        
        if trust_score.confidence < 0.5:
            risk_factors.append("Low confidence in trust assessment")
            risk_score += 0.2
        
        if trust_score.trust_trend < -0.2:
            risk_factors.append("Declining trust trend")
            risk_score += 0.3
        
        # Check for context-specific risks
        for context, score in trust_score.context_scores.items():
            if score < 0.2:
                risk_factors.append(f"Low {context.value} trust")
                risk_score += 0.1
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Generate recommendations
        recommendations = self._generate_security_recommendations(trust_score, risk_factors)
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'recommendations': recommendations
        }
    
    def adjust_trust_allocation(
        self, 
        agent_id: str, 
        adjustment_factor: float,
        reason: str = ""
    ) -> bool:
        """
        Manually adjust trust allocation for an agent
        
        Args:
            agent_id: Agent identifier
            adjustment_factor: Factor to adjust trust (0.0 to 2.0)
            reason: Reason for adjustment
            
        Returns:
            True if adjustment successful
        """
        if agent_id not in self.dynamic_trust_scores:
            return False
        
        trust_score = self.dynamic_trust_scores[agent_id]
        
        # Apply adjustment with bounds checking
        new_trust = max(0.0, min(1.0, trust_score.overall_trust * adjustment_factor))
        
        # Update trust score
        trust_score.overall_trust = new_trust
        trust_score.allocation_level = self._determine_allocation_level(new_trust)
        trust_score.last_updated = time.time()
        
        # Record adjustment
        self.trust_allocation_history[agent_id].append({
            'timestamp': time.time(),
            'action': 'manual_adjustment',
            'adjustment_factor': adjustment_factor,
            'reason': reason,
            'new_trust': new_trust
        })
        
        return True
    
    def get_trust_allocation_analytics(self) -> Dict[str, Any]:
        """
        Get analytics on trust allocation patterns
        
        Returns:
            Trust allocation analytics
        """
        total_agents = len(self.dynamic_trust_scores)
        if total_agents == 0:
            return {'total_agents': 0}
        
        # Calculate distribution by allocation level
        level_distribution = defaultdict(int)
        trust_scores = []
        
        for trust_score in self.dynamic_trust_scores.values():
            level_distribution[trust_score.allocation_level.value] += 1
            trust_scores.append(trust_score.overall_trust)
        
        # Calculate statistics
        avg_trust = statistics.mean(trust_scores)
        trust_std = statistics.stdev(trust_scores) if len(trust_scores) > 1 else 0
        
        # Calculate risk distribution
        risk_distribution = defaultdict(int)
        for agent_id in self.dynamic_trust_scores:
            risk_assessment = self.assess_trust_risk(agent_id)
            risk_distribution[risk_assessment['risk_level']] += 1
        
        return {
            'total_agents': total_agents,
            'average_trust': avg_trust,
            'trust_std_deviation': trust_std,
            'allocation_level_distribution': dict(level_distribution),
            'risk_distribution': dict(risk_distribution),
            'high_risk_agents': risk_distribution['high'],
            'medium_risk_agents': risk_distribution['medium'],
            'low_risk_agents': risk_distribution['low']
        }
    
    def _calculate_dynamic_trust_score(self, agent_id: str) -> None:
        """Calculate dynamic trust score for an agent"""
        if agent_id not in self.trust_contexts:
            return
        
        context_scores = {}
        total_weighted_score = 0.0
        total_weight = 0.0
        
        # Calculate scores for each context
        for context_type, weight in self.context_weights.items():
            if context_type in self.trust_contexts[agent_id]:
                context_data = list(self.trust_contexts[agent_id][context_type])
                if context_data:
                    # Calculate context score with time decay
                    context_score = self._calculate_context_score(context_data)
                    context_scores[context_type] = context_score
                    
                    total_weighted_score += context_score * weight
                    total_weight += weight
                else:
                    context_scores[context_type] = 0.5  # Neutral score
            else:
                context_scores[context_type] = 0.5  # Neutral score
        
        # Calculate overall trust score
        if total_weight > 0:
            overall_trust = total_weighted_score / total_weight
        else:
            overall_trust = 0.5
        
        # Calculate confidence based on data availability and recency
        confidence = self._calculate_confidence(agent_id)
        
        # Calculate trust trend
        trust_trend = self._calculate_trust_trend(agent_id, overall_trust)
        
        # Determine allocation level
        allocation_level = self._determine_allocation_level(overall_trust)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(context_scores, overall_trust)
        
        # Generate security recommendations
        security_recommendations = self._generate_security_recommendations(
            None, risk_factors, context_scores, overall_trust
        )
        
        # Create dynamic trust score
        trust_score = DynamicTrustScore(
            agent_id=agent_id,
            overall_trust=overall_trust,
            context_scores=context_scores,
            allocation_level=allocation_level,
            confidence=confidence,
            last_updated=time.time(),
            trust_trend=trust_trend,
            risk_factors=risk_factors,
            security_recommendations=security_recommendations
        )
        
        self.dynamic_trust_scores[agent_id] = trust_score
    
    def _calculate_context_score(self, context_data: List[TrustContextData]) -> float:
        """Calculate score for a specific context"""
        if not context_data:
            return 0.5
        
        current_time = time.time()
        weighted_scores = []
        
        for data in context_data:
            # Apply time decay
            age = current_time - data.timestamp
            decay = self.trust_decay_rate ** (age / 3600)  # Decay per hour
            
            # Weight by confidence
            weighted_score = data.value * data.confidence * decay
            weighted_scores.append(weighted_score)
        
        if weighted_scores:
            return max(0.0, min(1.0, statistics.mean(weighted_scores)))
        
        return 0.5
    
    def _calculate_confidence(self, agent_id: str) -> float:
        """Calculate confidence in trust assessment"""
        if agent_id not in self.trust_contexts:
            return 0.0
        
        total_data_points = 0
        recent_data_points = 0
        current_time = time.time()
        
        for context_data_list in self.trust_contexts[agent_id].values():
            total_data_points += len(context_data_list)
            recent_data_points += sum(
                1 for data in context_data_list 
                if current_time - data.timestamp < 3600  # Last hour
            )
        
        if total_data_points == 0:
            return 0.0
        
        # Base confidence on data availability
        data_confidence = min(1.0, total_data_points / 20)  # Normalize to 20 data points
        
        # Adjust for recency
        recency_confidence = min(1.0, recent_data_points / 5)  # Normalize to 5 recent points
        
        return (data_confidence + recency_confidence) / 2
    
    def _calculate_trust_trend(self, agent_id: str, current_trust: float) -> float:
        """Calculate trust trend over time"""
        if agent_id not in self.trust_allocation_history:
            return 0.0
        
        history = list(self.trust_allocation_history[agent_id])
        if len(history) < 2:
            return 0.0
        
        # Get recent trust scores
        recent_scores = []
        for entry in history[-10:]:  # Last 10 entries
            if 'trust_score' in entry:
                recent_scores.append(entry['trust_score'])
        
        if len(recent_scores) < 2:
            return 0.0
        
        # Calculate trend using linear regression
        x = list(range(len(recent_scores)))
        y = recent_scores
        
        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi * xi for xi in x)
        
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Normalize trend to [-1, 1] range
        return max(-1.0, min(1.0, slope * 10))
    
    def _determine_allocation_level(self, trust_score: float) -> TrustAllocationLevel:
        """Determine trust allocation level based on score"""
        if trust_score >= 0.8:
            return TrustAllocationLevel.MAXIMAL
        elif trust_score >= 0.6:
            return TrustAllocationLevel.HIGH
        elif trust_score >= 0.4:
            return TrustAllocationLevel.MODERATE
        elif trust_score >= 0.2:
            return TrustAllocationLevel.LOW
        else:
            return TrustAllocationLevel.MINIMAL
    
    def _get_permission_trust_requirement(self, permission: str) -> float:
        """Get trust requirement for a specific permission"""
        # Define trust requirements for different permissions
        permission_requirements = {
            'read_data': 0.3,
            'write_data': 0.5,
            'execute_tool': 0.4,
            'admin_access': 0.8,
            'system_config': 0.9,
            'user_management': 0.7,
            'audit_access': 0.6,
            'network_access': 0.5
        }
        
        return permission_requirements.get(permission, 0.5)
    
    def _assess_permission_risk(self, permission: str, trust_score: DynamicTrustScore) -> float:
        """Assess risk of granting a specific permission"""
        base_risk = 0.1  # Base risk for any permission
        
        # Adjust risk based on trust score
        if trust_score.overall_trust < 0.3:
            base_risk += 0.4
        elif trust_score.overall_trust < 0.5:
            base_risk += 0.2
        
        # Adjust risk based on confidence
        if trust_score.confidence < 0.5:
            base_risk += 0.2
        
        # Adjust risk based on trust trend
        if trust_score.trust_trend < -0.2:
            base_risk += 0.3
        
        # Permission-specific risk adjustments
        high_risk_permissions = ['admin_access', 'system_config', 'user_management']
        if permission in high_risk_permissions:
            base_risk += 0.2
        
        return min(1.0, base_risk)
    
    def _identify_risk_factors(
        self, 
        context_scores: Dict[TrustContext, float], 
        overall_trust: float
    ) -> List[str]:
        """Identify risk factors based on trust scores"""
        risk_factors = []
        
        if overall_trust < 0.3:
            risk_factors.append("Very low overall trust")
        
        for context, score in context_scores.items():
            if score < 0.2:
                risk_factors.append(f"Low {context.value} trust")
        
        return risk_factors
    
    def _generate_security_recommendations(
        self, 
        trust_score: Optional[DynamicTrustScore] = None,
        risk_factors: Optional[List[str]] = None,
        context_scores: Optional[Dict[TrustContext, float]] = None,
        overall_trust: Optional[float] = None
    ) -> List[str]:
        """Generate security recommendations based on trust assessment"""
        recommendations = []
        
        if trust_score:
            overall_trust = trust_score.overall_trust
            context_scores = trust_score.context_scores
            risk_factors = trust_score.risk_factors
        
        if overall_trust and overall_trust < 0.3:
            recommendations.append("Consider restricting agent access to critical resources")
            recommendations.append("Implement additional monitoring and logging")
        
        if context_scores:
            for context, score in context_scores.items():
                if score < 0.2:
                    if context == TrustContext.BEHAVIORAL:
                        recommendations.append("Monitor agent behavior patterns more closely")
                    elif context == TrustContext.DEVICE:
                        recommendations.append("Verify device integrity and security posture")
                    elif context == TrustContext.NETWORK:
                        recommendations.append("Check network security and connection integrity")
        
        if risk_factors:
            if "Very low overall trust" in risk_factors:
                recommendations.append("Consider temporary suspension pending investigation")
            if any("Low" in factor for factor in risk_factors):
                recommendations.append("Increase monitoring frequency and detail level")
        
        return recommendations
    
    def _validate_context_data(self, context_data: TrustContextData) -> bool:
        """Validate trust context data"""
        if not 0.0 <= context_data.value <= 1.0:
            return False
        
        if not 0.0 <= context_data.confidence <= 1.0:
            return False
        
        if context_data.timestamp > time.time():
            return False
        
        return True
