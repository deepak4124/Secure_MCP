"""
Reputation Management System for MCP Security Framework

This module provides comprehensive reputation tracking and management including:
- Multi-dimensional reputation scoring
- Reputation aggregation and propagation
- Reputation decay and time-based adjustments
- Reputation-based decision making
- Reputation attack resistance
- Cross-domain reputation transfer
- Reputation visualization and analytics
"""

import time
import math
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
import numpy as np
from scipy import stats

from pydantic import BaseModel, Field


class ReputationDimension(Enum):
    """Reputation dimension enumeration"""
    COMPETENCE = "competence"
    RELIABILITY = "reliability"
    HONESTY = "honesty"
    COOPERATION = "cooperation"
    SECURITY = "security"
    PERFORMANCE = "performance"
    INNOVATION = "innovation"
    LEADERSHIP = "leadership"


class ReputationSource(Enum):
    """Reputation source enumeration"""
    DIRECT_EXPERIENCE = "direct_experience"
    WITNESS_REPORT = "witness_report"
    THIRD_PARTY = "third_party"
    SYSTEM_GENERATED = "system_generated"
    PEER_REVIEW = "peer_review"
    EXPERT_ASSESSMENT = "expert_assessment"


class ReputationEvent(Enum):
    """Reputation event enumeration"""
    TASK_COMPLETION = "task_completion"
    TASK_FAILURE = "task_failure"
    SECURITY_VIOLATION = "security_violation"
    SECURITY_CONTRIBUTION = "security_contribution"
    COOPERATION_POSITIVE = "cooperation_positive"
    COOPERATION_NEGATIVE = "cooperation_negative"
    INNOVATION_CONTRIBUTION = "innovation_contribution"
    LEADERSHIP_DEMONSTRATION = "leadership_demonstration"
    PEER_ENDORSEMENT = "peer_endorsement"
    PEER_CRITICISM = "peer_criticism"


class ReputationLevel(Enum):
    """Reputation level enumeration"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    EXCELLENT = "excellent"


@dataclass
class ReputationScore:
    """Reputation score data structure"""
    entity_id: str
    dimension: ReputationDimension
    score: float  # 0-1 scale
    confidence: float  # 0-1 scale
    source_count: int
    last_updated: float
    trend: float  # -1 to 1
    volatility: float  # 0-1 scale


@dataclass
class ReputationEvent:
    """Reputation event data structure"""
    event_id: str
    entity_id: str
    event_type: ReputationEvent
    dimension: ReputationDimension
    value: float  # -1 to 1
    source: ReputationSource
    source_entity: Optional[str]
    timestamp: float
    context: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0


@dataclass
class ReputationProfile:
    """Comprehensive reputation profile"""
    entity_id: str
    overall_reputation: float
    dimension_scores: Dict[ReputationDimension, ReputationScore]
    reputation_level: ReputationLevel
    trustworthiness: float
    influence_score: float
    network_position: float
    last_updated: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReputationNetwork:
    """Reputation network representation"""
    network_id: str
    entities: Set[str]
    relationships: Dict[Tuple[str, str], float]  # (entity1, entity2) -> relationship_strength
    centrality_scores: Dict[str, float]
    community_structure: Dict[str, List[str]]
    last_updated: float


class ReputationManager:
    """
    Comprehensive reputation management system
    
    Features:
    - Multi-dimensional reputation scoring
    - Reputation aggregation and propagation
    - Reputation decay and time-based adjustments
    - Reputation-based decision making
    - Reputation attack resistance
    - Cross-domain reputation transfer
    - Reputation visualization and analytics
    - Network-based reputation analysis
    """
    
    def __init__(self):
        """Initialize reputation manager"""
        self.reputation_scores: Dict[str, Dict[ReputationDimension, ReputationScore]] = defaultdict(dict)
        self.reputation_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.reputation_networks: Dict[str, ReputationNetwork] = {}
        self.reputation_profiles: Dict[str, ReputationProfile] = {}
        
        # Reputation parameters
        self.decay_factor = 0.95  # Reputation decay per time unit
        self.min_events = 5  # Minimum events for reliable reputation
        self.confidence_threshold = 0.6  # Minimum confidence for reputation decisions
        self.volatility_threshold = 0.3  # High volatility threshold
        
        # Dimension weights for overall reputation
        self.dimension_weights = {
            ReputationDimension.COMPETENCE: 0.25,
            ReputationDimension.RELIABILITY: 0.20,
            ReputationDimension.HONESTY: 0.20,
            ReputationDimension.COOPERATION: 0.15,
            ReputationDimension.SECURITY: 0.10,
            ReputationDimension.PERFORMANCE: 0.05,
            ReputationDimension.INNOVATION: 0.03,
            ReputationDimension.LEADERSHIP: 0.02
        }
        
        # Event type weights
        self.event_weights = {
            ReputationEvent.TASK_COMPLETION: 0.3,
            ReputationEvent.TASK_FAILURE: -0.2,
            ReputationEvent.SECURITY_VIOLATION: -0.5,
            ReputationEvent.SECURITY_CONTRIBUTION: 0.4,
            ReputationEvent.COOPERATION_POSITIVE: 0.2,
            ReputationEvent.COOPERATION_NEGATIVE: -0.2,
            ReputationEvent.INNOVATION_CONTRIBUTION: 0.3,
            ReputationEvent.LEADERSHIP_DEMONSTRATION: 0.4,
            ReputationEvent.PEER_ENDORSEMENT: 0.3,
            ReputationEvent.PEER_CRITICISM: -0.3
        }
        
        # Source credibility weights
        self.source_weights = {
            ReputationSource.DIRECT_EXPERIENCE: 1.0,
            ReputationSource.WITNESS_REPORT: 0.8,
            ReputationSource.PEER_REVIEW: 0.7,
            ReputationSource.EXPERT_ASSESSMENT: 0.9,
            ReputationSource.THIRD_PARTY: 0.6,
            ReputationSource.SYSTEM_GENERATED: 0.5
        }
    
    def add_reputation_event(self, event: ReputationEvent) -> bool:
        """
        Add a reputation event
        
        Args:
            event: Reputation event to add
            
        Returns:
            True if event added successfully
        """
        # Validate event
        if not self._validate_reputation_event(event):
            return False
        
        # Add event to storage
        self.reputation_events[event.entity_id].append(event)
        
        # Update reputation scores
        self._update_reputation_scores(event.entity_id)
        
        # Update reputation networks
        self._update_reputation_networks(event)
        
        return True
    
    def _validate_reputation_event(self, event: ReputationEvent) -> bool:
        """Validate reputation event"""
        if not -1.0 <= event.value <= 1.0:
            return False
        
        if event.timestamp > time.time():
            return False
        
        if event.weight <= 0:
            return False
        
        return True
    
    def _update_reputation_scores(self, entity_id: str):
        """Update reputation scores for an entity"""
        events = list(self.reputation_events[entity_id])
        
        if not events:
            return
        
        # Group events by dimension
        dimension_events = defaultdict(list)
        for event in events:
            dimension_events[event.dimension].append(event)
        
        # Calculate scores for each dimension
        for dimension, dim_events in dimension_events.items():
            score = self._calculate_dimension_score(dim_events)
            confidence = self._calculate_confidence(dim_events)
            trend = self._calculate_trend(dim_events)
            volatility = self._calculate_volatility(dim_events)
            
            reputation_score = ReputationScore(
                entity_id=entity_id,
                dimension=dimension,
                score=score,
                confidence=confidence,
                source_count=len(dim_events),
                last_updated=time.time(),
                trend=trend,
                volatility=volatility
            )
            
            self.reputation_scores[entity_id][dimension] = reputation_score
        
        # Update reputation profile
        self._update_reputation_profile(entity_id)
    
    def _calculate_dimension_score(self, events: List[ReputationEvent]) -> float:
        """Calculate reputation score for a dimension"""
        if not events:
            return 0.5  # Neutral score
        
        # Apply time decay and weights
        current_time = time.time()
        weighted_scores = []
        
        for event in events:
            # Time decay
            age = current_time - event.timestamp
            decay = self.decay_factor ** (age / 86400)  # Decay per day
            
            # Event weight
            event_weight = self.event_weights.get(event.event_type, 0.0)
            
            # Source weight
            source_weight = self.source_weights.get(event.source, 0.5)
            
            # Combined weight
            total_weight = event_weight * source_weight * event.weight * decay
            
            # Weighted score
            weighted_score = event.value * total_weight
            weighted_scores.append(weighted_score)
        
        # Calculate average weighted score
        if weighted_scores:
            avg_score = np.mean(weighted_scores)
            # Normalize to [0, 1] range
            return max(0.0, min(1.0, 0.5 + avg_score))
        
        return 0.5
    
    def _calculate_confidence(self, events: List[ReputationEvent]) -> float:
        """Calculate confidence in reputation score"""
        if not events:
            return 0.0
        
        # Base confidence on event count
        event_confidence = min(1.0, len(events) / (self.min_events * 2))
        
        # Adjust for event recency
        current_time = time.time()
        recent_events = [e for e in events if current_time - e.timestamp < 86400]  # Last 24 hours
        recency_confidence = min(1.0, len(recent_events) / 3)
        
        # Adjust for source diversity
        sources = set(event.source for event in events)
        source_diversity = min(1.0, len(sources) / 3)
        
        # Combine confidences
        confidence = (event_confidence + recency_confidence + source_diversity) / 3
        
        return max(0.0, min(1.0, confidence))
    
    def _calculate_trend(self, events: List[ReputationEvent]) -> float:
        """Calculate reputation trend over time"""
        if len(events) < 2:
            return 0.0
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Calculate trend using linear regression
        timestamps = [e.timestamp for e in sorted_events]
        values = [e.value for e in sorted_events]
        
        if len(timestamps) < 2:
            return 0.0
        
        # Calculate slope
        slope = np.polyfit(timestamps, values, 1)[0]
        
        # Normalize trend to [-1, 1] range
        trend = max(-1.0, min(1.0, slope * 1000))  # Scale factor
        
        return trend
    
    def _calculate_volatility(self, events: List[ReputationEvent]) -> float:
        """Calculate reputation volatility"""
        if len(events) < 3:
            return 0.0
        
        values = [e.value for e in events]
        volatility = np.std(values)
        
        return min(1.0, volatility)
    
    def _update_reputation_profile(self, entity_id: str):
        """Update comprehensive reputation profile"""
        if entity_id not in self.reputation_scores:
            return
        
        dimension_scores = self.reputation_scores[entity_id]
        
        # Calculate overall reputation
        overall_reputation = 0.0
        total_weight = 0.0
        
        for dimension, score in dimension_scores.items():
            weight = self.dimension_weights.get(dimension, 0.0)
            overall_reputation += score.score * weight
            total_weight += weight
        
        if total_weight > 0:
            overall_reputation /= total_weight
        
        # Determine reputation level
        reputation_level = self._determine_reputation_level(overall_reputation)
        
        # Calculate trustworthiness
        trustworthiness = self._calculate_trustworthiness(dimension_scores)
        
        # Calculate influence score
        influence_score = self._calculate_influence_score(entity_id)
        
        # Calculate network position
        network_position = self._calculate_network_position(entity_id)
        
        profile = ReputationProfile(
            entity_id=entity_id,
            overall_reputation=overall_reputation,
            dimension_scores=dimension_scores,
            reputation_level=reputation_level,
            trustworthiness=trustworthiness,
            influence_score=influence_score,
            network_position=network_position,
            last_updated=time.time()
        )
        
        self.reputation_profiles[entity_id] = profile
    
    def _determine_reputation_level(self, reputation: float) -> ReputationLevel:
        """Determine reputation level from score"""
        if reputation >= 0.95:
            return ReputationLevel.EXCELLENT
        elif reputation >= 0.85:
            return ReputationLevel.VERY_HIGH
        elif reputation >= 0.70:
            return ReputationLevel.HIGH
        elif reputation >= 0.50:
            return ReputationLevel.MEDIUM
        elif reputation >= 0.30:
            return ReputationLevel.LOW
        else:
            return ReputationLevel.VERY_LOW
    
    def _calculate_trustworthiness(self, dimension_scores: Dict[ReputationDimension, ReputationScore]) -> float:
        """Calculate trustworthiness score"""
        trust_dimensions = [
            ReputationDimension.HONESTY,
            ReputationDimension.RELIABILITY,
            ReputationDimension.SECURITY
        ]
        
        trust_scores = []
        for dimension in trust_dimensions:
            if dimension in dimension_scores:
                score = dimension_scores[dimension]
                # Weight by confidence
                weighted_score = score.score * score.confidence
                trust_scores.append(weighted_score)
        
        if trust_scores:
            return np.mean(trust_scores)
        
        return 0.0
    
    def _calculate_influence_score(self, entity_id: str) -> float:
        """Calculate influence score based on network position"""
        # Simplified influence calculation
        # In a real implementation, this would consider network centrality, etc.
        
        if entity_id not in self.reputation_scores:
            return 0.0
        
        dimension_scores = self.reputation_scores[entity_id]
        
        # Influence based on leadership and innovation dimensions
        influence_dimensions = [
            ReputationDimension.LEADERSHIP,
            ReputationDimension.INNOVATION,
            ReputationDimension.COOPERATION
        ]
        
        influence_scores = []
        for dimension in influence_dimensions:
            if dimension in dimension_scores:
                score = dimension_scores[dimension]
                influence_scores.append(score.score)
        
        if influence_scores:
            return np.mean(influence_scores)
        
        return 0.0
    
    def _calculate_network_position(self, entity_id: str) -> float:
        """Calculate network position score"""
        # Simplified network position calculation
        # In a real implementation, this would consider actual network topology
        
        if entity_id not in self.reputation_events:
            return 0.0
        
        events = list(self.reputation_events[entity_id])
        
        # Count unique source entities
        source_entities = set()
        for event in events:
            if event.source_entity:
                source_entities.add(event.source_entity)
        
        # Network position based on number of connections
        connection_count = len(source_entities)
        network_position = min(1.0, connection_count / 10.0)  # Normalize to 10 connections
        
        return network_position
    
    def _update_reputation_networks(self, event: ReputationEvent):
        """Update reputation networks based on event"""
        # This is a simplified implementation
        # In a real system, this would maintain actual network graphs
        
        if event.source_entity:
            # Create or update network relationship
            network_id = "default"
            
            if network_id not in self.reputation_networks:
                self.reputation_networks[network_id] = ReputationNetwork(
                    network_id=network_id,
                    entities=set(),
                    relationships={},
                    centrality_scores={},
                    community_structure={},
                    last_updated=time.time()
                )
            
            network = self.reputation_networks[network_id]
            network.entities.add(event.entity_id)
            network.entities.add(event.source_entity)
            
            # Update relationship strength
            relationship_key = (event.source_entity, event.entity_id)
            if relationship_key not in network.relationships:
                network.relationships[relationship_key] = 0.0
            
            # Update relationship strength based on event
            network.relationships[relationship_key] += event.value * event.weight * 0.1
            network.relationships[relationship_key] = max(-1.0, min(1.0, network.relationships[relationship_key]))
            
            network.last_updated = time.time()
    
    def get_reputation_score(self, entity_id: str, dimension: ReputationDimension) -> Optional[ReputationScore]:
        """Get reputation score for an entity and dimension"""
        if entity_id in self.reputation_scores and dimension in self.reputation_scores[entity_id]:
            return self.reputation_scores[entity_id][dimension]
        return None
    
    def get_reputation_profile(self, entity_id: str) -> Optional[ReputationProfile]:
        """Get comprehensive reputation profile for an entity"""
        return self.reputation_profiles.get(entity_id)
    
    def get_reputation_ranking(self, dimension: ReputationDimension = None, limit: int = 10) -> List[Tuple[str, float]]:
        """
        Get reputation ranking
        
        Args:
            dimension: Specific dimension to rank by (None for overall)
            limit: Maximum number of entities to return
            
        Returns:
            List of (entity_id, score) tuples
        """
        rankings = []
        
        for entity_id, profile in self.reputation_profiles.items():
            if dimension:
                if dimension in profile.dimension_scores:
                    score = profile.dimension_scores[dimension].score
                    confidence = profile.dimension_scores[dimension].confidence
                    if confidence >= self.confidence_threshold:
                        rankings.append((entity_id, score))
            else:
                if profile.overall_reputation > 0:
                    rankings.append((entity_id, profile.overall_reputation))
        
        # Sort by score
        rankings.sort(key=lambda x: x[1], reverse=True)
        
        return rankings[:limit]
    
    def detect_reputation_attacks(self, entity_id: str) -> List[Dict[str, Any]]:
        """
        Detect potential reputation attacks
        
        Args:
            entity_id: Entity to analyze
            
        Returns:
            List of detected attack patterns
        """
        if entity_id not in self.reputation_events:
            return []
        
        events = list(self.reputation_events[entity_id])
        attacks = []
        
        # Check for sudden reputation changes
        if len(events) >= 10:
            recent_events = events[-10:]
            older_events = events[-20:-10] if len(events) >= 20 else events[:-10]
            
            recent_avg = np.mean([e.value for e in recent_events])
            older_avg = np.mean([e.value for e in older_events])
            
            if abs(recent_avg - older_avg) > 0.5:  # Significant change
                attacks.append({
                    "attack_type": "sudden_reputation_change",
                    "description": f"Sudden reputation change from {older_avg:.3f} to {recent_avg:.3f}",
                    "severity": "medium",
                    "confidence": 0.7
                })
        
        # Check for coordinated attacks (multiple negative events from same source)
        source_events = defaultdict(list)
        for event in events:
            if event.source_entity:
                source_events[event.source_entity].append(event)
        
        for source, source_event_list in source_events.items():
            if len(source_event_list) >= 5:  # Multiple events from same source
                negative_events = [e for e in source_event_list if e.value < 0]
                if len(negative_events) >= 3:  # Multiple negative events
                    attacks.append({
                        "attack_type": "coordinated_attack",
                        "description": f"Multiple negative events from source {source}",
                        "severity": "high",
                        "confidence": 0.8,
                        "source": source
                    })
        
        # Check for high volatility
        if entity_id in self.reputation_scores:
            for dimension, score in self.reputation_scores[entity_id].items():
                if score.volatility > self.volatility_threshold:
                    attacks.append({
                        "attack_type": "high_volatility",
                        "description": f"High volatility in {dimension.value} dimension",
                        "severity": "medium",
                        "confidence": 0.6,
                        "dimension": dimension.value,
                        "volatility": score.volatility
                    })
        
        return attacks
    
    def transfer_reputation(self, from_entity: str, to_entity: str, 
                          transfer_factor: float = 0.1) -> bool:
        """
        Transfer reputation between entities
        
        Args:
            from_entity: Source entity
            to_entity: Target entity
            transfer_factor: Factor for reputation transfer (0-1)
            
        Returns:
            True if transfer successful
        """
        if from_entity not in self.reputation_profiles:
            return False
        
        source_profile = self.reputation_profiles[from_entity]
        
        # Create transfer events
        for dimension, score in source_profile.dimension_scores.items():
            if score.confidence >= self.confidence_threshold:
                transfer_value = score.score * transfer_factor
                
                transfer_event = ReputationEvent(
                    event_id=str(uuid.uuid4()),
                    entity_id=to_entity,
                    event_type=ReputationEvent.PEER_ENDORSEMENT,
                    dimension=dimension,
                    value=transfer_value,
                    source=ReputationSource.WITNESS_REPORT,
                    source_entity=from_entity,
                    timestamp=time.time(),
                    context={"transfer_from": from_entity, "transfer_factor": transfer_factor},
                    weight=0.5  # Reduced weight for transferred reputation
                )
                
                self.add_reputation_event(transfer_event)
        
        return True
    
    def get_reputation_analytics(self) -> Dict[str, Any]:
        """Get reputation analytics and statistics"""
        analytics = {
            "total_entities": len(self.reputation_profiles),
            "total_events": sum(len(events) for events in self.reputation_events.values()),
            "reputation_distribution": defaultdict(int),
            "dimension_statistics": {},
            "network_statistics": {},
            "attack_detection": {}
        }
        
        # Reputation level distribution
        for profile in self.reputation_profiles.values():
            analytics["reputation_distribution"][profile.reputation_level.value] += 1
        
        # Dimension statistics
        for dimension in ReputationDimension:
            scores = []
            confidences = []
            
            for entity_scores in self.reputation_scores.values():
                if dimension in entity_scores:
                    score = entity_scores[dimension]
                    scores.append(score.score)
                    confidences.append(score.confidence)
            
            if scores:
                analytics["dimension_statistics"][dimension.value] = {
                    "mean_score": np.mean(scores),
                    "std_score": np.std(scores),
                    "mean_confidence": np.mean(confidences),
                    "entity_count": len(scores)
                }
        
        # Network statistics
        for network in self.reputation_networks.values():
            analytics["network_statistics"][network.network_id] = {
                "entity_count": len(network.entities),
                "relationship_count": len(network.relationships),
                "last_updated": network.last_updated
            }
        
        # Attack detection statistics
        total_attacks = 0
        attack_types = defaultdict(int)
        
        for entity_id in self.reputation_profiles.keys():
            attacks = self.detect_reputation_attacks(entity_id)
            total_attacks += len(attacks)
            
            for attack in attacks:
                attack_types[attack["attack_type"]] += 1
        
        analytics["attack_detection"] = {
            "total_attacks": total_attacks,
            "attack_types": dict(attack_types),
            "entities_with_attacks": len([e for e in self.reputation_profiles.keys() 
                                        if self.detect_reputation_attacks(e)])
        }
        
        return analytics
    
    def export_reputation_data(self, file_path: str) -> bool:
        """Export reputation data to file"""
        try:
            export_data = {
                "reputation_scores": {
                    entity_id: {
                        dimension.value: {
                            "entity_id": score.entity_id,
                            "dimension": score.dimension.value,
                            "score": score.score,
                            "confidence": score.confidence,
                            "source_count": score.source_count,
                            "last_updated": score.last_updated,
                            "trend": score.trend,
                            "volatility": score.volatility
                        }
                        for dimension, score in dimension_scores.items()
                    }
                    for entity_id, dimension_scores in self.reputation_scores.items()
                },
                "reputation_profiles": {
                    entity_id: {
                        "entity_id": profile.entity_id,
                        "overall_reputation": profile.overall_reputation,
                        "reputation_level": profile.reputation_level.value,
                        "trustworthiness": profile.trustworthiness,
                        "influence_score": profile.influence_score,
                        "network_position": profile.network_position,
                        "last_updated": profile.last_updated,
                        "metadata": profile.metadata
                    }
                    for entity_id, profile in self.reputation_profiles.items()
                },
                "reputation_events": {
                    entity_id: [
                        {
                            "event_id": event.event_id,
                            "entity_id": event.entity_id,
                            "event_type": event.event_type.value,
                            "dimension": event.dimension.value,
                            "value": event.value,
                            "source": event.source.value,
                            "source_entity": event.source_entity,
                            "timestamp": event.timestamp,
                            "context": event.context,
                            "weight": event.weight
                        }
                        for event in events
                    ]
                    for entity_id, events in self.reputation_events.items()
                },
                "reputation_networks": {
                    network_id: {
                        "network_id": network.network_id,
                        "entities": list(network.entities),
                        "relationships": {f"{k[0]}-{k[1]}": v for k, v in network.relationships.items()},
                        "centrality_scores": network.centrality_scores,
                        "community_structure": network.community_structure,
                        "last_updated": network.last_updated
                    }
                    for network_id, network in self.reputation_networks.items()
                },
                "analytics": self.get_reputation_analytics(),
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting reputation data: {e}")
            return False
