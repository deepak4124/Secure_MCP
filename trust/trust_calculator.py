"""
Trust Calculation System for Secure Multi-Agent MCP Networks

This module provides comprehensive trust calculation including:
- Multi-dimensional trust scoring
- Behavioral analysis and pattern recognition
- Trust aggregation from multiple sources
- Trust decay and time-based adjustments
- Sybil attack detection and resistance
"""

import time
import math
import statistics
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from collections import defaultdict, deque
import json

from pydantic import BaseModel, Field


class TrustDimension(Enum):
    """Trust dimension enumeration"""
    COMPETENCE = "competence"  # Ability to perform tasks correctly
    RELIABILITY = "reliability"  # Consistency in task completion
    HONESTY = "honesty"  # Truthfulness in reporting
    COOPERATION = "cooperation"  # Willingness to collaborate
    SECURITY = "security"  # Adherence to security protocols


class TrustEventType(Enum):
    """Trust event type enumeration"""
    TASK_SUCCESS = "task_success"
    TASK_FAILURE = "task_failure"
    SECURITY_VIOLATION = "security_violation"
    COOPERATION_POSITIVE = "cooperation_positive"
    COOPERATION_NEGATIVE = "cooperation_negative"
    HONESTY_POSITIVE = "honesty_positive"
    HONESTY_NEGATIVE = "honesty_negative"


@dataclass
class TrustEvent:
    """Trust event data structure"""
    event_id: str
    agent_id: str
    event_type: TrustEventType
    timestamp: float
    value: float  # Event value (0.0 to 1.0)
    context: Dict[str, str] = field(default_factory=dict)
    source_agent: Optional[str] = None  # Agent that reported the event


@dataclass
class TrustScore:
    """Trust score data structure"""
    agent_id: str
    overall_score: float
    dimension_scores: Dict[TrustDimension, float]
    confidence: float
    last_updated: float
    event_count: int
    trend: float  # Trust trend over time


class TrustCalculator:
    """
    Comprehensive trust calculation system for multi-agent networks
    
    Features:
    - Multi-dimensional trust scoring
    - Behavioral analysis and pattern recognition
    - Trust aggregation from multiple sources
    - Trust decay and time-based adjustments
    - Sybil attack detection and resistance
    - Collusion detection and prevention
    """
    
    def __init__(
        self,
        decay_factor: float = 0.95,
        min_events: int = 5,
        window_size: int = 100,
        sybil_threshold: float = 0.8
    ):
        """
        Initialize trust calculator
        
        Args:
            decay_factor: Trust decay factor per time unit
            min_events: Minimum events required for reliable trust score
            window_size: Size of sliding window for event analysis
            sybil_threshold: Threshold for sybil attack detection
        """
        self.decay_factor = decay_factor
        self.min_events = min_events
        self.window_size = window_size
        self.sybil_threshold = sybil_threshold
        
        # Trust data storage
        self.trust_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.trust_scores: Dict[str, TrustScore] = {}
        self.agent_relationships: Dict[str, Set[str]] = defaultdict(set)
        self.sybil_scores: Dict[str, float] = {}
        
        # Trust calculation parameters
        self.dimension_weights = {
            TrustDimension.COMPETENCE: 0.3,
            TrustDimension.RELIABILITY: 0.25,
            TrustDimension.HONESTY: 0.2,
            TrustDimension.COOPERATION: 0.15,
            TrustDimension.SECURITY: 0.1
        }
        
        # Event type weights
        self.event_weights = {
            TrustEventType.TASK_SUCCESS: 0.3,
            TrustEventType.TASK_FAILURE: -0.2,
            TrustEventType.SECURITY_VIOLATION: -0.5,
            TrustEventType.COOPERATION_POSITIVE: 0.15,
            TrustEventType.COOPERATION_NEGATIVE: -0.15,
            TrustEventType.HONESTY_POSITIVE: 0.2,
            TrustEventType.HONESTY_NEGATIVE: -0.3
        }
    
    def add_trust_event(self, event: TrustEvent) -> bool:
        """
        Add a trust event for an agent
        
        Args:
            event: Trust event to add
            
        Returns:
            True if event added successfully
        """
        # Validate event
        if not self._validate_event(event):
            return False
        
        # Add event to storage
        self.trust_events[event.agent_id].append(event)
        
        # Update agent relationships
        if event.source_agent and event.source_agent != event.agent_id:
            self.agent_relationships[event.agent_id].add(event.source_agent)
            self.agent_relationships[event.source_agent].add(event.agent_id)
        
        # Recalculate trust score
        self._calculate_trust_score(event.agent_id)
        
        # Update sybil detection
        self._update_sybil_detection(event.agent_id)
        
        return True
    
    def get_trust_score(self, agent_id: str) -> Optional[TrustScore]:
        """
        Get current trust score for an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Trust score or None if not found
        """
        return self.trust_scores.get(agent_id)
    
    def get_trust_ranking(self, limit: Optional[int] = None) -> List[Tuple[str, float]]:
        """
        Get trust ranking of all agents
        
        Args:
            limit: Maximum number of agents to return
            
        Returns:
            List of (agent_id, trust_score) tuples sorted by trust score
        """
        scores = [
            (agent_id, score.overall_score)
            for agent_id, score in self.trust_scores.items()
            if score.confidence > 0.5  # Only include confident scores
        ]
        
        scores.sort(key=lambda x: x[1], reverse=True)
        
        if limit:
            scores = scores[:limit]
        
        return scores
    
    def detect_sybil_agents(self) -> List[str]:
        """
        Detect potential sybil agents
        
        Returns:
            List of agent IDs identified as potential sybils
        """
        sybil_agents = []
        
        for agent_id, sybil_score in self.sybil_scores.items():
            if sybil_score > self.sybil_threshold:
                sybil_agents.append(agent_id)
        
        return sybil_agents
    
    def detect_collusion(self, agent_id: str) -> List[str]:
        """
        Detect potential collusion for an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of agent IDs potentially colluding
        """
        if agent_id not in self.agent_relationships:
            return []
        
        colluding_agents = []
        agent_events = self.trust_events[agent_id]
        
        # Analyze event patterns for collusion indicators
        for related_agent in self.agent_relationships[agent_id]:
            if related_agent == agent_id:
                continue
            
            # Check for suspicious patterns
            collusion_score = self._calculate_collusion_score(agent_id, related_agent)
            
            if collusion_score > 0.7:  # Collusion threshold
                colluding_agents.append(related_agent)
        
        return colluding_agents
    
    def predict_trust_trend(self, agent_id: str, time_horizon: float = 3600) -> float:
        """
        Predict trust trend for an agent
        
        Args:
            agent_id: Agent identifier
            time_horizon: Time horizon for prediction in seconds
            
        Returns:
            Predicted trust change
        """
        if agent_id not in self.trust_events:
            return 0.0
        
        events = list(self.trust_events[agent_id])
        if len(events) < 3:
            return 0.0
        
        # Calculate recent trend
        recent_events = [e for e in events if time.time() - e.timestamp < 3600]  # Last hour
        
        if len(recent_events) < 2:
            return 0.0
        
        # Simple linear trend calculation
        timestamps = [e.timestamp for e in recent_events]
        values = [e.value for e in recent_events]
        
        # Calculate slope
        n = len(timestamps)
        sum_x = sum(timestamps)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(timestamps, values))
        sum_x2 = sum(x * x for x in timestamps)
        
        if n * sum_x2 - sum_x * sum_x == 0:
            return 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        
        # Predict change over time horizon
        predicted_change = slope * time_horizon
        
        return max(-1.0, min(1.0, predicted_change))  # Clamp to [-1, 1]
    
    def _validate_event(self, event: TrustEvent) -> bool:
        """Validate trust event"""
        if not 0.0 <= event.value <= 1.0:
            return False
        
        if event.timestamp > time.time():
            return False
        
        return True
    
    def _calculate_trust_score(self, agent_id: str) -> None:
        """Calculate trust score for an agent"""
        events = list(self.trust_events[agent_id])
        
        if len(events) < self.min_events:
            # Not enough events for reliable score
            return
        
        # Calculate dimension scores
        dimension_scores = {}
        
        for dimension in TrustDimension:
            dimension_events = self._filter_events_by_dimension(events, dimension)
            dimension_scores[dimension] = self._calculate_dimension_score(dimension_events)
        
        # Calculate overall score
        overall_score = sum(
            score * self.dimension_weights[dimension]
            for dimension, score in dimension_scores.items()
        )
        
        # Calculate confidence based on event count and recency
        confidence = self._calculate_confidence(events)
        
        # Calculate trend
        trend = self._calculate_trend(events)
        
        # Create trust score
        trust_score = TrustScore(
            agent_id=agent_id,
            overall_score=max(0.0, min(1.0, overall_score)),
            dimension_scores=dimension_scores,
            confidence=confidence,
            last_updated=time.time(),
            event_count=len(events),
            trend=trend
        )
        
        self.trust_scores[agent_id] = trust_score
    
    def _filter_events_by_dimension(self, events: List[TrustEvent], dimension: TrustDimension) -> List[TrustEvent]:
        """Filter events by trust dimension"""
        dimension_mapping = {
            TrustDimension.COMPETENCE: [TrustEventType.TASK_SUCCESS, TrustEventType.TASK_FAILURE],
            TrustDimension.RELIABILITY: [TrustEventType.TASK_SUCCESS, TrustEventType.TASK_FAILURE],
            TrustDimension.HONESTY: [TrustEventType.HONESTY_POSITIVE, TrustEventType.HONESTY_NEGATIVE],
            TrustDimension.COOPERATION: [TrustEventType.COOPERATION_POSITIVE, TrustEventType.COOPERATION_NEGATIVE],
            TrustDimension.SECURITY: [TrustEventType.SECURITY_VIOLATION]
        }
        
        relevant_types = dimension_mapping.get(dimension, [])
        
        return [e for e in events if e.event_type in relevant_types]
    
    def _calculate_dimension_score(self, events: List[TrustEvent]) -> float:
        """Calculate score for a specific dimension"""
        if not events:
            return 0.5  # Neutral score
        
        # Apply time decay
        current_time = time.time()
        weighted_scores = []
        
        for event in events:
            age = current_time - event.timestamp
            decay = self.decay_factor ** (age / 3600)  # Decay per hour
            
            event_weight = self.event_weights.get(event.event_type, 0.0)
            weighted_score = event.value * event_weight * decay
            
            weighted_scores.append(weighted_score)
        
        # Calculate average weighted score
        if weighted_scores:
            avg_score = statistics.mean(weighted_scores)
            # Normalize to [0, 1] range
            return max(0.0, min(1.0, 0.5 + avg_score))
        
        return 0.5
    
    def _calculate_confidence(self, events: List[TrustEvent]) -> float:
        """Calculate confidence in trust score"""
        if not events:
            return 0.0
        
        # Base confidence on event count
        event_confidence = min(1.0, len(events) / (self.min_events * 2))
        
        # Adjust for event recency
        current_time = time.time()
        recent_events = [e for e in events if current_time - e.timestamp < 3600]  # Last hour
        recency_confidence = min(1.0, len(recent_events) / 5)
        
        # Combine confidences
        confidence = (event_confidence + recency_confidence) / 2
        
        return max(0.0, min(1.0, confidence))
    
    def _calculate_trend(self, events: List[TrustEvent]) -> float:
        """Calculate trust trend over time"""
        if len(events) < 2:
            return 0.0
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Calculate trend using linear regression
        timestamps = [e.timestamp for e in sorted_events]
        values = [e.value for e in sorted_events]
        
        n = len(timestamps)
        if n < 2:
            return 0.0
        
        # Calculate slope
        sum_x = sum(timestamps)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(timestamps, values))
        sum_x2 = sum(x * x for x in timestamps)
        
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Normalize trend to [-1, 1] range
        trend = max(-1.0, min(1.0, slope * 1000))  # Scale factor
        
        return trend
    
    def _update_sybil_detection(self, agent_id: str) -> None:
        """Update sybil detection for an agent"""
        if agent_id not in self.agent_relationships:
            return
        
        # Calculate sybil score based on various indicators
        sybil_score = 0.0
        
        # Indicator 1: Similar behavior patterns
        behavior_similarity = self._calculate_behavior_similarity(agent_id)
        sybil_score += behavior_similarity * 0.3
        
        # Indicator 2: Network connectivity patterns
        connectivity_score = self._calculate_connectivity_score(agent_id)
        sybil_score += connectivity_score * 0.2
        
        # Indicator 3: Event timing patterns
        timing_score = self._calculate_timing_score(agent_id)
        sybil_score += timing_score * 0.2
        
        # Indicator 4: Trust score patterns
        trust_pattern_score = self._calculate_trust_pattern_score(agent_id)
        sybil_score += trust_pattern_score * 0.3
        
        self.sybil_scores[agent_id] = sybil_score
    
    def _calculate_behavior_similarity(self, agent_id: str) -> float:
        """Calculate behavior similarity with other agents"""
        if agent_id not in self.trust_events:
            return 0.0
        
        agent_events = list(self.trust_events[agent_id])
        if len(agent_events) < 3:
            return 0.0
        
        # Compare with related agents
        similarities = []
        for related_agent in self.agent_relationships[agent_id]:
            if related_agent == agent_id:
                continue
            
            if related_agent not in self.trust_events:
                continue
            
            related_events = list(self.trust_events[related_agent])
            if len(related_events) < 3:
                continue
            
            # Calculate behavior similarity
            similarity = self._calculate_event_similarity(agent_events, related_events)
            similarities.append(similarity)
        
        if similarities:
            return statistics.mean(similarities)
        
        return 0.0
    
    def _calculate_event_similarity(self, events1: List[TrustEvent], events2: List[TrustEvent]) -> float:
        """Calculate similarity between two event sequences"""
        # Simple similarity based on event type distribution
        types1 = [e.event_type for e in events1]
        types2 = [e.event_type for e in events2]
        
        # Calculate Jaccard similarity
        set1 = set(types1)
        set2 = set(types2)
        
        if not set1 and not set2:
            return 1.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_connectivity_score(self, agent_id: str) -> float:
        """Calculate network connectivity score for sybil detection"""
        if agent_id not in self.agent_relationships:
            return 0.0
        
        connections = len(self.agent_relationships[agent_id])
        
        # High connectivity might indicate sybil
        if connections > 10:  # Threshold for high connectivity
            return min(1.0, (connections - 10) / 20)
        
        return 0.0
    
    def _calculate_timing_score(self, agent_id: str) -> float:
        """Calculate timing pattern score for sybil detection"""
        if agent_id not in self.trust_events:
            return 0.0
        
        events = list(self.trust_events[agent_id])
        if len(events) < 3:
            return 0.0
        
        # Check for suspicious timing patterns
        timestamps = [e.timestamp for e in events]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return 0.0
        
        # Check for very regular intervals (might indicate automation)
        if len(intervals) > 1:
            interval_variance = statistics.variance(intervals)
            if interval_variance < 1.0:  # Very low variance
                return 0.8
        
        return 0.0
    
    def _calculate_trust_pattern_score(self, agent_id: str) -> float:
        """Calculate trust pattern score for sybil detection"""
        if agent_id not in self.trust_scores:
            return 0.0
        
        trust_score = self.trust_scores[agent_id]
        
        # Check for suspicious trust patterns
        # Very high trust with low event count might indicate sybil
        if trust_score.overall_score > 0.9 and trust_score.event_count < 10:
            return 0.7
        
        # Very consistent trust scores might indicate manipulation
        if trust_score.confidence > 0.9 and abs(trust_score.trend) < 0.1:
            return 0.5
        
        return 0.0
    
    def _calculate_collusion_score(self, agent1: str, agent2: str) -> float:
        """Calculate collusion score between two agents"""
        if agent1 not in self.trust_events or agent2 not in self.trust_events:
            return 0.0
        
        events1 = list(self.trust_events[agent1])
        events2 = list(self.trust_events[agent2])
        
        if len(events1) < 3 or len(events2) < 3:
            return 0.0
        
        # Check for suspicious patterns
        collusion_score = 0.0
        
        # Pattern 1: Mutual high ratings
        mutual_ratings = 0
        for event1 in events1:
            if event1.source_agent == agent2 and event1.value > 0.8:
                mutual_ratings += 1
        
        if mutual_ratings > 3:
            collusion_score += 0.4
        
        # Pattern 2: Similar event timing
        timing_similarity = self._calculate_timing_similarity(events1, events2)
        collusion_score += timing_similarity * 0.3
        
        # Pattern 3: Coordinated behavior
        behavior_coordination = self._calculate_behavior_coordination(events1, events2)
        collusion_score += behavior_coordination * 0.3
        
        return min(1.0, collusion_score)
    
    def _calculate_timing_similarity(self, events1: List[TrustEvent], events2: List[TrustEvent]) -> float:
        """Calculate timing similarity between event sequences"""
        if not events1 or not events2:
            return 0.0
        
        timestamps1 = [e.timestamp for e in events1]
        timestamps2 = [e.timestamp for e in events2]
        
        # Find events within 5 minutes of each other
        close_events = 0
        for t1 in timestamps1:
            for t2 in timestamps2:
                if abs(t1 - t2) < 300:  # 5 minutes
                    close_events += 1
        
        max_possible = min(len(timestamps1), len(timestamps2))
        return close_events / max_possible if max_possible > 0 else 0.0
    
    def _calculate_behavior_coordination(self, events1: List[TrustEvent], events2: List[TrustEvent]) -> float:
        """Calculate behavior coordination between event sequences"""
        if not events1 or not events2:
            return 0.0
        
        # Check for coordinated event types
        types1 = [e.event_type for e in events1]
        types2 = [e.event_type for e in events2]
        
        # Count coordinated positive/negative events
        coordinated = 0
        for i, type1 in enumerate(types1):
            if i < len(types2):
                type2 = types2[i]
                # Check if events are coordinated (both positive or both negative)
                if (type1 in [TrustEventType.TASK_SUCCESS, TrustEventType.COOPERATION_POSITIVE] and
                    type2 in [TrustEventType.TASK_SUCCESS, TrustEventType.COOPERATION_POSITIVE]):
                    coordinated += 1
                elif (type1 in [TrustEventType.TASK_FAILURE, TrustEventType.COOPERATION_NEGATIVE] and
                      type2 in [TrustEventType.TASK_FAILURE, TrustEventType.COOPERATION_NEGATIVE]):
                    coordinated += 1
        
        max_possible = min(len(types1), len(types2))
        return coordinated / max_possible if max_possible > 0 else 0.0


# Example usage and testing
if __name__ == "__main__":
    # Initialize trust calculator
    trust_calc = TrustCalculator()
    
    # Create test events
    current_time = time.time()
    
    # Add positive events for agent1
    events = [
        TrustEvent("1", "agent1", TrustEventType.TASK_SUCCESS, current_time - 3600, 0.9),
        TrustEvent("2", "agent1", TrustEventType.COOPERATION_POSITIVE, current_time - 1800, 0.8),
        TrustEvent("3", "agent1", TrustEventType.HONESTY_POSITIVE, current_time - 900, 0.85),
    ]
    
    for event in events:
        trust_calc.add_trust_event(event)
    
    # Get trust score
    trust_score = trust_calc.get_trust_score("agent1")
    if trust_score:
        print(f"Agent1 trust score: {trust_score.overall_score:.3f}")
        print(f"Confidence: {trust_score.confidence:.3f}")
        print(f"Trend: {trust_score.trend:.3f}")
    
    # Get trust ranking
    ranking = trust_calc.get_trust_ranking()
    print(f"Trust ranking: {ranking}")
    
    # Detect sybil agents
    sybil_agents = trust_calc.detect_sybil_agents()
    print(f"Sybil agents: {sybil_agents}")
