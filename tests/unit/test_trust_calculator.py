"""
Unit tests for Trust Calculator
"""

import pytest
import time
from unittest.mock import Mock, patch
from mcp_security_framework.core.trust import (
    TrustCalculator, TrustEvent, TrustEventType, TrustDimension, TrustScore
)


class TestTrustCalculator:
    """Test cases for TrustCalculator"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.trust_calculator = TrustCalculator()
        self.test_agent_id = "test_agent_001"
        self.test_event_id = "event_001"
    
    def test_add_trust_event_success(self):
        """Test successful trust event addition"""
        event = TrustEvent(
            event_id=self.test_event_id,
            agent_id=self.test_agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time(),
            value=0.8
        )
        
        result = self.trust_calculator.add_trust_event(event)
        
        assert result is True
        assert self.test_agent_id in self.trust_calculator.trust_events
        assert len(self.trust_calculator.trust_events[self.test_agent_id]) == 1
    
    def test_add_trust_event_invalid_value(self):
        """Test adding trust event with invalid value"""
        event = TrustEvent(
            event_id=self.test_event_id,
            agent_id=self.test_agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time(),
            value=1.5  # Invalid value > 1.0
        )
        
        result = self.trust_calculator.add_trust_event(event)
        
        assert result is False
    
    def test_add_trust_event_future_timestamp(self):
        """Test adding trust event with future timestamp"""
        event = TrustEvent(
            event_id=self.test_event_id,
            agent_id=self.test_agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time() + 3600,  # Future timestamp
            value=0.8
        )
        
        result = self.trust_calculator.add_trust_event(event)
        
        assert result is False
    
    def test_get_trust_score_sufficient_events(self):
        """Test getting trust score with sufficient events"""
        # Add multiple events to meet minimum requirement
        for i in range(6):  # More than min_events (5)
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 60,  # Spread over time
                value=0.8
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(self.test_agent_id)
        
        assert trust_score is not None
        assert isinstance(trust_score, TrustScore)
        assert trust_score.agent_id == self.test_agent_id
        assert 0.0 <= trust_score.overall_score <= 1.0
        assert trust_score.confidence > 0.0
    
    def test_get_trust_score_insufficient_events(self):
        """Test getting trust score with insufficient events"""
        # Add only 2 events (less than min_events)
        for i in range(2):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 60,
                value=0.8
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(self.test_agent_id)
        
        assert trust_score is None
    
    def test_get_trust_ranking(self):
        """Test getting trust ranking"""
        # Add events for multiple agents
        agents = ["agent_1", "agent_2", "agent_3"]
        for agent_id in agents:
            for i in range(6):
                event = TrustEvent(
                    event_id=f"event_{agent_id}_{i}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - i * 60,
                    value=0.8 if agent_id == "agent_1" else 0.6  # agent_1 has higher score
                )
                self.trust_calculator.add_trust_event(event)
        
        ranking = self.trust_calculator.get_trust_ranking()
        
        assert len(ranking) == 3
        assert ranking[0][0] == "agent_1"  # Highest trust score
        assert ranking[0][1] >= ranking[1][1]  # Sorted by score
    
    def test_detect_sybil_agents(self):
        """Test sybil agent detection"""
        # Add events that would trigger sybil detection
        for i in range(10):  # High connectivity
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 10,
                value=0.9,  # Very high trust
                source_agent=f"related_agent_{i}"
            )
            self.trust_calculator.add_trust_event(event)
        
        sybil_agents = self.trust_calculator.detect_sybil_agents()
        
        # Should detect potential sybil based on high connectivity
        assert isinstance(sybil_agents, list)
    
    def test_detect_collusion(self):
        """Test collusion detection"""
        # Add events that would trigger collusion detection
        for i in range(5):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 60,
                value=0.9,  # High value
                source_agent="colluding_agent"
            )
            self.trust_calculator.add_trust_event(event)
        
        colluding_agents = self.trust_calculator.detect_collusion(self.test_agent_id)
        
        assert isinstance(colluding_agents, list)
    
    def test_predict_trust_trend(self):
        """Test trust trend prediction"""
        # Add events with improving trend
        for i in range(10):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - (10 - i) * 60,  # Recent events better
                value=0.5 + (i * 0.05)  # Improving trend
            )
            self.trust_calculator.add_trust_event(event)
        
        trend = self.trust_calculator.predict_trust_trend(self.test_agent_id)
        
        assert isinstance(trend, float)
        assert -1.0 <= trend <= 1.0
    
    def test_predict_trust_trend_insufficient_data(self):
        """Test trust trend prediction with insufficient data"""
        # Add only 2 events
        for i in range(2):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 60,
                value=0.8
            )
            self.trust_calculator.add_trust_event(event)
        
        trend = self.trust_calculator.predict_trust_trend(self.test_agent_id)
        
        assert trend == 0.0
    
    def test_trust_score_calculation_dimensions(self):
        """Test trust score calculation across dimensions"""
        # Add events for different dimensions
        events = [
            (TrustEventType.TASK_SUCCESS, 0.8),  # Competence
            (TrustEventType.TASK_SUCCESS, 0.7),  # Reliability
            (TrustEventType.HONESTY_POSITIVE, 0.9),  # Honesty
            (TrustEventType.COOPERATION_POSITIVE, 0.6),  # Cooperation
            (TrustEventType.SECURITY_VIOLATION, -0.5)  # Security (negative)
        ]
        
        for i, (event_type, value) in enumerate(events):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=event_type,
                timestamp=time.time() - i * 60,
                value=value
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(self.test_agent_id)
        
        assert trust_score is not None
        assert len(trust_score.dimension_scores) == 5  # All dimensions
        for dimension in TrustDimension:
            assert dimension in trust_score.dimension_scores
            assert 0.0 <= trust_score.dimension_scores[dimension] <= 1.0
    
    def test_trust_decay_over_time(self):
        """Test trust decay over time"""
        # Add old event
        old_event = TrustEvent(
            event_id="old_event",
            agent_id=self.test_agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time() - 7200,  # 2 hours ago
            value=0.9
        )
        self.trust_calculator.add_trust_event(old_event)
        
        # Add recent event
        recent_event = TrustEvent(
            event_id="recent_event",
            agent_id=self.test_agent_id,
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=time.time() - 300,  # 5 minutes ago
            value=0.7
        )
        self.trust_calculator.add_trust_event(recent_event)
        
        trust_score = self.trust_calculator.get_trust_score(self.test_agent_id)
        
        # Recent event should have more influence
        assert trust_score is not None
        # The overall score should be closer to the recent event value
    
    def test_confidence_calculation(self):
        """Test confidence calculation based on event count and recency"""
        # Add many recent events
        for i in range(15):  # More than min_events * 2
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - i * 30,  # All within last hour
                value=0.8
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(self.test_agent_id)
        
        assert trust_score is not None
        assert trust_score.confidence > 0.8  # High confidence due to many recent events
    
    def test_trust_trend_calculation(self):
        """Test trust trend calculation"""
        # Add events with clear trend
        for i in range(10):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=self.test_agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - (10 - i) * 60,
                value=0.5 + (i * 0.04)  # Clear upward trend
            )
            self.trust_calculator.add_trust_event(event)
        
        trust_score = self.trust_calculator.get_trust_score(self.test_agent_id)
        
        assert trust_score is not None
        assert trust_score.trend > 0  # Positive trend
    
    def test_ml_trust_calculation(self):
        """Test ML-based trust calculation"""
        # Test the ML trust calculation method
        context = {"operation": "test_operation", "resource": "test_resource"}
        
        # Add some interactions
        self.trust_calculator.add_interaction(
            self.test_agent_id, "normal interaction"
        )
        self.trust_calculator.add_interaction(
            self.test_agent_id, "helpful response"
        )
        
        # Test ML trust calculation
        ml_score = self.trust_calculator.calculate_trust_score_with_ml(
            self.test_agent_id, context
        )
        
        assert isinstance(ml_score, float)
        assert 0.0 <= ml_score <= 1.0
    
    def test_interaction_storage(self):
        """Test interaction storage for ML models"""
        # Add multiple interactions
        interactions = [
            "first interaction",
            "second interaction",
            "third interaction"
        ]
        
        for interaction in interactions:
            self.trust_calculator.add_interaction(self.test_agent_id, interaction)
        
        # Check interactions are stored
        assert self.test_agent_id in self.trust_calculator.agent_interactions
        stored_interactions = self.trust_calculator.agent_interactions[self.test_agent_id]
        assert len(stored_interactions) == 3
        assert stored_interactions == interactions
    
    def test_interaction_limit(self):
        """Test interaction storage limit"""
        # Add more than 100 interactions
        for i in range(105):
            self.trust_calculator.add_interaction(
                self.test_agent_id, f"interaction_{i}"
            )
        
        # Should only keep last 100
        stored_interactions = self.trust_calculator.agent_interactions[self.test_agent_id]
        assert len(stored_interactions) == 100
        assert stored_interactions[0] == "interaction_5"  # First 5 should be removed
        assert stored_interactions[-1] == "interaction_104"  # Last should be kept


