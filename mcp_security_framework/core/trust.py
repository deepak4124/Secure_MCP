"""
Trust Calculation System for MCP Security Framework

This module provides simple trust calculation based on tool execution success rates.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class TrustEvent:
    """Trust event data structure"""
    event_id: str
    agent_id: str
    event_type: str
    timestamp: float
    value: float  # Event value (0.0 to 1.0)
    context: Dict[str, str] = field(default_factory=dict)
    source_agent: Optional[str] = None

@dataclass
class TrustScore:
    """Trust score data structure"""
    agent_id: str
    overall_score: float
    confidence: float
    last_updated: float
    event_count: int

class TrustCalculator:
    """
    Simple trust calculation system based on execution success rates.
    """
    
    def __init__(self, decay_factor: float = 0.95, min_events: int = 5):
        self.decay_factor = decay_factor
        self.min_events = min_events
        self.trust_events: Dict[str, List[TrustEvent]] = {}
        self.trust_scores: Dict[str, TrustScore] = {}
        
    def add_trust_event(self, event: TrustEvent) -> bool:
        if event.agent_id not in self.trust_events:
            self.trust_events[event.agent_id] = []
        
        self.trust_events[event.agent_id].append(event)
        self._calculate_trust_score(event.agent_id)
        return True
    
    def get_trust_score(self, agent_id: str) -> Optional[TrustScore]:
        return self.trust_scores.get(agent_id)
        
    def _calculate_trust_score(self, agent_id: str) -> None:
        events = self.trust_events.get(agent_id, [])
        if not events:
            return
            
        current_time = time.time()
        weighted_scores = []
        
        for event in events[-100:]:  # Look at last 100 events
            age_hours = (current_time - event.timestamp) / 3600
            decay = max(0.1, self.decay_factor ** age_hours)
            weighted_scores.append(event.value * decay)
            
        if weighted_scores:
            overall_score = sum(weighted_scores) / len(weighted_scores)
            confidence = min(1.0, len(events) / self.min_events)
            
            self.trust_scores[agent_id] = TrustScore(
                agent_id=agent_id,
                overall_score=max(0.0, min(1.0, overall_score)),
                confidence=confidence,
                last_updated=current_time,
                event_count=len(events)
            )
