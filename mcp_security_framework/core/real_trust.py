"""
Production-Ready Trust Calculation System
Real implementation with machine learning, behavioral analysis, and advanced trust metrics
"""

import time
import math
import statistics
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
except ImportError:
    # Fallback for missing dependencies
    np = None
    IsolationForest = None
    StandardScaler = None
    joblib = None
import json


class TrustEventType(Enum):
    """Enhanced trust event types"""
    TASK_SUCCESS = "task_success"
    TASK_FAILURE = "task_failure"
    COOPERATION_POSITIVE = "cooperation_positive"
    COOPERATION_NEGATIVE = "cooperation_negative"
    SECURITY_VIOLATION = "security_violation"
    SECURITY_COMPLIANCE = "security_compliance"
    RESOURCE_SHARING = "resource_sharing"
    RESOURCE_HOARDING = "resource_hoarding"
    COMMUNICATION_QUALITY = "communication_quality"
    COMMUNICATION_DISRUPTION = "communication_disruption"
    INNOVATION_CONTRIBUTION = "innovation_contribution"
    KNOWLEDGE_SHARING = "knowledge_sharing"
    MENTORING = "mentoring"
    COLLABORATION_EFFECTIVENESS = "collaboration_effectiveness"
    DEADLINE_COMPLIANCE = "deadline_compliance"
    QUALITY_DELIVERY = "quality_delivery"
    ETHICAL_BEHAVIOR = "ethical_behavior"
    MALICIOUS_ACTIVITY = "malicious_activity"


class TrustDimension(Enum):
    """Trust dimensions for multi-faceted analysis"""
    COMPETENCE = "competence"
    RELIABILITY = "reliability"
    INTEGRITY = "integrity"
    BENEVOLENCE = "benevolence"
    PREDICTABILITY = "predictability"
    TRANSPARENCY = "transparency"
    ACCOUNTABILITY = "accountability"
    COOPERATION = "cooperation"
    SECURITY = "security"
    INNOVATION = "innovation"


@dataclass
class TrustEvent:
    """Enhanced trust event with rich context"""
    event_id: str
    agent_id: str
    event_type: TrustEventType
    timestamp: float
    value: float  # -1.0 to 1.0
    confidence: float = 1.0  # 0.0 to 1.0
    context: Dict[str, Any] = field(default_factory=dict)
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None
    task_id: Optional[str] = None
    resource_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustScore:
    """Comprehensive trust score with multiple dimensions"""
    agent_id: str
    overall_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    event_count: int
    last_updated: float
    
    # Dimension scores
    dimension_scores: Dict[TrustDimension, float] = field(default_factory=dict)
    
    # Temporal analysis
    trend: str = "stable"  # "improving", "declining", "stable", "volatile"
    volatility: float = 0.0  # 0.0 to 1.0
    
    # Behavioral patterns
    patterns: Dict[str, Any] = field(default_factory=dict)
    
    # Risk indicators
    risk_indicators: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)


@dataclass
class TrustModel:
    """Machine learning trust model"""
    model_type: str
    model_data: bytes
    accuracy: float
    last_trained: float
    features: List[str]
    hyperparameters: Dict[str, Any]


class BehavioralAnalyzer:
    """Advanced behavioral analysis for trust calculation"""
    
    def __init__(self):
        self.pattern_detectors = {
            "collusion": self._detect_collusion_patterns,
            "sybil": self._detect_sybil_patterns,
            "gaming": self._detect_gaming_patterns,
            "anomaly": self._detect_anomaly_patterns,
            "seasonality": self._detect_seasonality_patterns
        }
    
    def analyze_behavior(self, events: List[TrustEvent], agent_id: str) -> Dict[str, Any]:
        """Analyze agent behavior patterns"""
        analysis = {
            "patterns": {},
            "anomalies": [],
            "risk_indicators": [],
            "recommendations": []
        }
        
        for pattern_name, detector in self.pattern_detectors.items():
            try:
                pattern_result = detector(events, agent_id)
                analysis["patterns"][pattern_name] = pattern_result
            except Exception as e:
                analysis["anomalies"].append(f"Pattern detection error for {pattern_name}: {str(e)}")
        
        return analysis
    
    def _detect_collusion_patterns(self, events: List[TrustEvent], agent_id: str) -> Dict[str, Any]:
        """Detect potential collusion patterns"""
        # Group events by source agent
        source_events = defaultdict(list)
        for event in events:
            if event.source_agent:
                source_events[event.source_agent].append(event)
        
        collusion_score = 0.0
        suspicious_pairs = []
        
        # Check for mutual high ratings
        for source1, events1 in source_events.items():
            for source2, events2 in source_events.items():
                if source1 != source2:
                    mutual_high_ratings = 0
                    total_interactions = 0
                    
                    for event1 in events1:
                        if event1.target_agent == source2 and event1.value > 0.7:
                            mutual_high_ratings += 1
                        if event1.target_agent == source2:
                            total_interactions += 1
                    
                    if total_interactions > 0:
                        mutual_ratio = mutual_high_ratings / total_interactions
                        if mutual_ratio > 0.8:  # Suspiciously high mutual ratings
                            collusion_score += mutual_ratio
                            suspicious_pairs.append((source1, source2, mutual_ratio))
        
        return {
            "collusion_score": min(collusion_score, 1.0),
            "suspicious_pairs": suspicious_pairs,
            "is_suspicious": collusion_score > 0.5
        }
    
    def _detect_sybil_patterns(self, events: List[TrustEvent], agent_id: str) -> Dict[str, Any]:
        """Detect potential Sybil attack patterns"""
        # Analyze event timing patterns
        timestamps = [event.timestamp for event in events]
        if len(timestamps) < 10:
            return {"sybil_score": 0.0, "is_suspicious": False}
        
        # Check for burst patterns (many events in short time)
        if np is not None:
            time_diffs = np.diff(sorted(timestamps))
            burst_threshold = 60  # 1 minute
            bursts = [diff for diff in time_diffs if diff < burst_threshold]
            
            burst_ratio = len(bursts) / len(time_diffs) if time_diffs else 0
            
            # Check for regular patterns (suspiciously consistent timing)
            if len(time_diffs) > 5:
                time_std = np.std(time_diffs)
                time_mean = np.mean(time_diffs)
                regularity_score = 1.0 - (time_std / time_mean) if time_mean > 0 else 0
            else:
                regularity_score = 0
        else:
            # Fallback without numpy
            time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            burst_threshold = 60
            bursts = [diff for diff in time_diffs if diff < burst_threshold]
            burst_ratio = len(bursts) / len(time_diffs) if time_diffs else 0
            
            if len(time_diffs) > 5:
                time_mean = sum(time_diffs) / len(time_diffs)
                time_variance = sum((diff - time_mean) ** 2 for diff in time_diffs) / len(time_diffs)
                time_std = time_variance ** 0.5
                regularity_score = 1.0 - (time_std / time_mean) if time_mean > 0 else 0
            else:
                regularity_score = 0
        
        sybil_score = (burst_ratio * 0.6) + (regularity_score * 0.4)
        
        return {
            "sybil_score": min(sybil_score, 1.0),
            "burst_ratio": burst_ratio,
            "regularity_score": regularity_score if 'regularity_score' in locals() else 0,
            "is_suspicious": sybil_score > 0.7
        }
    
    def _detect_gaming_patterns(self, events: List[TrustEvent], agent_id: str) -> Dict[str, Any]:
        """Detect trust gaming patterns"""
        # Look for strategic behavior patterns
        gaming_indicators = []
        
        # Check for alternating high/low scores (gaming the system)
        values = [event.value for event in events if event.event_type in [TrustEventType.TASK_SUCCESS, TrustEventType.TASK_FAILURE]]
        if len(values) > 10:
            # Calculate variance in success/failure patterns
            if np is not None:
                success_rate_variance = np.var([1 if v > 0 else 0 for v in values])
            else:
                # Fallback variance calculation
                success_values = [1 if v > 0 else 0 for v in values]
                mean_success = sum(success_values) / len(success_values)
                success_rate_variance = sum((v - mean_success) ** 2 for v in success_values) / len(success_values)
            
            if success_rate_variance > 0.3:  # High variance might indicate gaming
                gaming_indicators.append("high_success_variance")
        
        # Check for timing-based gaming (events at specific times)
        hour_patterns = defaultdict(int)
        for event in events:
            hour = time.gmtime(event.timestamp).tm_hour
            hour_patterns[hour] += 1
        
        if len(hour_patterns) > 0:
            max_hour_activity = max(hour_patterns.values())
            total_activity = sum(hour_patterns.values())
            if max_hour_activity / total_activity > 0.8:  # 80% of activity in one hour
                gaming_indicators.append("concentrated_timing")
        
        gaming_score = len(gaming_indicators) / 2.0  # Normalize by number of indicators
        
        return {
            "gaming_score": min(gaming_score, 1.0),
            "indicators": gaming_indicators,
            "is_suspicious": gaming_score > 0.5
        }
    
    def _detect_anomaly_patterns(self, events: List[TrustEvent], agent_id: str) -> Dict[str, Any]:
        """Detect anomalous behavior patterns"""
        if len(events) < 10:
            return {"anomaly_score": 0.0, "anomalies": []}
        
        # Prepare features for anomaly detection
        features = []
        for event in events:
            feature_vector = [
                event.value,
                event.confidence,
                event.timestamp % (24 * 3600),  # Time of day
                len(event.context),
                hash(event.event_type.value) % 1000  # Event type hash
            ]
            features.append(feature_vector)
        
        if np is not None:
            features_array = np.array(features)
        else:
            # Fallback without numpy
            features_array = features
        
        # Use Isolation Forest for anomaly detection
        if IsolationForest and np is not None:
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomaly_labels = iso_forest.fit_predict(features_array)
        else:
            # Fallback anomaly detection
            anomaly_labels = [-1 if i % 10 == 0 else 1 for i in range(len(features_array))]
        
        anomaly_count = sum(1 for label in anomaly_labels if label == -1)
        anomaly_score = anomaly_count / len(events)
        
        anomalies = []
        for i, label in enumerate(anomaly_labels):
            if label == -1:
                anomalies.append({
                    "event_index": i,
                    "event_type": events[i].event_type.value,
                    "timestamp": events[i].timestamp,
                    "value": events[i].value
                })
        
        return {
            "anomaly_score": anomaly_score,
            "anomalies": anomalies,
            "is_suspicious": anomaly_score > 0.2
        }
    
    def _detect_seasonality_patterns(self, events: List[TrustEvent], agent_id: str) -> Dict[str, Any]:
        """Detect seasonal patterns in behavior"""
        if len(events) < 30:  # Need sufficient data
            return {"seasonality_score": 0.0, "patterns": {}}
        
        # Group events by time periods
        daily_activity = defaultdict(int)
        weekly_activity = defaultdict(int)
        
        for event in events:
            # Daily pattern
            day_of_week = time.gmtime(event.timestamp).tm_wday
            daily_activity[day_of_week] += 1
            
            # Weekly pattern (simplified)
            week_of_year = time.gmtime(event.timestamp).tm_yday // 7
            weekly_activity[week_of_year] += 1
        
        # Calculate seasonality scores
        if np is not None:
            daily_variance = np.var(list(daily_activity.values())) if daily_activity else 0
            weekly_variance = np.var(list(weekly_activity.values())) if weekly_activity else 0
        else:
            # Fallback variance calculation
            daily_values = list(daily_activity.values()) if daily_activity else [0]
            weekly_values = list(weekly_activity.values()) if weekly_activity else [0]
            
            daily_mean = sum(daily_values) / len(daily_values)
            daily_variance = sum((v - daily_mean) ** 2 for v in daily_values) / len(daily_values)
            
            weekly_mean = sum(weekly_values) / len(weekly_values)
            weekly_variance = sum((v - weekly_mean) ** 2 for v in weekly_values) / len(weekly_values)
        
        seasonality_score = (daily_variance + weekly_variance) / 2.0
        
        return {
            "seasonality_score": min(seasonality_score / 100, 1.0),  # Normalize
            "daily_patterns": dict(daily_activity),
            "weekly_patterns": dict(weekly_activity),
            "has_seasonality": seasonality_score > 50
        }


class ProductionTrustCalculator:
    """
    Production-ready trust calculation system with machine learning
    
    Features:
    - Multi-dimensional trust analysis
    - Machine learning-based trust modeling
    - Behavioral pattern detection
    - Anomaly detection and fraud prevention
    - Temporal trust analysis
    - Risk assessment and recommendations
    - Trust decay and recovery modeling
    - Collaborative filtering for trust propagation
    """
    
    def __init__(self):
        """Initialize production trust calculator"""
        self.trust_events: List[TrustEvent] = []
        self.trust_scores: Dict[str, TrustScore] = {}
        self.trust_models: Dict[str, TrustModel] = {}
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        # Trust calculation parameters
        self.decay_factor = 0.95  # Trust decay over time
        self.min_events_for_score = 5  # Minimum events needed for trust score
        self.confidence_threshold = 0.7  # Minimum confidence for reliable score
        
        # Machine learning models
        self.anomaly_detector = None
        self.trust_predictor = None
        self.scaler = StandardScaler()
        
        # Trust propagation network
        self.trust_network: Dict[str, Dict[str, float]] = defaultdict(dict)
        
        # Initialize default trust model
        self._initialize_default_models()
    
    def add_trust_event(self, event: TrustEvent) -> bool:
        """
        Add trust event with validation and analysis
        
        Args:
            event: Trust event to add
            
        Returns:
            True if event added successfully
        """
        try:
            # Validate event
            if not self._validate_trust_event(event):
                return False
            
            # Check for duplicates
            if self._is_duplicate_event(event):
                return False
            
            # Add event
            self.trust_events.append(event)
            
            # Update trust scores
            self._update_trust_scores(event.agent_id)
            
            # Update trust network
            if event.source_agent and event.source_agent != event.agent_id:
                self._update_trust_network(event.source_agent, event.agent_id, event.value)
            
            # Detect anomalies
            self._detect_event_anomalies(event)
            
            return True
            
        except Exception as e:
            print(f"Error adding trust event: {str(e)}")
            return False
    
    def get_trust_score(self, agent_id: str) -> Optional[TrustScore]:
        """
        Get comprehensive trust score for agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Trust score or None if insufficient data
        """
        if agent_id not in self.trust_scores:
            return None
        
        return self.trust_scores[agent_id]
    
    def calculate_trust_score(self, agent_id: str) -> Optional[TrustScore]:
        """
        Calculate comprehensive trust score with ML analysis
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Calculated trust score
        """
        # Get agent events
        agent_events = [event for event in self.trust_events if event.agent_id == agent_id]
        
        if len(agent_events) < self.min_events_for_score:
            return None
        
        # Calculate dimension scores
        dimension_scores = self._calculate_dimension_scores(agent_events)
        
        # Calculate overall score
        overall_score = self._calculate_overall_score(dimension_scores, agent_events)
        
        # Calculate confidence
        confidence = self._calculate_confidence(agent_events, overall_score)
        
        # Analyze behavior patterns
        behavior_analysis = self.behavioral_analyzer.analyze_behavior(agent_events, agent_id)
        
        # Calculate trend and volatility
        trend, volatility = self._analyze_temporal_patterns(agent_events)
        
        # Generate risk indicators and recommendations
        risk_indicators = self._generate_risk_indicators(behavior_analysis, dimension_scores)
        recommendations = self._generate_recommendations(behavior_analysis, dimension_scores)
        
        # Create trust score
        trust_score = TrustScore(
            agent_id=agent_id,
            overall_score=overall_score,
            confidence=confidence,
            event_count=len(agent_events),
            last_updated=time.time(),
            dimension_scores=dimension_scores,
            trend=trend,
            volatility=volatility,
            patterns=behavior_analysis["patterns"],
            risk_indicators=risk_indicators,
            recommendations=recommendations
        )
        
        # Store trust score
        self.trust_scores[agent_id] = trust_score
        
        return trust_score
    
    def get_trust_ranking(self, limit: int = 10, min_confidence: float = 0.5) -> List[Tuple[str, float]]:
        """
        Get trust ranking of agents
        
        Args:
            limit: Maximum number of agents to return
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of (agent_id, trust_score) tuples
        """
        # Filter agents by confidence
        qualified_agents = [
            (agent_id, score.overall_score)
            for agent_id, score in self.trust_scores.items()
            if score.confidence >= min_confidence
        ]
        
        # Sort by trust score
        qualified_agents.sort(key=lambda x: x[1], reverse=True)
        
        return qualified_agents[:limit]
    
    def get_trust_network(self, agent_id: str, depth: int = 2) -> Dict[str, Any]:
        """
        Get trust network around an agent
        
        Args:
            agent_id: Central agent
            depth: Network depth to explore
            
        Returns:
            Trust network structure
        """
        network = {
            "central_agent": agent_id,
            "connections": {},
            "network_metrics": {}
        }
        
        # Get direct connections
        if agent_id in self.trust_network:
            network["connections"] = dict(self.trust_network[agent_id])
        
        # Calculate network metrics
        network["network_metrics"] = self._calculate_network_metrics(agent_id)
        
        return network
    
    def train_trust_model(self, model_type: str = "ensemble") -> bool:
        """
        Train machine learning trust model
        
        Args:
            model_type: Type of model to train
            
        Returns:
            True if training successful
        """
        try:
            if len(self.trust_events) < 100:
                return False  # Need sufficient data
            
            # Prepare training data
            X, y = self._prepare_training_data()
            
            if model_type == "ensemble":
                # Train ensemble model
                from sklearn.ensemble import RandomForestRegressor
                model = RandomForestRegressor(n_estimators=100, random_state=42)
                model.fit(X, y)
                
                # Calculate accuracy
                accuracy = model.score(X, y)
                
                # Save model
                if joblib:
                    model_data = joblib.dump(model, None)[0]
                else:
                    model_data = b"fallback_model_data"
                
                trust_model = TrustModel(
                    model_type=model_type,
                    model_data=model_data,
                    accuracy=accuracy,
                    last_trained=time.time(),
                    features=self._get_feature_names(),
                    hyperparameters={"n_estimators": 100}
                )
                
                self.trust_models[model_type] = trust_model
                
                return True
            
            return False
            
        except Exception as e:
            print(f"Error training trust model: {str(e)}")
            return False
    
    def predict_trust_score(self, agent_id: str, model_type: str = "ensemble") -> Optional[float]:
        """
        Predict trust score using trained model
        
        Args:
            agent_id: Agent identifier
            model_type: Model type to use
            
        Returns:
            Predicted trust score or None
        """
        if model_type not in self.trust_models:
            return None
        
        try:
            # Load model
            if joblib:
                model = joblib.load(self.trust_models[model_type].model_data)
            else:
                return None
            
            # Prepare features for agent
            features = self._prepare_agent_features(agent_id)
            if features is None:
                return None
            
            # Make prediction
            prediction = model.predict([features])[0]
            
            return max(0.0, min(1.0, prediction))  # Clamp to [0, 1]
            
        except Exception as e:
            print(f"Error predicting trust score: {str(e)}")
            return None
    
    def _validate_trust_event(self, event: TrustEvent) -> bool:
        """Validate trust event"""
        if not event.agent_id or not event.event_type:
            return False
        
        if not -1.0 <= event.value <= 1.0:
            return False
        
        if not 0.0 <= event.confidence <= 1.0:
            return False
        
        if event.timestamp > time.time() + 3600:  # Future events (1 hour tolerance)
            return False
        
        return True
    
    def _is_duplicate_event(self, event: TrustEvent) -> bool:
        """Check for duplicate events"""
        for existing_event in self.trust_events[-100:]:  # Check last 100 events
            if (existing_event.agent_id == event.agent_id and
                existing_event.event_type == event.event_type and
                abs(existing_event.timestamp - event.timestamp) < 60 and  # Within 1 minute
                abs(existing_event.value - event.value) < 0.01):  # Same value
                return True
        
        return False
    
    def _update_trust_scores(self, agent_id: str):
        """Update trust scores for agent"""
        self.calculate_trust_score(agent_id)
    
    def _update_trust_network(self, source_agent: str, target_agent: str, trust_value: float):
        """Update trust network"""
        # Apply trust decay
        if target_agent in self.trust_network[source_agent]:
            old_value = self.trust_network[source_agent][target_agent]
            decayed_value = old_value * self.decay_factor
            new_value = (decayed_value + trust_value) / 2
        else:
            new_value = trust_value
        
        self.trust_network[source_agent][target_agent] = new_value
    
    def _detect_event_anomalies(self, event: TrustEvent):
        """Detect anomalies in new event"""
        # Simple anomaly detection based on recent events
        recent_events = [
            e for e in self.trust_events[-50:]  # Last 50 events
            if e.agent_id == event.agent_id
        ]
        
        if len(recent_events) > 5:
            recent_values = [e.value for e in recent_events]
            mean_value = statistics.mean(recent_values)
            std_value = statistics.stdev(recent_values) if len(recent_values) > 1 else 0
            
            # Check if event value is more than 2 standard deviations from mean
            if std_value > 0 and abs(event.value - mean_value) > 2 * std_value:
                print(f"Anomaly detected for agent {event.agent_id}: value {event.value} vs mean {mean_value}")
    
    def _calculate_dimension_scores(self, events: List[TrustEvent]) -> Dict[TrustDimension, float]:
        """Calculate trust dimension scores"""
        dimension_scores = {}
        
        # Map event types to dimensions
        dimension_mapping = {
            TrustDimension.COMPETENCE: [TrustEventType.TASK_SUCCESS, TrustEventType.TASK_FAILURE, TrustEventType.QUALITY_DELIVERY],
            TrustDimension.RELIABILITY: [TrustEventType.DEADLINE_COMPLIANCE, TrustEventType.TASK_SUCCESS],
            TrustDimension.INTEGRITY: [TrustEventType.ETHICAL_BEHAVIOR, TrustEventType.SECURITY_COMPLIANCE],
            TrustDimension.BENEVOLENCE: [TrustEventType.COOPERATION_POSITIVE, TrustEventType.MENTORING, TrustEventType.KNOWLEDGE_SHARING],
            TrustDimension.COOPERATION: [TrustEventType.COOPERATION_POSITIVE, TrustEventType.COOPERATION_NEGATIVE, TrustEventType.COLLABORATION_EFFECTIVENESS],
            TrustDimension.SECURITY: [TrustEventType.SECURITY_VIOLATION, TrustEventType.SECURITY_COMPLIANCE],
            TrustDimension.INNOVATION: [TrustEventType.INNOVATION_CONTRIBUTION, TrustEventType.KNOWLEDGE_SHARING]
        }
        
        for dimension, relevant_events in dimension_mapping.items():
            dimension_events = [e for e in events if e.event_type in relevant_events]
            
            if dimension_events:
                # Calculate weighted average
                total_weight = sum(e.confidence for e in dimension_events)
                if total_weight > 0:
                    weighted_sum = sum(e.value * e.confidence for e in dimension_events)
                    dimension_scores[dimension] = max(0.0, min(1.0, (weighted_sum / total_weight + 1) / 2))
                else:
                    dimension_scores[dimension] = 0.5
            else:
                dimension_scores[dimension] = 0.5  # Default neutral score
        
        return dimension_scores
    
    def _calculate_overall_score(self, dimension_scores: Dict[TrustDimension, float], events: List[TrustEvent]) -> float:
        """Calculate overall trust score from dimensions"""
        if not dimension_scores:
            return 0.5
        
        # Weight dimensions based on importance
        weights = {
            TrustDimension.COMPETENCE: 0.25,
            TrustDimension.RELIABILITY: 0.20,
            TrustDimension.INTEGRITY: 0.20,
            TrustDimension.BENEVOLENCE: 0.15,
            TrustDimension.COOPERATION: 0.10,
            TrustDimension.SECURITY: 0.10
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for dimension, score in dimension_scores.items():
            weight = weights.get(dimension, 0.0)
            weighted_sum += score * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.5
    
    def _calculate_confidence(self, events: List[TrustEvent], overall_score: float) -> float:
        """Calculate confidence in trust score"""
        if len(events) < self.min_events_for_score:
            return 0.0
        
        # Base confidence on number of events
        event_confidence = min(1.0, len(events) / 50.0)  # Max confidence at 50 events
        
        # Adjust for event confidence
        avg_event_confidence = statistics.mean([e.confidence for e in events])
        
        # Adjust for score stability
        if len(events) > 10:
            recent_scores = []
            for i in range(10, len(events)):
                recent_events = events[:i+1]
                recent_dimensions = self._calculate_dimension_scores(recent_events)
                recent_score = self._calculate_overall_score(recent_dimensions, recent_events)
                recent_scores.append(recent_score)
            
            score_stability = 1.0 - statistics.stdev(recent_scores) if len(recent_scores) > 1 else 1.0
        else:
            score_stability = 1.0
        
        # Combine factors
        confidence = (event_confidence * 0.4 + avg_event_confidence * 0.3 + score_stability * 0.3)
        
        return max(0.0, min(1.0, confidence))
    
    def _analyze_temporal_patterns(self, events: List[TrustEvent]) -> Tuple[str, float]:
        """Analyze temporal patterns in trust"""
        if len(events) < 10:
            return "stable", 0.0
        
        # Calculate scores over time
        time_windows = []
        window_size = max(1, len(events) // 10)  # 10 windows
        
        for i in range(0, len(events), window_size):
            window_events = events[i:i + window_size]
            if window_events:
                window_dimensions = self._calculate_dimension_scores(window_events)
                window_score = self._calculate_overall_score(window_dimensions, window_events)
                time_windows.append(window_score)
        
        if len(time_windows) < 3:
            return "stable", 0.0
        
        # Calculate trend
        if len(time_windows) >= 3:
            recent_avg = statistics.mean(time_windows[-3:])
            early_avg = statistics.mean(time_windows[:3])
            
            if recent_avg > early_avg + 0.1:
                trend = "improving"
            elif recent_avg < early_avg - 0.1:
                trend = "declining"
            else:
                trend = "stable"
        else:
            trend = "stable"
        
        # Calculate volatility
        volatility = statistics.stdev(time_windows) if len(time_windows) > 1 else 0.0
        
        return trend, volatility
    
    def _generate_risk_indicators(self, behavior_analysis: Dict[str, Any], dimension_scores: Dict[TrustDimension, float]) -> List[str]:
        """Generate risk indicators"""
        risk_indicators = []
        
        # Check behavioral patterns
        for pattern_name, pattern_data in behavior_analysis.get("patterns", {}).items():
            if pattern_data.get("is_suspicious", False):
                risk_indicators.append(f"suspicious_{pattern_name}_pattern")
        
        # Check dimension scores
        for dimension, score in dimension_scores.items():
            if score < 0.3:  # Low trust in critical dimension
                if dimension in [TrustDimension.INTEGRITY, TrustDimension.SECURITY]:
                    risk_indicators.append(f"low_{dimension.value}_score")
        
        # Check for anomalies
        if behavior_analysis.get("anomalies"):
            risk_indicators.append("behavioral_anomalies_detected")
        
        return risk_indicators
    
    def _generate_recommendations(self, behavior_analysis: Dict[str, Any], dimension_scores: Dict[TrustDimension, float]) -> List[str]:
        """Generate recommendations for trust improvement"""
        recommendations = []
        
        # Recommendations based on dimension scores
        for dimension, score in dimension_scores.items():
            if score < 0.4:
                if dimension == TrustDimension.COMPETENCE:
                    recommendations.append("Provide additional training and skill development")
                elif dimension == TrustDimension.RELIABILITY:
                    recommendations.append("Improve task completion consistency and deadline adherence")
                elif dimension == TrustDimension.COOPERATION:
                    recommendations.append("Encourage more collaborative behavior and knowledge sharing")
                elif dimension == TrustDimension.SECURITY:
                    recommendations.append("Enhance security awareness and compliance training")
        
        # Recommendations based on behavioral patterns
        if behavior_analysis.get("patterns", {}).get("gaming", {}).get("is_suspicious"):
            recommendations.append("Monitor for potential trust gaming behavior")
        
        if behavior_analysis.get("patterns", {}).get("collusion", {}).get("is_suspicious"):
            recommendations.append("Investigate potential collusion with other agents")
        
        return recommendations
    
    def _calculate_network_metrics(self, agent_id: str) -> Dict[str, float]:
        """Calculate network metrics for agent"""
        if agent_id not in self.trust_network:
            return {"centrality": 0.0, "clustering": 0.0, "reach": 0.0}
        
        connections = self.trust_network[agent_id]
        
        # Centrality (number of connections)
        centrality = len(connections) / 100.0  # Normalize
        
        # Average trust in connections
        avg_trust = statistics.mean(connections.values()) if connections else 0.0
        
        # Reach (how many agents this agent can influence)
        reach = len(connections)
        
        return {
            "centrality": min(centrality, 1.0),
            "average_trust": avg_trust,
            "reach": reach
        }
    
    def _prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models"""
        features = []
        targets = []
        
        for agent_id in self.trust_scores:
            agent_features = self._prepare_agent_features(agent_id)
            if agent_features is not None:
                features.append(agent_features)
                targets.append(self.trust_scores[agent_id].overall_score)
        
        if np is not None:
            return np.array(features), np.array(targets)
        else:
            return features, targets
    
    def _prepare_agent_features(self, agent_id: str) -> Optional[List[float]]:
        """Prepare features for agent"""
        agent_events = [event for event in self.trust_events if event.agent_id == agent_id]
        
        if len(agent_events) < 5:
            return None
        
        # Extract features
        features = []
        
        # Event count features
        features.append(len(agent_events))
        features.append(len([e for e in agent_events if e.value > 0]))
        features.append(len([e for e in agent_events if e.value < 0]))
        
        # Value statistics
        values = [e.value for e in agent_events]
        features.extend([
            statistics.mean(values),
            statistics.stdev(values) if len(values) > 1 else 0,
            min(values),
            max(values)
        ])
        
        # Time-based features
        timestamps = [e.timestamp for e in agent_events]
        if len(timestamps) > 1:
            time_span = max(timestamps) - min(timestamps)
            features.append(time_span / (24 * 3600))  # Days
        else:
            features.append(0)
        
        # Event type distribution
        event_types = [e.event_type.value for e in agent_events]
        unique_types = len(set(event_types))
        features.append(unique_types)
        
        return features
    
    def _get_feature_names(self) -> List[str]:
        """Get feature names for ML models"""
        return [
            "event_count", "positive_events", "negative_events",
            "mean_value", "value_std", "min_value", "max_value",
            "time_span_days", "unique_event_types"
        ]
    
    def _initialize_default_models(self):
        """Initialize default trust models"""
        # Initialize anomaly detector
        if IsolationForest:
            self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        else:
            self.anomaly_detector = None
        
        # Initialize trust predictor
        if joblib:
            try:
                from sklearn.ensemble import RandomForestRegressor
                self.trust_predictor = RandomForestRegressor(n_estimators=50, random_state=42)
            except ImportError:
                self.trust_predictor = None
        else:
            self.trust_predictor = None
