"""
Advanced Behavioral Analysis System for MCP Security Framework

This module provides sophisticated behavioral analysis capabilities including
deceptive behavior detection, behavioral evolution prediction, and multi-modal
anomaly detection inspired by behavioral security research.
"""

import time
import math
import statistics
from typing import Dict, List, Optional, Tuple, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from collections import defaultdict, deque
import json
import networkx as nx
from scipy import stats

from pydantic import BaseModel, Field


class BehaviorType(Enum):
    """Behavior type enumeration"""
    NORMAL = "normal"
    ANOMALOUS = "anomalous"
    DECEPTIVE = "deceptive"
    COLLUSIVE = "collusive"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"


class AnalysisMethod(Enum):
    """Analysis method enumeration"""
    SEQUENCE_ANALYSIS = "sequence_analysis"
    GRAPH_ANALYSIS = "graph_analysis"
    TEMPORAL_ANALYSIS = "temporal_analysis"
    ENSEMBLE_DETECTION = "ensemble_detection"
    PATTERN_MATCHING = "pattern_matching"
    STATISTICAL_ANALYSIS = "statistical_analysis"


class DeceptionIndicator(Enum):
    """Deception indicator enumeration"""
    INCONSISTENT_BEHAVIOR = "inconsistent_behavior"
    UNUSUAL_TIMING = "unusual_timing"
    COORDINATED_ACTIONS = "coordinated_actions"
    HIDDEN_PATTERNS = "hidden_patterns"
    EVASIVE_BEHAVIOR = "evasive_behavior"
    MANIPULATIVE_ACTIONS = "manipulative_actions"


@dataclass
class BehaviorEvent:
    """Behavior event data structure"""
    event_id: str
    agent_id: str
    event_type: str
    timestamp: float
    data: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorSequence:
    """Behavior sequence data structure"""
    agent_id: str
    events: List[BehaviorEvent]
    start_time: float
    end_time: float
    sequence_type: str
    features: Dict[str, float] = field(default_factory=dict)


@dataclass
class DeceptionAssessment:
    """Deception assessment result"""
    agent_id: str
    deception_score: float
    deception_indicators: List[DeceptionIndicator]
    confidence: float
    evidence: List[str]
    risk_level: str
    recommendations: List[str]
    assessment_timestamp: float


@dataclass
class BehaviorPrediction:
    """Behavior prediction result"""
    agent_id: str
    predicted_behavior: BehaviorType
    confidence: float
    time_horizon: int
    prediction_factors: Dict[str, float]
    risk_assessment: str
    mitigation_strategies: List[str]
    prediction_timestamp: float


class SequenceAnalysis:
    """Sequence-based behavioral analysis"""
    
    def __init__(self):
        self.sequence_patterns = defaultdict(list)
        self.anomaly_threshold = 0.7
    
    def analyze_patterns(self, behavior_sequence: BehaviorSequence) -> Dict[str, Any]:
        """Analyze behavioral patterns in a sequence"""
        events = behavior_sequence.events
        if len(events) < 3:
            return {'pattern_type': 'insufficient_data', 'anomaly_score': 0.0}
        
        # Extract sequence features
        features = self._extract_sequence_features(events)
        
        # Detect patterns
        patterns = self._detect_sequence_patterns(features)
        
        # Calculate anomaly score
        anomaly_score = self._calculate_sequence_anomaly(features, patterns)
        
        return {
            'pattern_type': patterns.get('type', 'unknown'),
            'anomaly_score': anomaly_score,
            'features': features,
            'patterns': patterns
        }
    
    def _extract_sequence_features(self, events: List[BehaviorEvent]) -> Dict[str, float]:
        """Extract features from event sequence"""
        if not events:
            return {}
        
        # Time-based features
        timestamps = [event.timestamp for event in events]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        features = {
            'sequence_length': len(events),
            'duration': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
            'avg_interval': statistics.mean(intervals) if intervals else 0,
            'interval_variance': statistics.variance(intervals) if len(intervals) > 1 else 0,
            'interval_consistency': 1.0 - (statistics.variance(intervals) / (statistics.mean(intervals) + 1e-6)) if intervals else 0
        }
        
        # Event type features
        event_types = [event.event_type for event in events]
        unique_types = set(event_types)
        features['event_diversity'] = len(unique_types) / len(event_types)
        features['most_common_event'] = max(set(event_types), key=event_types.count) if event_types else None
        
        # Behavioral features
        features['repetition_rate'] = self._calculate_repetition_rate(event_types)
        features['pattern_complexity'] = self._calculate_pattern_complexity(event_types)
        
        return features
    
    def _detect_sequence_patterns(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Detect patterns in sequence features"""
        patterns = {'type': 'normal'}
        
        # Detect repetitive patterns
        if features.get('repetition_rate', 0) > 0.8:
            patterns['type'] = 'repetitive'
            patterns['repetition_level'] = 'high'
        elif features.get('repetition_rate', 0) > 0.5:
            patterns['type'] = 'repetitive'
            patterns['repetition_level'] = 'medium'
        
        # Detect random patterns
        if features.get('interval_variance', 0) > 1000:  # High variance in timing
            patterns['type'] = 'random'
            patterns['randomness_level'] = 'high'
        
        # Detect complex patterns
        if features.get('pattern_complexity', 0) > 0.7:
            patterns['type'] = 'complex'
            patterns['complexity_level'] = 'high'
        
        return patterns
    
    def _calculate_sequence_anomaly(self, features: Dict[str, float], patterns: Dict[str, Any]) -> float:
        """Calculate anomaly score for sequence"""
        anomaly_score = 0.0
        
        # Check for unusual timing patterns
        if features.get('interval_consistency', 0) < 0.3:
            anomaly_score += 0.3
        
        # Check for unusual repetition
        if features.get('repetition_rate', 0) > 0.9:
            anomaly_score += 0.2
        
        # Check for unusual complexity
        if features.get('pattern_complexity', 0) > 0.8:
            anomaly_score += 0.2
        
        # Check for unusual diversity
        if features.get('event_diversity', 0) < 0.1:
            anomaly_score += 0.3
        
        return min(1.0, anomaly_score)
    
    def _calculate_repetition_rate(self, event_types: List[str]) -> float:
        """Calculate repetition rate in event types"""
        if not event_types:
            return 0.0
        
        total_events = len(event_types)
        unique_events = len(set(event_types))
        
        if unique_events == 0:
            return 0.0
        
        return 1.0 - (unique_events / total_events)
    
    def _calculate_pattern_complexity(self, event_types: List[str]) -> float:
        """Calculate pattern complexity"""
        if not event_types:
            return 0.0
        
        # Calculate entropy as a measure of complexity
        event_counts = defaultdict(int)
        for event_type in event_types:
            event_counts[event_type] += 1
        
        total_events = len(event_types)
        entropy = 0.0
        
        for count in event_counts.values():
            probability = count / total_events
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Normalize entropy
        max_entropy = math.log2(len(event_counts)) if len(event_counts) > 1 else 1.0
        return entropy / max_entropy if max_entropy > 0 else 0.0


class GraphAnalysis:
    """Graph-based behavioral analysis"""
    
    def __init__(self):
        self.interaction_graphs = defaultdict(nx.Graph)
        self.anomaly_threshold = 0.6
    
    def detect_anomalies(self, behavior_sequence: BehaviorSequence) -> Dict[str, Any]:
        """Detect anomalies using graph analysis"""
        agent_id = behavior_sequence.agent_id
        
        # Build interaction graph
        graph = self._build_interaction_graph(behavior_sequence)
        self.interaction_graphs[agent_id] = graph
        
        # Analyze graph properties
        graph_properties = self._analyze_graph_properties(graph)
        
        # Detect anomalies
        anomalies = self._detect_graph_anomalies(graph, graph_properties)
        
        return {
            'graph_properties': graph_properties,
            'anomalies': anomalies,
            'anomaly_score': len(anomalies) / max(1, len(graph.nodes))
        }
    
    def _build_interaction_graph(self, behavior_sequence: BehaviorSequence) -> nx.Graph:
        """Build interaction graph from behavior sequence"""
        graph = nx.Graph()
        
        for event in behavior_sequence.events:
            # Add agent as node
            graph.add_node(event.agent_id, 
                          event_type=event.event_type,
                          timestamp=event.timestamp)
            
            # Add interactions as edges
            if 'interaction_partner' in event.data:
                partner = event.data['interaction_partner']
                if graph.has_edge(event.agent_id, partner):
                    graph[event.agent_id][partner]['weight'] += 1
                else:
                    graph.add_edge(event.agent_id, partner, weight=1)
        
        return graph
    
    def _analyze_graph_properties(self, graph: nx.Graph) -> Dict[str, float]:
        """Analyze graph properties"""
        if not graph.nodes:
            return {}
        
        properties = {
            'node_count': len(graph.nodes),
            'edge_count': len(graph.edges),
            'density': nx.density(graph),
            'average_clustering': nx.average_clustering(graph),
            'transitivity': nx.transitivity(graph)
        }
        
        # Calculate centrality measures
        if len(graph.nodes) > 1:
            properties['average_degree_centrality'] = statistics.mean(nx.degree_centrality(graph).values())
            properties['average_betweenness_centrality'] = statistics.mean(nx.betweenness_centrality(graph).values())
            properties['average_closeness_centrality'] = statistics.mean(nx.closeness_centrality(graph).values())
        
        return properties
    
    def _detect_graph_anomalies(self, graph: nx.Graph, properties: Dict[str, float]) -> List[str]:
        """Detect anomalies in graph structure"""
        anomalies = []
        
        # Check for unusual density
        if properties.get('density', 0) > 0.8:
            anomalies.append("Unusually high graph density")
        elif properties.get('density', 0) < 0.1:
            anomalies.append("Unusually low graph density")
        
        # Check for unusual clustering
        if properties.get('average_clustering', 0) > 0.9:
            anomalies.append("Unusually high clustering coefficient")
        
        # Check for unusual centrality
        if properties.get('average_degree_centrality', 0) > 0.8:
            anomalies.append("Unusually high degree centrality")
        
        return anomalies


class TemporalAnalysis:
    """Temporal behavioral analysis"""
    
    def __init__(self):
        self.temporal_patterns = defaultdict(list)
        self.seasonal_analysis = True
    
    def detect_anomalies(self, behavior_sequence: BehaviorSequence) -> Dict[str, Any]:
        """Detect temporal anomalies in behavior"""
        events = behavior_sequence.events
        if len(events) < 5:
            return {'temporal_anomalies': [], 'anomaly_score': 0.0}
        
        # Extract temporal features
        temporal_features = self._extract_temporal_features(events)
        
        # Detect temporal anomalies
        anomalies = self._detect_temporal_anomalies(temporal_features)
        
        # Calculate anomaly score
        anomaly_score = len(anomalies) / max(1, len(temporal_features))
        
        return {
            'temporal_features': temporal_features,
            'temporal_anomalies': anomalies,
            'anomaly_score': anomaly_score
        }
    
    def predict_evolution(self, historical_behavior: List[BehaviorSequence], time_horizon: int) -> BehaviorPrediction:
        """Predict behavioral evolution"""
        if not historical_behavior:
            return BehaviorPrediction(
                agent_id="unknown",
                predicted_behavior=BehaviorType.NORMAL,
                confidence=0.0,
                time_horizon=time_horizon,
                prediction_factors={},
                risk_assessment="unknown",
                mitigation_strategies=[],
                prediction_timestamp=time.time()
            )
        
        # Analyze historical patterns
        historical_patterns = self._analyze_historical_patterns(historical_behavior)
        
        # Predict future behavior
        prediction = self._predict_future_behavior(historical_patterns, time_horizon)
        
        return prediction
    
    def _extract_temporal_features(self, events: List[BehaviorEvent]) -> Dict[str, Any]:
        """Extract temporal features from events"""
        if not events:
            return {}
        
        timestamps = [event.timestamp for event in events]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        features = {
            'total_duration': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
            'event_frequency': len(events) / (timestamps[-1] - timestamps[0] + 1e-6),
            'interval_mean': statistics.mean(intervals) if intervals else 0,
            'interval_std': statistics.stdev(intervals) if len(intervals) > 1 else 0,
            'interval_trend': self._calculate_trend(intervals),
            'burstiness': self._calculate_burstiness(intervals),
            'regularity': self._calculate_regularity(intervals)
        }
        
        # Add time-of-day features
        if self.seasonal_analysis:
            features.update(self._extract_seasonal_features(timestamps))
        
        return features
    
    def _detect_temporal_anomalies(self, features: Dict[str, Any]) -> List[str]:
        """Detect temporal anomalies"""
        anomalies = []
        
        # Check for unusual frequency
        if features.get('event_frequency', 0) > 10:  # More than 10 events per second
            anomalies.append("Unusually high event frequency")
        elif features.get('event_frequency', 0) < 0.01:  # Less than 1 event per 100 seconds
            anomalies.append("Unusually low event frequency")
        
        # Check for unusual burstiness
        if features.get('burstiness', 0) > 0.8:
            anomalies.append("Unusually bursty behavior")
        
        # Check for unusual regularity
        if features.get('regularity', 0) > 0.9:
            anomalies.append("Unusually regular behavior")
        
        # Check for unusual timing patterns
        if features.get('interval_trend', 0) > 0.5:
            anomalies.append("Increasing interval trend")
        elif features.get('interval_trend', 0) < -0.5:
            anomalies.append("Decreasing interval trend")
        
        return anomalies
    
    def _analyze_historical_patterns(self, historical_behavior: List[BehaviorSequence]) -> Dict[str, Any]:
        """Analyze historical behavioral patterns"""
        patterns = {
            'behavior_types': defaultdict(int),
            'temporal_patterns': [],
            'evolution_trend': 0.0,
            'stability_score': 0.0
        }
        
        for sequence in historical_behavior:
            # Analyze behavior type
            behavior_type = self._classify_behavior_type(sequence)
            patterns['behavior_types'][behavior_type] += 1
            
            # Analyze temporal patterns
            temporal_features = self._extract_temporal_features(sequence.events)
            patterns['temporal_patterns'].append(temporal_features)
        
        # Calculate evolution trend
        patterns['evolution_trend'] = self._calculate_evolution_trend(patterns['temporal_patterns'])
        
        # Calculate stability score
        patterns['stability_score'] = self._calculate_stability_score(patterns['temporal_patterns'])
        
        return patterns
    
    def _predict_future_behavior(self, patterns: Dict[str, Any], time_horizon: int) -> BehaviorPrediction:
        """Predict future behavior based on historical patterns"""
        # Determine most likely behavior type
        behavior_types = patterns['behavior_types']
        most_likely_type = max(behavior_types.items(), key=lambda x: x[1])[0] if behavior_types else BehaviorType.NORMAL
        
        # Calculate confidence based on pattern stability
        confidence = patterns.get('stability_score', 0.5)
        
        # Assess risk
        risk_assessment = self._assess_behavioral_risk(patterns, most_likely_type)
        
        # Generate mitigation strategies
        mitigation_strategies = self._generate_mitigation_strategies(risk_assessment, most_likely_type)
        
        return BehaviorPrediction(
            agent_id="predicted",
            predicted_behavior=most_likely_type,
            confidence=confidence,
            time_horizon=time_horizon,
            prediction_factors=patterns,
            risk_assessment=risk_assessment,
            mitigation_strategies=mitigation_strategies,
            prediction_timestamp=time.time()
        )
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend in values"""
        if len(values) < 2:
            return 0.0
        
        x = list(range(len(values)))
        slope, _, _, _, _ = stats.linregress(x, values)
        return slope
    
    def _calculate_burstiness(self, intervals: List[float]) -> float:
        """Calculate burstiness of intervals"""
        if len(intervals) < 2:
            return 0.0
        
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals)
        
        if mean_interval == 0:
            return 0.0
        
        return (std_interval - mean_interval) / (std_interval + mean_interval)
    
    def _calculate_regularity(self, intervals: List[float]) -> float:
        """Calculate regularity of intervals"""
        if len(intervals) < 2:
            return 1.0
        
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals)
        
        if mean_interval == 0:
            return 1.0
        
        cv = std_interval / mean_interval  # Coefficient of variation
        return 1.0 / (1.0 + cv)  # Regularity is inverse of coefficient of variation
    
    def _extract_seasonal_features(self, timestamps: List[float]) -> Dict[str, float]:
        """Extract seasonal features from timestamps"""
        features = {}
        
        # Convert timestamps to hour of day
        hours = [time.localtime(ts).tm_hour for ts in timestamps]
        
        # Calculate hour distribution
        hour_counts = defaultdict(int)
        for hour in hours:
            hour_counts[hour] += 1
        
        # Calculate entropy of hour distribution
        total_events = len(hours)
        entropy = 0.0
        for count in hour_counts.values():
            probability = count / total_events
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        features['hour_entropy'] = entropy
        features['most_active_hour'] = max(hour_counts.items(), key=lambda x: x[1])[0] if hour_counts else 0
        
        return features
    
    def _classify_behavior_type(self, sequence: BehaviorSequence) -> BehaviorType:
        """Classify behavior type based on sequence"""
        # Simple classification based on sequence features
        if len(sequence.events) < 3:
            return BehaviorType.NORMAL
        
        # Check for suspicious patterns
        event_types = [event.event_type for event in sequence.events]
        unique_types = set(event_types)
        
        if len(unique_types) == 1:
            return BehaviorType.SUSPICIOUS  # Repetitive behavior
        
        return BehaviorType.NORMAL
    
    def _calculate_evolution_trend(self, temporal_patterns: List[Dict[str, Any]]) -> float:
        """Calculate evolution trend in temporal patterns"""
        if len(temporal_patterns) < 2:
            return 0.0
        
        # Extract a key metric (e.g., event frequency) and calculate trend
        frequencies = [pattern.get('event_frequency', 0) for pattern in temporal_patterns]
        return self._calculate_trend(frequencies)
    
    def _calculate_stability_score(self, temporal_patterns: List[Dict[str, Any]]) -> float:
        """Calculate stability score of temporal patterns"""
        if len(temporal_patterns) < 2:
            return 1.0
        
        # Calculate variance in key metrics
        frequencies = [pattern.get('event_frequency', 0) for pattern in temporal_patterns]
        mean_freq = statistics.mean(frequencies)
        std_freq = statistics.stdev(frequencies) if len(frequencies) > 1 else 0
        
        if mean_freq == 0:
            return 1.0
        
        cv = std_freq / mean_freq  # Coefficient of variation
        return 1.0 / (1.0 + cv)  # Stability is inverse of coefficient of variation
    
    def _assess_behavioral_risk(self, patterns: Dict[str, Any], behavior_type: BehaviorType) -> str:
        """Assess behavioral risk"""
        if behavior_type in [BehaviorType.MALICIOUS, BehaviorType.DECEPTIVE]:
            return "high"
        elif behavior_type in [BehaviorType.SUSPICIOUS, BehaviorType.COLLUSIVE]:
            return "medium"
        else:
            return "low"
    
    def _generate_mitigation_strategies(self, risk_assessment: str, behavior_type: BehaviorType) -> List[str]:
        """Generate mitigation strategies"""
        strategies = []
        
        if risk_assessment == "high":
            strategies.extend([
                "Implement immediate monitoring",
                "Restrict agent permissions",
                "Initiate investigation"
            ])
        elif risk_assessment == "medium":
            strategies.extend([
                "Increase monitoring frequency",
                "Review agent activities",
                "Consider additional controls"
            ])
        else:
            strategies.append("Continue normal monitoring")
        
        return strategies


class EnsembleDetection:
    """Ensemble detection combining multiple analysis methods"""
    
    def __init__(self):
        self.sequence_analyzer = SequenceAnalysis()
        self.graph_analyzer = GraphAnalysis()
        self.temporal_analyzer = TemporalAnalysis()
        self.weights = {
            AnalysisMethod.SEQUENCE_ANALYSIS: 0.3,
            AnalysisMethod.GRAPH_ANALYSIS: 0.3,
            AnalysisMethod.TEMPORAL_ANALYSIS: 0.4
        }
    
    def combine_assessments(self, assessments: List[Dict[str, Any]]) -> DeceptionAssessment:
        """Combine multiple assessments into a single deception assessment"""
        if not assessments:
            return DeceptionAssessment(
                agent_id="unknown",
                deception_score=0.0,
                deception_indicators=[],
                confidence=0.0,
                evidence=[],
                risk_level="unknown",
                recommendations=[],
                assessment_timestamp=time.time()
            )
        
        # Extract agent ID from first assessment
        agent_id = assessments[0].get('agent_id', 'unknown')
        
        # Combine anomaly scores
        anomaly_scores = [assessment.get('anomaly_score', 0.0) for assessment in assessments]
        weighted_score = sum(score * self.weights.get(AnalysisMethod.SEQUENCE_ANALYSIS, 0.33) 
                           for score in anomaly_scores)
        
        # Determine deception indicators
        deception_indicators = self._identify_deception_indicators(assessments)
        
        # Calculate confidence
        confidence = self._calculate_ensemble_confidence(assessments)
        
        # Collect evidence
        evidence = self._collect_evidence(assessments)
        
        # Determine risk level
        risk_level = self._determine_risk_level(weighted_score, deception_indicators)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_level, deception_indicators)
        
        return DeceptionAssessment(
            agent_id=agent_id,
            deception_score=weighted_score,
            deception_indicators=deception_indicators,
            confidence=confidence,
            evidence=evidence,
            risk_level=risk_level,
            recommendations=recommendations,
            assessment_timestamp=time.time()
        )
    
    def _identify_deception_indicators(self, assessments: List[Dict[str, Any]]) -> List[DeceptionIndicator]:
        """Identify deception indicators from assessments"""
        indicators = []
        
        for assessment in assessments:
            # Check for inconsistent behavior
            if assessment.get('pattern_type') == 'inconsistent':
                indicators.append(DeceptionIndicator.INCONSISTENT_BEHAVIOR)
            
            # Check for unusual timing
            if assessment.get('temporal_anomalies'):
                indicators.append(DeceptionIndicator.UNUSUAL_TIMING)
            
            # Check for coordinated actions
            if assessment.get('graph_properties', {}).get('density', 0) > 0.8:
                indicators.append(DeceptionIndicator.COORDINATED_ACTIONS)
            
            # Check for hidden patterns
            if assessment.get('pattern_type') == 'complex':
                indicators.append(DeceptionIndicator.HIDDEN_PATTERNS)
        
        return list(set(indicators))  # Remove duplicates
    
    def _calculate_ensemble_confidence(self, assessments: List[Dict[str, Any]]) -> float:
        """Calculate confidence in ensemble assessment"""
        if not assessments:
            return 0.0
        
        # Calculate confidence based on agreement between assessments
        anomaly_scores = [assessment.get('anomaly_score', 0.0) for assessment in assessments]
        
        if len(anomaly_scores) < 2:
            return 0.5
        
        # Calculate variance in scores (lower variance = higher confidence)
        variance = statistics.variance(anomaly_scores)
        confidence = 1.0 / (1.0 + variance)
        
        return min(1.0, confidence)
    
    def _collect_evidence(self, assessments: List[Dict[str, Any]]) -> List[str]:
        """Collect evidence from assessments"""
        evidence = []
        
        for assessment in assessments:
            if assessment.get('anomaly_score', 0) > 0.5:
                evidence.append(f"High anomaly score: {assessment.get('anomaly_score', 0):.2f}")
            
            if assessment.get('temporal_anomalies'):
                evidence.append(f"Temporal anomalies: {', '.join(assessment['temporal_anomalies'])}")
            
            if assessment.get('anomalies'):
                evidence.append(f"Graph anomalies: {', '.join(assessment['anomalies'])}")
        
        return evidence
    
    def _determine_risk_level(self, deception_score: float, indicators: List[DeceptionIndicator]) -> str:
        """Determine risk level based on deception score and indicators"""
        if deception_score >= 0.8 or len(indicators) >= 4:
            return "critical"
        elif deception_score >= 0.6 or len(indicators) >= 3:
            return "high"
        elif deception_score >= 0.4 or len(indicators) >= 2:
            return "medium"
        else:
            return "low"
    
    def _generate_recommendations(self, risk_level: str, indicators: List[DeceptionIndicator]) -> List[str]:
        """Generate recommendations based on risk level and indicators"""
        recommendations = []
        
        if risk_level == "critical":
            recommendations.extend([
                "Immediate agent suspension",
                "Full security investigation",
                "Notify security team"
            ])
        elif risk_level == "high":
            recommendations.extend([
                "Increase monitoring frequency",
                "Restrict agent permissions",
                "Schedule security review"
            ])
        elif risk_level == "medium":
            recommendations.extend([
                "Enhanced monitoring",
                "Review agent activities",
                "Consider additional controls"
            ])
        else:
            recommendations.append("Continue normal monitoring")
        
        # Add indicator-specific recommendations
        if DeceptionIndicator.COORDINATED_ACTIONS in indicators:
            recommendations.append("Investigate potential collusion")
        
        if DeceptionIndicator.INCONSISTENT_BEHAVIOR in indicators:
            recommendations.append("Verify agent identity and integrity")
        
        return recommendations


class AdvancedBehavioralAnalysis:
    """
    Advanced Behavioral Analysis System
    
    Provides sophisticated behavioral analysis including deceptive behavior detection,
    behavioral evolution prediction, and multi-modal anomaly detection.
    """
    
    def __init__(self):
        """Initialize advanced behavioral analysis system"""
        self.sequence_analyzer = SequenceAnalysis()
        self.graph_analyzer = GraphAnalysis()
        self.temporal_analyzer = TemporalAnalysis()
        self.ensemble_detector = EnsembleDetection()
        
        self.behavior_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.deception_assessments: Dict[str, DeceptionAssessment] = {}
        self.behavior_predictions: Dict[str, BehaviorPrediction] = {}
    
    def analyze_behavior(self, behavior_sequence: BehaviorSequence) -> DeceptionAssessment:
        """
        Perform comprehensive behavioral analysis
        
        Args:
            behavior_sequence: Behavior sequence to analyze
            
        Returns:
            Deception assessment result
        """
        agent_id = behavior_sequence.agent_id
        
        # Store behavior in history
        self.behavior_history[agent_id].append(behavior_sequence)
        
        # Perform multi-modal analysis
        sequence_assessment = self.sequence_analyzer.analyze_patterns(behavior_sequence)
        graph_assessment = self.graph_analyzer.detect_anomalies(behavior_sequence)
        temporal_assessment = self.temporal_analyzer.detect_anomalies(behavior_sequence)
        
        # Add agent ID to assessments
        sequence_assessment['agent_id'] = agent_id
        graph_assessment['agent_id'] = agent_id
        temporal_assessment['agent_id'] = agent_id
        
        # Combine assessments using ensemble detection
        assessments = [sequence_assessment, graph_assessment, temporal_assessment]
        deception_assessment = self.ensemble_detector.combine_assessments(assessments)
        
        # Store assessment
        self.deception_assessments[agent_id] = deception_assessment
        
        return deception_assessment
    
    def predict_behavioral_evolution(
        self, 
        agent_id: str, 
        time_horizon: int = 24
    ) -> BehaviorPrediction:
        """
        Predict behavioral evolution for an agent
        
        Args:
            agent_id: Agent identifier
            time_horizon: Time horizon for prediction in hours
            
        Returns:
            Behavior prediction result
        """
        if agent_id not in self.behavior_history:
            return BehaviorPrediction(
                agent_id=agent_id,
                predicted_behavior=BehaviorType.NORMAL,
                confidence=0.0,
                time_horizon=time_horizon,
                prediction_factors={},
                risk_assessment="unknown",
                mitigation_strategies=[],
                prediction_timestamp=time.time()
            )
        
        # Get historical behavior
        historical_behavior = list(self.behavior_history[agent_id])
        
        # Predict evolution using temporal analysis
        prediction = self.temporal_analyzer.predict_evolution(historical_behavior, time_horizon)
        prediction.agent_id = agent_id
        
        # Store prediction
        self.behavior_predictions[agent_id] = prediction
        
        return prediction
    
    def get_behavioral_analytics(self) -> Dict[str, Any]:
        """
        Get behavioral analytics across all agents
        
        Returns:
            Behavioral analytics summary
        """
        total_agents = len(self.behavior_history)
        if total_agents == 0:
            return {'total_agents': 0}
        
        # Calculate deception statistics
        deception_scores = [assessment.deception_score for assessment in self.deception_assessments.values()]
        risk_levels = [assessment.risk_level for assessment in self.deception_assessments.values()]
        
        # Count risk levels
        risk_distribution = defaultdict(int)
        for risk_level in risk_levels:
            risk_distribution[risk_level] += 1
        
        # Calculate average deception score
        avg_deception_score = statistics.mean(deception_scores) if deception_scores else 0.0
        
        # Count deception indicators
        all_indicators = []
        for assessment in self.deception_assessments.values():
            all_indicators.extend(assessment.deception_indicators)
        
        indicator_counts = defaultdict(int)
        for indicator in all_indicators:
            indicator_counts[indicator.value] += 1
        
        return {
            'total_agents': total_agents,
            'average_deception_score': avg_deception_score,
            'risk_distribution': dict(risk_distribution),
            'deception_indicators': dict(indicator_counts),
            'high_risk_agents': risk_distribution['high'] + risk_distribution['critical'],
            'assessments_performed': len(self.deception_assessments),
            'predictions_generated': len(self.behavior_predictions)
        }
