"""
Adaptive Security System for MCP Security Framework

This module provides comprehensive adaptive security mechanisms including:
- Dynamic policy adaptation
- Threat-based security adjustments
- Behavioral pattern learning
- Risk-based access control adaptation
- Automated response mechanisms
- Security posture optimization
- Continuous security improvement
"""

import time
import uuid
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
import numpy as np
from scipy import stats
import threading
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel, Field


class AdaptationTrigger(Enum):
    """Adaptation trigger enumeration"""
    THREAT_DETECTED = "threat_detected"
    RISK_THRESHOLD_EXCEEDED = "risk_threshold_exceeded"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    SECURITY_INCIDENT = "security_incident"
    POLICY_VIOLATION = "policy_violation"
    TRUST_SCORE_CHANGE = "trust_score_change"
    ENVIRONMENTAL_CHANGE = "environmental_change"


class AdaptationAction(Enum):
    """Adaptation action enumeration"""
    INCREASE_SECURITY_LEVEL = "increase_security_level"
    DECREASE_SECURITY_LEVEL = "decrease_security_level"
    MODIFY_ACCESS_CONTROL = "modify_access_control"
    UPDATE_POLICIES = "update_policies"
    ADJUST_TRUST_THRESHOLDS = "adjust_trust_thresholds"
    ENABLE_ADDITIONAL_MONITORING = "enable_additional_monitoring"
    ISOLATE_COMPONENT = "isolate_component"
    ACTIVATE_BACKUP_SYSTEM = "activate_backup_system"
    NOTIFY_ADMINISTRATORS = "notify_administrators"
    TRIGGER_INCIDENT_RESPONSE = "trigger_incident_response"


class AdaptationLevel(Enum):
    """Adaptation level enumeration"""
    MINIMAL = "minimal"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"
    CRITICAL = "critical"


class LearningAlgorithm(Enum):
    """Learning algorithm enumeration"""
    REINFORCEMENT_LEARNING = "reinforcement_learning"
    SUPERVISED_LEARNING = "supervised_learning"
    UNSUPERVISED_LEARNING = "unsupervised_learning"
    ONLINE_LEARNING = "online_learning"
    TRANSFER_LEARNING = "transfer_learning"


@dataclass
class AdaptationRule:
    """Adaptation rule definition"""
    rule_id: str
    name: str
    description: str
    trigger: AdaptationTrigger
    conditions: List[Dict[str, Any]]
    actions: List[AdaptationAction]
    adaptation_level: AdaptationLevel
    priority: int
    enabled: bool = True
    success_rate: float = 0.0
    execution_count: int = 0
    last_executed: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdaptationEvent:
    """Adaptation event data structure"""
    event_id: str
    trigger: AdaptationTrigger
    context: Dict[str, Any]
    timestamp: float
    severity: float
    affected_components: List[str]
    recommended_actions: List[AdaptationAction]
    executed_actions: List[Dict[str, Any]] = field(default_factory=list)
    outcome: Optional[str] = None
    effectiveness: Optional[float] = None


@dataclass
class BehavioralPattern:
    """Behavioral pattern representation"""
    pattern_id: str
    entity_id: str
    pattern_type: str
    features: Dict[str, Any]
    frequency: int
    confidence: float
    last_observed: float
    anomaly_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityPosture:
    """Security posture representation"""
    posture_id: str
    timestamp: float
    overall_security_level: float
    component_security_levels: Dict[str, float]
    active_policies: List[str]
    active_monitoring: List[str]
    risk_score: float
    threat_level: float
    adaptation_recommendations: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdaptiveSecuritySystem:
    """
    Comprehensive adaptive security system
    
    Features:
    - Dynamic policy adaptation
    - Threat-based security adjustments
    - Behavioral pattern learning
    - Risk-based access control adaptation
    - Automated response mechanisms
    - Security posture optimization
    - Continuous security improvement
    - Machine learning integration
    """
    
    def __init__(self):
        """Initialize adaptive security system"""
        self.adaptation_rules: Dict[str, AdaptationRule] = {}
        self.adaptation_events: deque = deque(maxlen=1000)
        self.behavioral_patterns: Dict[str, List[BehavioralPattern]] = defaultdict(list)
        self.security_postures: deque = deque(maxlen=100)
        self.learning_models: Dict[str, Any] = {}
        self.adaptation_history: List[Dict[str, Any]] = []
        
        # Adaptation parameters
        self.adaptation_threshold = 0.7
        self.learning_rate = 0.1
        self.pattern_confidence_threshold = 0.8
        self.anomaly_threshold = 0.6
        self.adaptation_cooldown = 300  # 5 minutes
        
        # Background processing
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.processing_thread = threading.Thread(target=self._background_processor, daemon=True)
        self.processing_thread.start()
        
        # Initialize default adaptation rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default adaptation rules"""
        default_rules = [
            AdaptationRule(
                rule_id="threat_detection_response",
                name="Threat Detection Response",
                description="Respond to detected threats by increasing security",
                trigger=AdaptationTrigger.THREAT_DETECTED,
                conditions=[
                    {"type": "threat_severity", "operator": ">=", "value": 0.7},
                    {"type": "threat_confidence", "operator": ">=", "value": 0.8}
                ],
                actions=[
                    AdaptationAction.INCREASE_SECURITY_LEVEL,
                    AdaptationAction.ENABLE_ADDITIONAL_MONITORING,
                    AdaptationAction.NOTIFY_ADMINISTRATORS
                ],
                adaptation_level=AdaptationLevel.SIGNIFICANT,
                priority=1
            ),
            AdaptationRule(
                rule_id="risk_threshold_response",
                name="Risk Threshold Response",
                description="Respond to high risk situations",
                trigger=AdaptationTrigger.RISK_THRESHOLD_EXCEEDED,
                conditions=[
                    {"type": "risk_score", "operator": ">", "value": 0.8}
                ],
                actions=[
                    AdaptationAction.MODIFY_ACCESS_CONTROL,
                    AdaptationAction.ADJUST_TRUST_THRESHOLDS,
                    AdaptationAction.ENABLE_ADDITIONAL_MONITORING
                ],
                adaptation_level=AdaptationLevel.MODERATE,
                priority=2
            ),
            AdaptationRule(
                rule_id="behavioral_anomaly_response",
                name="Behavioral Anomaly Response",
                description="Respond to behavioral anomalies",
                trigger=AdaptationTrigger.BEHAVIORAL_ANOMALY,
                conditions=[
                    {"type": "anomaly_score", "operator": ">", "value": 0.6},
                    {"type": "pattern_confidence", "operator": ">=", "value": 0.7}
                ],
                actions=[
                    AdaptationAction.ENABLE_ADDITIONAL_MONITORING,
                    AdaptationAction.MODIFY_ACCESS_CONTROL
                ],
                adaptation_level=AdaptationLevel.MODERATE,
                priority=3
            ),
            AdaptationRule(
                rule_id="security_incident_response",
                name="Security Incident Response",
                description="Respond to security incidents",
                trigger=AdaptationTrigger.SECURITY_INCIDENT,
                conditions=[
                    {"type": "incident_severity", "operator": ">=", "value": 0.5}
                ],
                actions=[
                    AdaptationAction.INCREASE_SECURITY_LEVEL,
                    AdaptationAction.ISOLATE_COMPONENT,
                    AdaptationAction.TRIGGER_INCIDENT_RESPONSE,
                    AdaptationAction.NOTIFY_ADMINISTRATORS
                ],
                adaptation_level=AdaptationLevel.CRITICAL,
                priority=1
            ),
            AdaptationRule(
                rule_id="performance_optimization",
                name="Performance Optimization",
                description="Optimize security based on performance",
                trigger=AdaptationTrigger.PERFORMANCE_DEGRADATION,
                conditions=[
                    {"type": "performance_impact", "operator": ">", "value": 0.3},
                    {"type": "security_level", "operator": ">", "value": 0.8}
                ],
                actions=[
                    AdaptationAction.DECREASE_SECURITY_LEVEL,
                    AdaptationAction.UPDATE_POLICIES
                ],
                adaptation_level=AdaptationLevel.MINIMAL,
                priority=4
            )
        ]
        
        for rule in default_rules:
            self.adaptation_rules[rule.rule_id] = rule
    
    def _background_processor(self):
        """Background processor for adaptive security"""
        while True:
            try:
                # Process adaptation events
                self._process_adaptation_events()
                
                # Update behavioral patterns
                self._update_behavioral_patterns()
                
                # Optimize security posture
                self._optimize_security_posture()
                
                # Update learning models
                self._update_learning_models()
                
                time.sleep(10)  # Process every 10 seconds
                
            except Exception as e:
                print(f"Error in adaptive security background processor: {e}")
                time.sleep(30)
    
    def trigger_adaptation(self, trigger: AdaptationTrigger, context: Dict[str, Any]) -> bool:
        """
        Trigger security adaptation
        
        Args:
            trigger: Adaptation trigger
            context: Context information
            
        Returns:
            True if adaptation triggered successfully
        """
        # Create adaptation event
        event = AdaptationEvent(
            event_id=str(uuid.uuid4()),
            trigger=trigger,
            context=context,
            timestamp=time.time(),
            severity=context.get("severity", 0.5),
            affected_components=context.get("affected_components", []),
            recommended_actions=[]
        )
        
        # Find applicable rules
        applicable_rules = self._find_applicable_rules(trigger, context)
        
        if not applicable_rules:
            return False
        
        # Execute adaptation rules
        executed_actions = []
        for rule in applicable_rules:
            if self._should_execute_rule(rule, context):
                actions = self._execute_adaptation_rule(rule, context)
                executed_actions.extend(actions)
                
                # Update rule statistics
                rule.execution_count += 1
                rule.last_executed = time.time()
        
        # Update event with executed actions
        event.executed_actions = executed_actions
        
        # Add to adaptation events
        self.adaptation_events.append(event)
        
        # Record in history
        self.adaptation_history.append({
            "event_id": event.event_id,
            "trigger": trigger.value,
            "context": context,
            "executed_actions": executed_actions,
            "timestamp": time.time()
        })
        
        return True
    
    def _find_applicable_rules(self, trigger: AdaptationTrigger, context: Dict[str, Any]) -> List[AdaptationRule]:
        """Find rules applicable to the trigger and context"""
        applicable_rules = []
        
        for rule in self.adaptation_rules.values():
            if not rule.enabled:
                continue
            
            if rule.trigger != trigger:
                continue
            
            # Check if rule conditions are met
            if self._evaluate_rule_conditions(rule, context):
                applicable_rules.append(rule)
        
        # Sort by priority
        applicable_rules.sort(key=lambda r: r.priority)
        
        return applicable_rules
    
    def _evaluate_rule_conditions(self, rule: AdaptationRule, context: Dict[str, Any]) -> bool:
        """Evaluate if rule conditions are met"""
        for condition in rule.conditions:
            condition_type = condition["type"]
            operator = condition["operator"]
            value = condition["value"]
            
            context_value = context.get(condition_type, 0)
            
            if not self._evaluate_condition(context_value, operator, value):
                return False
        
        return True
    
    def _evaluate_condition(self, context_value: Any, operator: str, value: Any) -> bool:
        """Evaluate a single condition"""
        try:
            if operator == ">":
                return context_value > value
            elif operator == ">=":
                return context_value >= value
            elif operator == "<":
                return context_value < value
            elif operator == "<=":
                return context_value <= value
            elif operator == "==":
                return context_value == value
            elif operator == "!=":
                return context_value != value
            else:
                return False
        except Exception:
            return False
    
    def _should_execute_rule(self, rule: AdaptationRule, context: Dict[str, Any]) -> bool:
        """Determine if a rule should be executed"""
        # Check cooldown period
        if rule.last_executed:
            time_since_last = time.time() - rule.last_executed
            if time_since_last < self.adaptation_cooldown:
                return False
        
        # Check success rate (avoid repeatedly failing rules)
        if rule.execution_count > 5 and rule.success_rate < 0.3:
            return False
        
        return True
    
    def _execute_adaptation_rule(self, rule: AdaptationRule, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute an adaptation rule"""
        executed_actions = []
        
        for action in rule.actions:
            try:
                result = self._execute_adaptation_action(action, context, rule.adaptation_level)
                executed_actions.append({
                    "action": action.value,
                    "result": result,
                    "timestamp": time.time(),
                    "rule_id": rule.rule_id
                })
            except Exception as e:
                executed_actions.append({
                    "action": action.value,
                    "result": f"Error: {str(e)}",
                    "timestamp": time.time(),
                    "rule_id": rule.rule_id
                })
        
        return executed_actions
    
    def _execute_adaptation_action(self, action: AdaptationAction, context: Dict[str, Any], 
                                 level: AdaptationLevel) -> str:
        """Execute a specific adaptation action"""
        if action == AdaptationAction.INCREASE_SECURITY_LEVEL:
            return self._increase_security_level(context, level)
        elif action == AdaptationAction.DECREASE_SECURITY_LEVEL:
            return self._decrease_security_level(context, level)
        elif action == AdaptationAction.MODIFY_ACCESS_CONTROL:
            return self._modify_access_control(context, level)
        elif action == AdaptationAction.UPDATE_POLICIES:
            return self._update_policies(context, level)
        elif action == AdaptationAction.ADJUST_TRUST_THRESHOLDS:
            return self._adjust_trust_thresholds(context, level)
        elif action == AdaptationAction.ENABLE_ADDITIONAL_MONITORING:
            return self._enable_additional_monitoring(context, level)
        elif action == AdaptationAction.ISOLATE_COMPONENT:
            return self._isolate_component(context, level)
        elif action == AdaptationAction.ACTIVATE_BACKUP_SYSTEM:
            return self._activate_backup_system(context, level)
        elif action == AdaptationAction.NOTIFY_ADMINISTRATORS:
            return self._notify_administrators(context, level)
        elif action == AdaptationAction.TRIGGER_INCIDENT_RESPONSE:
            return self._trigger_incident_response(context, level)
        else:
            return f"Unknown action: {action.value}"
    
    def _increase_security_level(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Increase security level"""
        # Implementation would depend on specific security controls
        increase_factor = {
            AdaptationLevel.MINIMAL: 0.1,
            AdaptationLevel.MODERATE: 0.2,
            AdaptationLevel.SIGNIFICANT: 0.3,
            AdaptationLevel.CRITICAL: 0.5
        }.get(level, 0.2)
        
        return f"Increased security level by {increase_factor}"
    
    def _decrease_security_level(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Decrease security level"""
        decrease_factor = {
            AdaptationLevel.MINIMAL: 0.05,
            AdaptationLevel.MODERATE: 0.1,
            AdaptationLevel.SIGNIFICANT: 0.15,
            AdaptationLevel.CRITICAL: 0.2
        }.get(level, 0.1)
        
        return f"Decreased security level by {decrease_factor}"
    
    def _modify_access_control(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Modify access control settings"""
        return f"Modified access control settings for level {level.value}"
    
    def _update_policies(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Update security policies"""
        return f"Updated security policies for level {level.value}"
    
    def _adjust_trust_thresholds(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Adjust trust thresholds"""
        adjustment = {
            AdaptationLevel.MINIMAL: 0.05,
            AdaptationLevel.MODERATE: 0.1,
            AdaptationLevel.SIGNIFICANT: 0.15,
            AdaptationLevel.CRITICAL: 0.2
        }.get(level, 0.1)
        
        return f"Adjusted trust thresholds by {adjustment}"
    
    def _enable_additional_monitoring(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Enable additional monitoring"""
        return f"Enabled additional monitoring for level {level.value}"
    
    def _isolate_component(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Isolate a component"""
        components = context.get("affected_components", ["unknown"])
        return f"Isolated components: {', '.join(components)}"
    
    def _activate_backup_system(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Activate backup system"""
        return f"Activated backup system for level {level.value}"
    
    def _notify_administrators(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Notify administrators"""
        return f"Notified administrators for level {level.value}"
    
    def _trigger_incident_response(self, context: Dict[str, Any], level: AdaptationLevel) -> str:
        """Trigger incident response"""
        return f"Triggered incident response for level {level.value}"
    
    def learn_behavioral_pattern(self, entity_id: str, behavior_data: Dict[str, Any]) -> bool:
        """
        Learn behavioral patterns from entity behavior
        
        Args:
            entity_id: Entity identifier
            behavior_data: Behavioral data
            
        Returns:
            True if pattern learned successfully
        """
        # Extract features from behavior data
        features = self._extract_behavioral_features(behavior_data)
        
        # Check if pattern already exists
        existing_pattern = self._find_similar_pattern(entity_id, features)
        
        if existing_pattern:
            # Update existing pattern
            existing_pattern.frequency += 1
            existing_pattern.last_observed = time.time()
            existing_pattern.confidence = min(1.0, existing_pattern.confidence + 0.1)
        else:
            # Create new pattern
            pattern = BehavioralPattern(
                pattern_id=str(uuid.uuid4()),
                entity_id=entity_id,
                pattern_type=behavior_data.get("type", "unknown"),
                features=features,
                frequency=1,
                confidence=0.5,
                last_observed=time.time(),
                anomaly_score=0.0
            )
            
            self.behavioral_patterns[entity_id].append(pattern)
        
        return True
    
    def _extract_behavioral_features(self, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from behavioral data"""
        features = {}
        
        # Extract common features
        if "timestamp" in behavior_data:
            features["hour_of_day"] = time.localtime(behavior_data["timestamp"]).tm_hour
            features["day_of_week"] = time.localtime(behavior_data["timestamp"]).tm_wday
        
        if "action" in behavior_data:
            features["action_type"] = behavior_data["action"]
        
        if "resource" in behavior_data:
            features["resource_type"] = behavior_data["resource"]
        
        if "duration" in behavior_data:
            features["duration"] = behavior_data["duration"]
        
        if "success" in behavior_data:
            features["success"] = behavior_data["success"]
        
        return features
    
    def _find_similar_pattern(self, entity_id: str, features: Dict[str, Any]) -> Optional[BehavioralPattern]:
        """Find similar behavioral pattern"""
        if entity_id not in self.behavioral_patterns:
            return None
        
        patterns = self.behavioral_patterns[entity_id]
        
        for pattern in patterns:
            similarity = self._calculate_pattern_similarity(pattern.features, features)
            if similarity > 0.8:  # High similarity threshold
                return pattern
        
        return None
    
    def _calculate_pattern_similarity(self, features1: Dict[str, Any], features2: Dict[str, Any]) -> float:
        """Calculate similarity between two feature sets"""
        common_keys = set(features1.keys()) & set(features2.keys())
        
        if not common_keys:
            return 0.0
        
        similarities = []
        for key in common_keys:
            val1 = features1[key]
            val2 = features2[key]
            
            if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                # Numerical similarity
                max_val = max(abs(val1), abs(val2))
                if max_val == 0:
                    similarity = 1.0
                else:
                    similarity = 1.0 - abs(val1 - val2) / max_val
            else:
                # Categorical similarity
                similarity = 1.0 if val1 == val2 else 0.0
            
            similarities.append(similarity)
        
        return np.mean(similarities) if similarities else 0.0
    
    def detect_behavioral_anomaly(self, entity_id: str, behavior_data: Dict[str, Any]) -> float:
        """
        Detect behavioral anomalies
        
        Args:
            entity_id: Entity identifier
            behavior_data: Behavioral data
            
        Returns:
            Anomaly score (0-1)
        """
        if entity_id not in self.behavioral_patterns:
            return 0.5  # Unknown entity, moderate anomaly score
        
        features = self._extract_behavioral_features(behavior_data)
        patterns = self.behavioral_patterns[entity_id]
        
        if not patterns:
            return 0.5
        
        # Calculate anomaly score based on pattern deviations
        anomaly_scores = []
        
        for pattern in patterns:
            similarity = self._calculate_pattern_similarity(pattern.features, features)
            anomaly_score = 1.0 - similarity
            anomaly_scores.append(anomaly_score)
        
        # Weight by pattern confidence
        if anomaly_scores:
            weights = [p.confidence for p in patterns]
            weighted_anomaly = np.average(anomaly_scores, weights=weights)
            return min(1.0, weighted_anomaly)
        
        return 0.5
    
    def _process_adaptation_events(self):
        """Process pending adaptation events"""
        # This would process events in the queue
        # For now, it's a placeholder
        pass
    
    def _update_behavioral_patterns(self):
        """Update behavioral patterns based on new data"""
        # This would update patterns based on recent observations
        # For now, it's a placeholder
        pass
    
    def _optimize_security_posture(self):
        """Optimize overall security posture"""
        # This would analyze current security posture and make optimizations
        # For now, it's a placeholder
        pass
    
    def _update_learning_models(self):
        """Update machine learning models"""
        # This would update ML models based on new data
        # For now, it's a placeholder
        pass
    
    def add_adaptation_rule(self, rule: AdaptationRule) -> bool:
        """Add a new adaptation rule"""
        if rule.rule_id in self.adaptation_rules:
            return False
        
        self.adaptation_rules[rule.rule_id] = rule
        return True
    
    def remove_adaptation_rule(self, rule_id: str) -> bool:
        """Remove an adaptation rule"""
        if rule_id not in self.adaptation_rules:
            return False
        
        del self.adaptation_rules[rule_id]
        return True
    
    def update_adaptation_rule(self, rule: AdaptationRule) -> bool:
        """Update an existing adaptation rule"""
        if rule.rule_id not in self.adaptation_rules:
            return False
        
        self.adaptation_rules[rule.rule_id] = rule
        return True
    
    def get_adaptation_metrics(self) -> Dict[str, Any]:
        """Get adaptation system metrics"""
        return {
            "total_rules": len(self.adaptation_rules),
            "enabled_rules": len([r for r in self.adaptation_rules.values() if r.enabled]),
            "total_events": len(self.adaptation_events),
            "total_patterns": sum(len(patterns) for patterns in self.behavioral_patterns.values()),
            "adaptation_history_count": len(self.adaptation_history),
            "rule_execution_stats": {
                rule_id: {
                    "execution_count": rule.execution_count,
                    "success_rate": rule.success_rate,
                    "last_executed": rule.last_executed
                }
                for rule_id, rule in self.adaptation_rules.items()
            }
        }
    
    def export_adaptation_data(self, file_path: str) -> bool:
        """Export adaptation data to file"""
        try:
            export_data = {
                "adaptation_rules": {
                    rule_id: {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "description": rule.description,
                        "trigger": rule.trigger.value,
                        "conditions": rule.conditions,
                        "actions": [action.value for action in rule.actions],
                        "adaptation_level": rule.adaptation_level.value,
                        "priority": rule.priority,
                        "enabled": rule.enabled,
                        "success_rate": rule.success_rate,
                        "execution_count": rule.execution_count,
                        "last_executed": rule.last_executed,
                        "metadata": rule.metadata
                    }
                    for rule_id, rule in self.adaptation_rules.items()
                },
                "adaptation_events": [
                    {
                        "event_id": event.event_id,
                        "trigger": event.trigger.value,
                        "context": event.context,
                        "timestamp": event.timestamp,
                        "severity": event.severity,
                        "affected_components": event.affected_components,
                        "recommended_actions": [action.value for action in event.recommended_actions],
                        "executed_actions": event.executed_actions,
                        "outcome": event.outcome,
                        "effectiveness": event.effectiveness
                    }
                    for event in self.adaptation_events
                ],
                "behavioral_patterns": {
                    entity_id: [
                        {
                            "pattern_id": pattern.pattern_id,
                            "entity_id": pattern.entity_id,
                            "pattern_type": pattern.pattern_type,
                            "features": pattern.features,
                            "frequency": pattern.frequency,
                            "confidence": pattern.confidence,
                            "last_observed": pattern.last_observed,
                            "anomaly_score": pattern.anomaly_score,
                            "metadata": pattern.metadata
                        }
                        for pattern in patterns
                    ]
                    for entity_id, patterns in self.behavioral_patterns.items()
                },
                "adaptation_history": self.adaptation_history,
                "metrics": self.get_adaptation_metrics(),
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting adaptation data: {e}")
            return False
