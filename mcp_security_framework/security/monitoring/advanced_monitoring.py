"""
Advanced Monitoring System for MCP Security Framework

This module provides comprehensive monitoring capabilities including:
- Real-time security monitoring
- Behavioral anomaly detection
- Performance monitoring and analysis
- Threat detection and alerting
- Compliance monitoring
- Predictive analytics
- Dashboard and reporting
"""

import time
import asyncio
import threading
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
import numpy as np
from scipy import stats
import networkx as nx
from concurrent.futures import ThreadPoolExecutor
import queue

from pydantic import BaseModel, Field


class MonitoringEvent(Enum):
    """Monitoring event enumeration"""
    SECURITY_VIOLATION = "security_violation"
    PERFORMANCE_ANOMALY = "performance_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    THREAT_DETECTED = "threat_detected"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_ERROR = "system_error"
    ACCESS_ATTEMPT = "access_attempt"
    DATA_ACCESS = "data_access"
    NETWORK_ACTIVITY = "network_activity"
    TRUST_CHANGE = "trust_change"


class AlertSeverity(Enum):
    """Alert severity enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MonitoringMetric(Enum):
    """Monitoring metric enumeration"""
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    NETWORK_LATENCY = "network_latency"
    TRUST_SCORE = "trust_score"
    SECURITY_EVENTS = "security_events"
    ACCESS_FREQUENCY = "access_frequency"
    DATA_VOLUME = "data_volume"


@dataclass
class MonitoringData:
    """Monitoring data structure"""
    metric: MonitoringMetric
    value: float
    timestamp: float
    entity_id: str
    context: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    event_type: MonitoringEvent
    severity: AlertSeverity
    title: str
    description: str
    entity_id: str
    timestamp: float
    metrics: Dict[str, float]
    context: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    resolved: bool = False
    resolution_notes: Optional[str] = None


@dataclass
class AnomalyDetection:
    """Anomaly detection result"""
    entity_id: str
    metric: MonitoringMetric
    anomaly_score: float
    expected_value: float
    actual_value: float
    confidence: float
    timestamp: float
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitoringDashboard:
    """Monitoring dashboard data"""
    dashboard_id: str
    name: str
    widgets: List[Dict[str, Any]]
    refresh_interval: int
    last_updated: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdvancedMonitoringSystem:
    """
    Comprehensive advanced monitoring system
    
    Features:
    - Real-time security monitoring
    - Behavioral anomaly detection
    - Performance monitoring and analysis
    - Threat detection and alerting
    - Compliance monitoring
    - Predictive analytics
    - Dashboard and reporting
    - Machine learning integration
    """
    
    def __init__(self):
        """Initialize advanced monitoring system"""
        self.monitoring_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.alerts: Dict[str, Alert] = {}
        self.anomaly_detectors: Dict[str, Any] = {}
        self.dashboards: Dict[str, MonitoringDashboard] = {}
        self.monitoring_rules: Dict[str, Dict[str, Any]] = {}
        self.alert_handlers: Dict[str, Callable] = {}
        
        # Monitoring parameters
        self.anomaly_threshold = 0.7
        self.alert_cooldown = 300  # 5 minutes
        self.data_retention_hours = 24
        self.batch_size = 100
        self.processing_interval = 1  # seconds
        
        # Background processing
        self.data_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.processing_thread = threading.Thread(target=self._background_processor, daemon=True)
        self.processing_thread.start()
        
        # Initialize default monitoring rules
        self._initialize_default_rules()
        
        # Initialize anomaly detectors
        self._initialize_anomaly_detectors()
    
    def _initialize_default_rules(self):
        """Initialize default monitoring rules"""
        self.monitoring_rules = {
            "high_error_rate": {
                "metric": MonitoringMetric.ERROR_RATE,
                "threshold": 0.05,  # 5% error rate
                "operator": ">",
                "severity": AlertSeverity.HIGH,
                "cooldown": 300
            },
            "low_trust_score": {
                "metric": MonitoringMetric.TRUST_SCORE,
                "threshold": 0.3,
                "operator": "<",
                "severity": AlertSeverity.MEDIUM,
                "cooldown": 600
            },
            "high_response_time": {
                "metric": MonitoringMetric.RESPONSE_TIME,
                "threshold": 5.0,  # 5 seconds
                "operator": ">",
                "severity": AlertSeverity.MEDIUM,
                "cooldown": 300
            },
            "high_memory_usage": {
                "metric": MonitoringMetric.MEMORY_USAGE,
                "threshold": 0.9,  # 90% memory usage
                "operator": ">",
                "severity": AlertSeverity.HIGH,
                "cooldown": 300
            },
            "security_event_spike": {
                "metric": MonitoringMetric.SECURITY_EVENTS,
                "threshold": 10,  # 10 events per minute
                "operator": ">",
                "severity": AlertSeverity.CRITICAL,
                "cooldown": 60
            }
        }
    
    def _initialize_anomaly_detectors(self):
        """Initialize anomaly detection algorithms"""
        # Statistical anomaly detector
        self.anomaly_detectors["statistical"] = {
            "type": "statistical",
            "window_size": 100,
            "threshold_multiplier": 3.0,
            "min_samples": 10
        }
        
        # Machine learning anomaly detector
        self.anomaly_detectors["ml_based"] = {
            "type": "ml_based",
            "model_type": "isolation_forest",
            "contamination": 0.1,
            "min_samples": 50
        }
        
        # Time series anomaly detector
        self.anomaly_detectors["time_series"] = {
            "type": "time_series",
            "window_size": 24,  # hours
            "seasonality": True,
            "trend_detection": True
        }
    
    def _background_processor(self):
        """Background processor for monitoring data"""
        while True:
            try:
                # Process monitoring data
                self._process_monitoring_data()
                
                # Check for anomalies
                self._detect_anomalies()
                
                # Check monitoring rules
                self._check_monitoring_rules()
                
                # Update dashboards
                self._update_dashboards()
                
                time.sleep(self.processing_interval)
                
            except Exception as e:
                print(f"Error in monitoring background processor: {e}")
                time.sleep(5)
    
    def add_monitoring_data(self, data: MonitoringData) -> bool:
        """
        Add monitoring data
        
        Args:
            data: Monitoring data to add
            
        Returns:
            True if data added successfully
        """
        try:
            # Add to queue for processing
            self.data_queue.put(data)
            
            # Add to storage
            key = f"{data.entity_id}:{data.metric.value}"
            self.monitoring_data[key].append(data)
            
            return True
            
        except Exception as e:
            print(f"Error adding monitoring data: {e}")
            return False
    
    def _process_monitoring_data(self):
        """Process monitoring data from queue"""
        processed_count = 0
        
        while not self.data_queue.empty() and processed_count < self.batch_size:
            try:
                data = self.data_queue.get_nowait()
                
                # Process the data
                self._process_single_data_point(data)
                
                processed_count += 1
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error processing monitoring data: {e}")
    
    def _process_single_data_point(self, data: MonitoringData):
        """Process a single monitoring data point"""
        # Update time series data
        self._update_time_series(data)
        
        # Check for immediate alerts
        self._check_immediate_alerts(data)
        
        # Update anomaly detection models
        self._update_anomaly_models(data)
    
    def _update_time_series(self, data: MonitoringData):
        """Update time series data for analysis"""
        # This would update time series databases or in-memory structures
        # For now, it's handled by the deque storage
        pass
    
    def _check_immediate_alerts(self, data: MonitoringData):
        """Check for immediate alert conditions"""
        for rule_id, rule in self.monitoring_rules.items():
            if rule["metric"] == data.metric:
                if self._evaluate_rule(rule, data.value):
                    self._create_alert(rule_id, rule, data)
    
    def _evaluate_rule(self, rule: Dict[str, Any], value: float) -> bool:
        """Evaluate a monitoring rule"""
        threshold = rule["threshold"]
        operator = rule["operator"]
        
        if operator == ">":
            return value > threshold
        elif operator == ">=":
            return value >= threshold
        elif operator == "<":
            return value < threshold
        elif operator == "<=":
            return value <= threshold
        elif operator == "==":
            return abs(value - threshold) < 0.001
        elif operator == "!=":
            return abs(value - threshold) >= 0.001
        else:
            return False
    
    def _create_alert(self, rule_id: str, rule: Dict[str, Any], data: MonitoringData):
        """Create an alert based on rule violation"""
        alert_id = f"{rule_id}_{data.entity_id}_{int(data.timestamp)}"
        
        # Check cooldown
        if alert_id in self.alerts:
            existing_alert = self.alerts[alert_id]
            if time.time() - existing_alert.timestamp < rule.get("cooldown", self.alert_cooldown):
                return
        
        alert = Alert(
            alert_id=alert_id,
            event_type=MonitoringEvent.PERFORMANCE_ANOMALY,
            severity=rule["severity"],
            title=f"{rule['metric'].value} threshold exceeded",
            description=f"{rule['metric'].value} value {data.value} exceeded threshold {rule['threshold']}",
            entity_id=data.entity_id,
            timestamp=time.time(),
            metrics={rule["metric"].value: data.value},
            context=data.context
        )
        
        self.alerts[alert_id] = alert
        
        # Trigger alert handlers
        self._trigger_alert_handlers(alert)
    
    def _trigger_alert_handlers(self, alert: Alert):
        """Trigger registered alert handlers"""
        for handler_id, handler in self.alert_handlers.items():
            try:
                handler(alert)
            except Exception as e:
                print(f"Error in alert handler {handler_id}: {e}")
    
    def _detect_anomalies(self):
        """Detect anomalies in monitoring data"""
        for key, data_deque in self.monitoring_data.items():
            if len(data_deque) < 10:  # Need minimum data for anomaly detection
                continue
            
            entity_id, metric_str = key.split(":", 1)
            metric = MonitoringMetric(metric_str)
            
            # Apply different anomaly detection methods
            anomalies = []
            
            # Statistical anomaly detection
            stat_anomaly = self._detect_statistical_anomaly(entity_id, metric, data_deque)
            if stat_anomaly:
                anomalies.append(stat_anomaly)
            
            # Time series anomaly detection
            ts_anomaly = self._detect_time_series_anomaly(entity_id, metric, data_deque)
            if ts_anomaly:
                anomalies.append(ts_anomaly)
            
            # Create alerts for detected anomalies
            for anomaly in anomalies:
                if anomaly.anomaly_score > self.anomaly_threshold:
                    self._create_anomaly_alert(anomaly)
    
    def _detect_statistical_anomaly(self, entity_id: str, metric: MonitoringMetric, 
                                  data_deque: deque) -> Optional[AnomalyDetection]:
        """Detect statistical anomalies"""
        if len(data_deque) < 10:
            return None
        
        # Get recent data
        recent_data = list(data_deque)[-100:]  # Last 100 points
        values = [d.value for d in recent_data]
        
        if len(values) < 10:
            return None
        
        # Calculate statistical measures
        mean_val = np.mean(values)
        std_val = np.std(values)
        
        if std_val == 0:
            return None
        
        # Check latest value
        latest_value = values[-1]
        z_score = abs(latest_value - mean_val) / std_val
        
        # Statistical anomaly if z-score > threshold
        threshold_multiplier = self.anomaly_detectors["statistical"]["threshold_multiplier"]
        
        if z_score > threshold_multiplier:
            return AnomalyDetection(
                entity_id=entity_id,
                metric=metric,
                anomaly_score=min(1.0, z_score / (threshold_multiplier * 2)),
                expected_value=mean_val,
                actual_value=latest_value,
                confidence=min(1.0, z_score / threshold_multiplier),
                timestamp=time.time(),
                context={"method": "statistical", "z_score": z_score}
            )
        
        return None
    
    def _detect_time_series_anomaly(self, entity_id: str, metric: MonitoringMetric, 
                                  data_deque: deque) -> Optional[AnomalyDetection]:
        """Detect time series anomalies"""
        if len(data_deque) < 24:  # Need at least 24 hours of data
            return None
        
        # Get time series data
        data_points = list(data_deque)
        timestamps = [d.timestamp for d in data_points]
        values = [d.value for d in data_points]
        
        # Simple trend analysis
        if len(values) < 10:
            return None
        
        # Calculate moving average
        window_size = min(12, len(values) // 2)  # Half the data or 12 points
        moving_avg = np.convolve(values, np.ones(window_size)/window_size, mode='valid')
        
        if len(moving_avg) == 0:
            return None
        
        # Check if latest value deviates significantly from trend
        latest_value = values[-1]
        expected_value = moving_avg[-1]
        
        # Calculate deviation
        if expected_value == 0:
            deviation = abs(latest_value)
        else:
            deviation = abs(latest_value - expected_value) / abs(expected_value)
        
        # Time series anomaly if deviation > threshold
        if deviation > 0.5:  # 50% deviation
            return AnomalyDetection(
                entity_id=entity_id,
                metric=metric,
                anomaly_score=min(1.0, deviation),
                expected_value=expected_value,
                actual_value=latest_value,
                confidence=min(1.0, deviation),
                timestamp=time.time(),
                context={"method": "time_series", "deviation": deviation}
            )
        
        return None
    
    def _create_anomaly_alert(self, anomaly: AnomalyDetection):
        """Create alert for detected anomaly"""
        alert_id = f"anomaly_{anomaly.entity_id}_{anomaly.metric.value}_{int(anomaly.timestamp)}"
        
        # Determine severity based on anomaly score
        if anomaly.anomaly_score > 0.9:
            severity = AlertSeverity.CRITICAL
        elif anomaly.anomaly_score > 0.7:
            severity = AlertSeverity.HIGH
        elif anomaly.anomaly_score > 0.5:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW
        
        alert = Alert(
            alert_id=alert_id,
            event_type=MonitoringEvent.BEHAVIORAL_ANOMALY,
            severity=severity,
            title=f"Anomaly detected in {anomaly.metric.value}",
            description=f"Anomaly score: {anomaly.anomaly_score:.3f}, Expected: {anomaly.expected_value:.3f}, Actual: {anomaly.actual_value:.3f}",
            entity_id=anomaly.entity_id,
            timestamp=anomaly.timestamp,
            metrics={anomaly.metric.value: anomaly.actual_value},
            context=anomaly.context
        )
        
        self.alerts[alert_id] = alert
        self._trigger_alert_handlers(alert)
    
    def _check_monitoring_rules(self):
        """Check monitoring rules against current data"""
        # This would check rules against aggregated data
        # For now, it's handled by immediate alert checking
        pass
    
    def _update_anomaly_models(self, data: MonitoringData):
        """Update anomaly detection models with new data"""
        # This would update ML models for anomaly detection
        # For now, it's a placeholder
        pass
    
    def _update_dashboards(self):
        """Update monitoring dashboards"""
        current_time = time.time()
        
        for dashboard in self.dashboards.values():
            if current_time - dashboard.last_updated > dashboard.refresh_interval:
                self._refresh_dashboard(dashboard)
                dashboard.last_updated = current_time
    
    def _refresh_dashboard(self, dashboard: MonitoringDashboard):
        """Refresh a specific dashboard"""
        # This would update dashboard widgets with latest data
        # For now, it's a placeholder
        pass
    
    def register_alert_handler(self, handler_id: str, handler: Callable):
        """Register an alert handler"""
        self.alert_handlers[handler_id] = handler
    
    def unregister_alert_handler(self, handler_id: str):
        """Unregister an alert handler"""
        if handler_id in self.alert_handlers:
            del self.alert_handlers[handler_id]
    
    def create_dashboard(self, dashboard: MonitoringDashboard) -> bool:
        """Create a monitoring dashboard"""
        if dashboard.dashboard_id in self.dashboards:
            return False
        
        self.dashboards[dashboard.dashboard_id] = dashboard
        return True
    
    def get_monitoring_metrics(self, entity_id: str, metric: MonitoringMetric, 
                             time_range: Tuple[float, float] = None) -> List[MonitoringData]:
        """
        Get monitoring metrics for an entity
        
        Args:
            entity_id: Entity identifier
            metric: Monitoring metric
            time_range: Time range tuple (start, end)
            
        Returns:
            List of monitoring data
        """
        key = f"{entity_id}:{metric.value}"
        
        if key not in self.monitoring_data:
            return []
        
        data = list(self.monitoring_data[key])
        
        if time_range:
            start_time, end_time = time_range
            data = [d for d in data if start_time <= d.timestamp <= end_time]
        
        return data
    
    def get_alerts(self, entity_id: str = None, severity: AlertSeverity = None, 
                  resolved: bool = None) -> List[Alert]:
        """
        Get alerts with optional filtering
        
        Args:
            entity_id: Filter by entity ID
            severity: Filter by severity
            resolved: Filter by resolution status
            
        Returns:
            List of alerts
        """
        alerts = list(self.alerts.values())
        
        if entity_id:
            alerts = [a for a in alerts if a.entity_id == entity_id]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if resolved is not None:
            alerts = [a for a in alerts if a.resolved == resolved]
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        
        return alerts
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        if alert_id not in self.alerts:
            return False
        
        self.alerts[alert_id].acknowledged = True
        return True
    
    def resolve_alert(self, alert_id: str, resolution_notes: str = None) -> bool:
        """Resolve an alert"""
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.resolved = True
        alert.resolution_notes = resolution_notes
        
        return True
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring system statistics"""
        total_alerts = len(self.alerts)
        unresolved_alerts = len([a for a in self.alerts.values() if not a.resolved])
        critical_alerts = len([a for a in self.alerts.values() if a.severity == AlertSeverity.CRITICAL])
        
        # Calculate data volume
        total_data_points = sum(len(data) for data in self.monitoring_data.values())
        
        # Calculate alert distribution by severity
        severity_distribution = defaultdict(int)
        for alert in self.alerts.values():
            severity_distribution[alert.severity.value] += 1
        
        return {
            "total_alerts": total_alerts,
            "unresolved_alerts": unresolved_alerts,
            "critical_alerts": critical_alerts,
            "total_data_points": total_data_points,
            "active_entities": len(set(key.split(":")[0] for key in self.monitoring_data.keys())),
            "alert_distribution": dict(severity_distribution),
            "monitoring_rules": len(self.monitoring_rules),
            "dashboards": len(self.dashboards),
            "alert_handlers": len(self.alert_handlers)
        }
    
    def export_monitoring_data(self, file_path: str) -> bool:
        """Export monitoring data to file"""
        try:
            export_data = {
                "monitoring_data": {
                    key: [
                        {
                            "metric": data.metric.value,
                            "value": data.value,
                            "timestamp": data.timestamp,
                            "entity_id": data.entity_id,
                            "context": data.context,
                            "tags": list(data.tags)
                        }
                        for data in data_deque
                    ]
                    for key, data_deque in self.monitoring_data.items()
                },
                "alerts": {
                    alert_id: {
                        "alert_id": alert.alert_id,
                        "event_type": alert.event_type.value,
                        "severity": alert.severity.value,
                        "title": alert.title,
                        "description": alert.description,
                        "entity_id": alert.entity_id,
                        "timestamp": alert.timestamp,
                        "metrics": alert.metrics,
                        "context": alert.context,
                        "acknowledged": alert.acknowledged,
                        "resolved": alert.resolved,
                        "resolution_notes": alert.resolution_notes
                    }
                    for alert_id, alert in self.alerts.items()
                },
                "monitoring_rules": self.monitoring_rules,
                "dashboards": {
                    dashboard_id: {
                        "dashboard_id": dashboard.dashboard_id,
                        "name": dashboard.name,
                        "widgets": dashboard.widgets,
                        "refresh_interval": dashboard.refresh_interval,
                        "last_updated": dashboard.last_updated,
                        "metadata": dashboard.metadata
                    }
                    for dashboard_id, dashboard in self.dashboards.items()
                },
                "statistics": self.get_monitoring_statistics(),
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting monitoring data: {e}")
            return False
