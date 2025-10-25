"""
Comprehensive Performance Analysis System for MCP Security Framework

This module provides comprehensive performance analysis capabilities including:
- Real-time performance monitoring
- Performance bottleneck identification
- Resource utilization analysis
- Scalability assessment
- Performance optimization recommendations
- Capacity planning
- Performance regression detection
"""

import time
import threading
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
import numpy as np
from scipy import stats
import psutil
import asyncio
from concurrent.futures import ThreadPoolExecutor
import queue

from pydantic import BaseModel, Field


class PerformanceMetric(Enum):
    """Performance metric enumeration"""
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    LATENCY = "latency"
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    DISK_USAGE = "disk_usage"
    NETWORK_USAGE = "network_usage"
    CONCURRENT_USERS = "concurrent_users"
    ERROR_RATE = "error_rate"
    AVAILABILITY = "availability"
    QUEUE_LENGTH = "queue_length"
    CACHE_HIT_RATIO = "cache_hit_ratio"


class PerformanceLevel(Enum):
    """Performance level enumeration"""
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    CRITICAL = "critical"


class BottleneckType(Enum):
    """Bottleneck type enumeration"""
    CPU_BOUND = "cpu_bound"
    MEMORY_BOUND = "memory_bound"
    IO_BOUND = "io_bound"
    NETWORK_BOUND = "network_bound"
    DATABASE_BOUND = "database_bound"
    CACHE_BOUND = "cache_bound"
    THREAD_BOUND = "thread_bound"


@dataclass
class PerformanceData:
    """Performance data structure"""
    metric: PerformanceMetric
    value: float
    timestamp: float
    component_id: str
    context: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)


@dataclass
class PerformanceBaseline:
    """Performance baseline data structure"""
    component_id: str
    metric: PerformanceMetric
    baseline_value: float
    standard_deviation: float
    percentile_95: float
    percentile_99: float
    sample_count: int
    last_updated: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceBottleneck:
    """Performance bottleneck identification"""
    bottleneck_id: str
    component_id: str
    bottleneck_type: BottleneckType
    severity: float  # 0-1 scale
    description: str
    affected_metrics: List[PerformanceMetric]
    impact_score: float
    recommendations: List[str]
    detected_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceReport:
    """Performance analysis report"""
    report_id: str
    component_id: str
    analysis_period: Tuple[float, float]
    overall_performance: PerformanceLevel
    key_metrics: Dict[PerformanceMetric, float]
    bottlenecks: List[PerformanceBottleneck]
    recommendations: List[str]
    capacity_utilization: float
    scalability_score: float
    generated_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class PerformanceAnalyzer:
    """
    Comprehensive performance analysis system
    
    Features:
    - Real-time performance monitoring
    - Performance bottleneck identification
    - Resource utilization analysis
    - Scalability assessment
    - Performance optimization recommendations
    - Capacity planning
    - Performance regression detection
    - Machine learning-based anomaly detection
    """
    
    def __init__(self):
        """Initialize performance analyzer"""
        self.performance_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.performance_baselines: Dict[str, PerformanceBaseline] = {}
        self.performance_bottlenecks: Dict[str, PerformanceBottleneck] = {}
        self.performance_reports: List[PerformanceReport] = []
        
        # Performance thresholds
        self.performance_thresholds = {
            PerformanceMetric.RESPONSE_TIME: {"excellent": 0.1, "good": 0.5, "acceptable": 1.0, "poor": 2.0},
            PerformanceMetric.THROUGHPUT: {"excellent": 1000, "good": 500, "acceptable": 100, "poor": 50},
            PerformanceMetric.CPU_USAGE: {"excellent": 0.3, "good": 0.6, "acceptable": 0.8, "poor": 0.9},
            PerformanceMetric.MEMORY_USAGE: {"excellent": 0.4, "good": 0.7, "acceptable": 0.85, "poor": 0.95},
            PerformanceMetric.ERROR_RATE: {"excellent": 0.001, "good": 0.01, "acceptable": 0.05, "poor": 0.1}
        }
        
        # Analysis parameters
        self.analysis_window = 3600  # 1 hour
        self.bottleneck_threshold = 0.7
        self.regression_threshold = 0.2
        self.baseline_sample_size = 1000
        
        # Background processing
        self.data_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.processing_thread = threading.Thread(target=self._background_processor, daemon=True)
        self.processing_thread.start()
        
        # System monitoring
        self.system_monitor_thread = threading.Thread(target=self._system_monitor, daemon=True)
        self.system_monitor_thread.start()
    
    def _background_processor(self):
        """Background processor for performance data"""
        while True:
            try:
                # Process performance data
                self._process_performance_data()
                
                # Update baselines
                self._update_performance_baselines()
                
                # Detect bottlenecks
                self._detect_performance_bottlenecks()
                
                # Detect regressions
                self._detect_performance_regressions()
                
                time.sleep(10)  # Process every 10 seconds
                
            except Exception as e:
                print(f"Error in performance analyzer background processor: {e}")
                time.sleep(30)
    
    def _system_monitor(self):
        """Monitor system performance metrics"""
        while True:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                network = psutil.net_io_counters()
                
                # Add system performance data
                current_time = time.time()
                
                self.add_performance_data(PerformanceData(
                    metric=PerformanceMetric.CPU_USAGE,
                    value=cpu_percent / 100.0,
                    timestamp=current_time,
                    component_id="system",
                    context={"cores": psutil.cpu_count()}
                ))
                
                self.add_performance_data(PerformanceData(
                    metric=PerformanceMetric.MEMORY_USAGE,
                    value=memory.percent / 100.0,
                    timestamp=current_time,
                    component_id="system",
                    context={"total": memory.total, "available": memory.available}
                ))
                
                self.add_performance_data(PerformanceData(
                    metric=PerformanceMetric.DISK_USAGE,
                    value=disk.percent / 100.0,
                    timestamp=current_time,
                    component_id="system",
                    context={"total": disk.total, "free": disk.free}
                ))
                
                time.sleep(5)  # Collect every 5 seconds
                
            except Exception as e:
                print(f"Error in system monitor: {e}")
                time.sleep(10)
    
    def add_performance_data(self, data: PerformanceData) -> bool:
        """
        Add performance data
        
        Args:
            data: Performance data to add
            
        Returns:
            True if data added successfully
        """
        try:
            # Add to queue for processing
            self.data_queue.put(data)
            
            # Add to storage
            key = f"{data.component_id}:{data.metric.value}"
            self.performance_data[key].append(data)
            
            return True
            
        except Exception as e:
            print(f"Error adding performance data: {e}")
            return False
    
    def _process_performance_data(self):
        """Process performance data from queue"""
        processed_count = 0
        
        while not self.data_queue.empty() and processed_count < 100:
            try:
                data = self.data_queue.get_nowait()
                
                # Process the data
                self._process_single_data_point(data)
                
                processed_count += 1
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error processing performance data: {e}")
    
    def _process_single_data_point(self, data: PerformanceData):
        """Process a single performance data point"""
        # Update time series data
        self._update_time_series(data)
        
        # Check for immediate performance issues
        self._check_immediate_performance_issues(data)
    
    def _update_time_series(self, data: PerformanceData):
        """Update time series data for analysis"""
        # This would update time series databases or in-memory structures
        # For now, it's handled by the deque storage
        pass
    
    def _check_immediate_performance_issues(self, data: PerformanceData):
        """Check for immediate performance issues"""
        thresholds = self.performance_thresholds.get(data.metric)
        if not thresholds:
            return
        
        # Check if value exceeds poor threshold
        if data.value > thresholds["poor"]:
            self._create_performance_alert(data, "poor")
        elif data.value > thresholds["acceptable"]:
            self._create_performance_alert(data, "acceptable")
    
    def _create_performance_alert(self, data: PerformanceData, level: str):
        """Create performance alert"""
        alert_id = f"perf_{data.component_id}_{data.metric.value}_{int(data.timestamp)}"
        
        # This would create alerts in the monitoring system
        print(f"Performance alert: {level} {data.metric.value} = {data.value} for {data.component_id}")
    
    def _update_performance_baselines(self):
        """Update performance baselines"""
        for key, data_deque in self.performance_data.items():
            if len(data_deque) < self.baseline_sample_size:
                continue
            
            component_id, metric_str = key.split(":", 1)
            metric = PerformanceMetric(metric_str)
            
            # Calculate baseline statistics
            values = [d.value for d in data_deque]
            
            baseline = PerformanceBaseline(
                component_id=component_id,
                metric=metric,
                baseline_value=np.mean(values),
                standard_deviation=np.std(values),
                percentile_95=np.percentile(values, 95),
                percentile_99=np.percentile(values, 99),
                sample_count=len(values),
                last_updated=time.time()
            )
            
            self.performance_baselines[key] = baseline
    
    def _detect_performance_bottlenecks(self):
        """Detect performance bottlenecks"""
        for key, data_deque in self.performance_data.items():
            if len(data_deque) < 100:  # Need minimum data
                continue
            
            component_id, metric_str = key.split(":", 1)
            metric = PerformanceMetric(metric_str)
            
            # Analyze for bottlenecks
            bottleneck = self._analyze_bottleneck(component_id, metric, data_deque)
            
            if bottleneck and bottleneck.severity > self.bottleneck_threshold:
                self.performance_bottlenecks[bottleneck.bottleneck_id] = bottleneck
    
    def _analyze_bottleneck(self, component_id: str, metric: PerformanceMetric, 
                          data_deque: deque) -> Optional[PerformanceBottleneck]:
        """Analyze for specific bottleneck type"""
        values = [d.value for d in data_deque]
        recent_values = values[-50:]  # Last 50 data points
        
        if not recent_values:
            return None
        
        # Determine bottleneck type based on metric
        if metric == PerformanceMetric.CPU_USAGE:
            return self._analyze_cpu_bottleneck(component_id, recent_values)
        elif metric == PerformanceMetric.MEMORY_USAGE:
            return self._analyze_memory_bottleneck(component_id, recent_values)
        elif metric == PerformanceMetric.RESPONSE_TIME:
            return self._analyze_response_time_bottleneck(component_id, recent_values)
        elif metric == PerformanceMetric.THROUGHPUT:
            return self._analyze_throughput_bottleneck(component_id, recent_values)
        
        return None
    
    def _analyze_cpu_bottleneck(self, component_id: str, values: List[float]) -> Optional[PerformanceBottleneck]:
        """Analyze CPU bottleneck"""
        avg_cpu = np.mean(values)
        
        if avg_cpu > 0.8:  # High CPU usage
            severity = min(1.0, (avg_cpu - 0.8) / 0.2)
            
            return PerformanceBottleneck(
                bottleneck_id=f"cpu_{component_id}_{int(time.time())}",
                component_id=component_id,
                bottleneck_type=BottleneckType.CPU_BOUND,
                severity=severity,
                description=f"High CPU usage: {avg_cpu:.2%}",
                affected_metrics=[PerformanceMetric.CPU_USAGE, PerformanceMetric.RESPONSE_TIME],
                impact_score=severity,
                recommendations=[
                    "Optimize CPU-intensive operations",
                    "Implement caching mechanisms",
                    "Consider horizontal scaling",
                    "Profile and optimize code"
                ],
                detected_at=time.time()
            )
        
        return None
    
    def _analyze_memory_bottleneck(self, component_id: str, values: List[float]) -> Optional[PerformanceBottleneck]:
        """Analyze memory bottleneck"""
        avg_memory = np.mean(values)
        
        if avg_memory > 0.85:  # High memory usage
            severity = min(1.0, (avg_memory - 0.85) / 0.15)
            
            return PerformanceBottleneck(
                bottleneck_id=f"memory_{component_id}_{int(time.time())}",
                component_id=component_id,
                bottleneck_type=BottleneckType.MEMORY_BOUND,
                severity=severity,
                description=f"High memory usage: {avg_memory:.2%}",
                affected_metrics=[PerformanceMetric.MEMORY_USAGE, PerformanceMetric.RESPONSE_TIME],
                impact_score=severity,
                recommendations=[
                    "Implement memory pooling",
                    "Optimize data structures",
                    "Add memory monitoring",
                    "Consider garbage collection tuning"
                ],
                detected_at=time.time()
            )
        
        return None
    
    def _analyze_response_time_bottleneck(self, component_id: str, values: List[float]) -> Optional[PerformanceBottleneck]:
        """Analyze response time bottleneck"""
        avg_response_time = np.mean(values)
        p95_response_time = np.percentile(values, 95)
        
        if avg_response_time > 1.0 or p95_response_time > 2.0:  # High response time
            severity = min(1.0, (avg_response_time - 1.0) / 2.0)
            
            return PerformanceBottleneck(
                bottleneck_id=f"response_{component_id}_{int(time.time())}",
                component_id=component_id,
                bottleneck_type=BottleneckType.IO_BOUND,
                severity=severity,
                description=f"High response time: avg={avg_response_time:.2f}s, p95={p95_response_time:.2f}s",
                affected_metrics=[PerformanceMetric.RESPONSE_TIME, PerformanceMetric.THROUGHPUT],
                impact_score=severity,
                recommendations=[
                    "Optimize database queries",
                    "Implement connection pooling",
                    "Add response caching",
                    "Consider async processing"
                ],
                detected_at=time.time()
            )
        
        return None
    
    def _analyze_throughput_bottleneck(self, component_id: str, values: List[float]) -> Optional[PerformanceBottleneck]:
        """Analyze throughput bottleneck"""
        avg_throughput = np.mean(values)
        
        if avg_throughput < 50:  # Low throughput
            severity = min(1.0, (50 - avg_throughput) / 50)
            
            return PerformanceBottleneck(
                bottleneck_id=f"throughput_{component_id}_{int(time.time())}",
                component_id=component_id,
                bottleneck_type=BottleneckType.THREAD_BOUND,
                severity=severity,
                description=f"Low throughput: {avg_throughput:.1f} requests/second",
                affected_metrics=[PerformanceMetric.THROUGHPUT, PerformanceMetric.CONCURRENT_USERS],
                impact_score=severity,
                recommendations=[
                    "Increase thread pool size",
                    "Implement load balancing",
                    "Optimize request processing",
                    "Consider microservices architecture"
                ],
                detected_at=time.time()
            )
        
        return None
    
    def _detect_performance_regressions(self):
        """Detect performance regressions"""
        for key, baseline in self.performance_baselines.items():
            if key not in self.performance_data:
                continue
            
            data_deque = self.performance_data[key]
            if len(data_deque) < 50:  # Need recent data
                continue
            
            # Compare recent performance with baseline
            recent_values = [d.value for d in list(data_deque)[-50:]]
            recent_avg = np.mean(recent_values)
            
            # Calculate regression score
            regression_score = abs(recent_avg - baseline.baseline_value) / baseline.baseline_value
            
            if regression_score > self.regression_threshold:
                self._create_regression_alert(key, baseline, recent_avg, regression_score)
    
    def _create_regression_alert(self, key: str, baseline: PerformanceBaseline, 
                               recent_avg: float, regression_score: float):
        """Create performance regression alert"""
        component_id, metric_str = key.split(":", 1)
        
        print(f"Performance regression detected: {component_id} {metric_str}")
        print(f"  Baseline: {baseline.baseline_value:.3f}")
        print(f"  Recent: {recent_avg:.3f}")
        print(f"  Regression: {regression_score:.1%}")
    
    def get_performance_level(self, metric: PerformanceMetric, value: float) -> PerformanceLevel:
        """Get performance level for a metric value"""
        thresholds = self.performance_thresholds.get(metric)
        if not thresholds:
            return PerformanceLevel.ACCEPTABLE
        
        if value <= thresholds["excellent"]:
            return PerformanceLevel.EXCELLENT
        elif value <= thresholds["good"]:
            return PerformanceLevel.GOOD
        elif value <= thresholds["acceptable"]:
            return PerformanceLevel.ACCEPTABLE
        elif value <= thresholds["poor"]:
            return PerformanceLevel.POOR
        else:
            return PerformanceLevel.CRITICAL
    
    def analyze_component_performance(self, component_id: str, 
                                    time_range: Tuple[float, float] = None) -> PerformanceReport:
        """
        Analyze performance for a specific component
        
        Args:
            component_id: Component identifier
            time_range: Time range for analysis
            
        Returns:
            Performance analysis report
        """
        if time_range is None:
            end_time = time.time()
            start_time = end_time - self.analysis_window
        else:
            start_time, end_time = time_range
        
        # Collect performance data for component
        component_metrics = {}
        bottlenecks = []
        
        for key, data_deque in self.performance_data.items():
            if not key.startswith(f"{component_id}:"):
                continue
            
            metric_str = key.split(":", 1)[1]
            metric = PerformanceMetric(metric_str)
            
            # Filter data by time range
            filtered_data = [d for d in data_deque if start_time <= d.timestamp <= end_time]
            
            if not filtered_data:
                continue
            
            # Calculate metrics
            values = [d.value for d in filtered_data]
            component_metrics[metric] = {
                "avg": np.mean(values),
                "min": np.min(values),
                "max": np.max(values),
                "p95": np.percentile(values, 95),
                "p99": np.percentile(values, 99)
            }
        
        # Get bottlenecks for component
        component_bottlenecks = [b for b in self.performance_bottlenecks.values() 
                               if b.component_id == component_id]
        
        # Calculate overall performance level
        overall_performance = self._calculate_overall_performance(component_metrics)
        
        # Calculate capacity utilization
        capacity_utilization = self._calculate_capacity_utilization(component_metrics)
        
        # Calculate scalability score
        scalability_score = self._calculate_scalability_score(component_metrics, component_bottlenecks)
        
        # Generate recommendations
        recommendations = self._generate_performance_recommendations(component_metrics, component_bottlenecks)
        
        report = PerformanceReport(
            report_id=f"perf_report_{component_id}_{int(time.time())}",
            component_id=component_id,
            analysis_period=(start_time, end_time),
            overall_performance=overall_performance,
            key_metrics={metric: data["avg"] for metric, data in component_metrics.items()},
            bottlenecks=component_bottlenecks,
            recommendations=recommendations,
            capacity_utilization=capacity_utilization,
            scalability_score=scalability_score,
            generated_at=time.time()
        )
        
        self.performance_reports.append(report)
        return report
    
    def _calculate_overall_performance(self, metrics: Dict[PerformanceMetric, Dict[str, float]]) -> PerformanceLevel:
        """Calculate overall performance level"""
        if not metrics:
            return PerformanceLevel.ACCEPTABLE
        
        performance_scores = []
        
        for metric, data in metrics.items():
            avg_value = data["avg"]
            level = self.get_performance_level(metric, avg_value)
            
            # Convert level to numeric score
            level_scores = {
                PerformanceLevel.EXCELLENT: 5,
                PerformanceLevel.GOOD: 4,
                PerformanceLevel.ACCEPTABLE: 3,
                PerformanceLevel.POOR: 2,
                PerformanceLevel.CRITICAL: 1
            }
            
            performance_scores.append(level_scores[level])
        
        avg_score = np.mean(performance_scores)
        
        if avg_score >= 4.5:
            return PerformanceLevel.EXCELLENT
        elif avg_score >= 3.5:
            return PerformanceLevel.GOOD
        elif avg_score >= 2.5:
            return PerformanceLevel.ACCEPTABLE
        elif avg_score >= 1.5:
            return PerformanceLevel.POOR
        else:
            return PerformanceLevel.CRITICAL
    
    def _calculate_capacity_utilization(self, metrics: Dict[PerformanceMetric, Dict[str, float]]) -> float:
        """Calculate capacity utilization"""
        utilization_metrics = [
            PerformanceMetric.CPU_USAGE,
            PerformanceMetric.MEMORY_USAGE,
            PerformanceMetric.DISK_USAGE
        ]
        
        utilizations = []
        for metric in utilization_metrics:
            if metric in metrics:
                utilizations.append(metrics[metric]["avg"])
        
        if not utilizations:
            return 0.0
        
        return np.mean(utilizations)
    
    def _calculate_scalability_score(self, metrics: Dict[PerformanceMetric, Dict[str, float]], 
                                   bottlenecks: List[PerformanceBottleneck]) -> float:
        """Calculate scalability score"""
        # Base score
        score = 1.0
        
        # Penalize for bottlenecks
        for bottleneck in bottlenecks:
            score -= bottleneck.impact_score * 0.2
        
        # Penalize for high resource utilization
        for metric in [PerformanceMetric.CPU_USAGE, PerformanceMetric.MEMORY_USAGE]:
            if metric in metrics:
                utilization = metrics[metric]["avg"]
                if utilization > 0.8:
                    score -= (utilization - 0.8) * 0.5
        
        return max(0.0, min(1.0, score))
    
    def _generate_performance_recommendations(self, metrics: Dict[PerformanceMetric, Dict[str, float]], 
                                            bottlenecks: List[PerformanceBottleneck]) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        # Add bottleneck-specific recommendations
        for bottleneck in bottlenecks:
            recommendations.extend(bottleneck.recommendations)
        
        # Add metric-specific recommendations
        for metric, data in metrics.items():
            avg_value = data["avg"]
            
            if metric == PerformanceMetric.RESPONSE_TIME and avg_value > 1.0:
                recommendations.append("Consider implementing response caching")
                recommendations.append("Optimize database queries and indexes")
            
            elif metric == PerformanceMetric.CPU_USAGE and avg_value > 0.8:
                recommendations.append("Implement CPU-intensive task optimization")
                recommendations.append("Consider horizontal scaling")
            
            elif metric == PerformanceMetric.MEMORY_USAGE and avg_value > 0.85:
                recommendations.append("Implement memory optimization techniques")
                recommendations.append("Consider memory pooling")
            
            elif metric == PerformanceMetric.ERROR_RATE and avg_value > 0.05:
                recommendations.append("Investigate and fix error sources")
                recommendations.append("Implement better error handling")
        
        # Remove duplicates
        return list(set(recommendations))
    
    def get_performance_statistics(self) -> Dict[str, Any]:
        """Get performance analysis statistics"""
        total_data_points = sum(len(data) for data in self.performance_data.values())
        active_components = len(set(key.split(":")[0] for key in self.performance_data.keys()))
        
        return {
            "total_data_points": total_data_points,
            "active_components": active_components,
            "performance_baselines": len(self.performance_baselines),
            "active_bottlenecks": len([b for b in self.performance_bottlenecks.values() 
                                     if time.time() - b.detected_at < 3600]),
            "performance_reports": len(self.performance_reports),
            "system_metrics": {
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent
            }
        }
    
    def export_performance_data(self, file_path: str) -> bool:
        """Export performance data to file"""
        try:
            export_data = {
                "performance_data": {
                    key: [
                        {
                            "metric": data.metric.value,
                            "value": data.value,
                            "timestamp": data.timestamp,
                            "component_id": data.component_id,
                            "context": data.context,
                            "tags": list(data.tags)
                        }
                        for data in data_deque
                    ]
                    for key, data_deque in self.performance_data.items()
                },
                "performance_baselines": {
                    key: {
                        "component_id": baseline.component_id,
                        "metric": baseline.metric.value,
                        "baseline_value": baseline.baseline_value,
                        "standard_deviation": baseline.standard_deviation,
                        "percentile_95": baseline.percentile_95,
                        "percentile_99": baseline.percentile_99,
                        "sample_count": baseline.sample_count,
                        "last_updated": baseline.last_updated,
                        "metadata": baseline.metadata
                    }
                    for key, baseline in self.performance_baselines.items()
                },
                "performance_bottlenecks": {
                    bottleneck_id: {
                        "bottleneck_id": bottleneck.bottleneck_id,
                        "component_id": bottleneck.component_id,
                        "bottleneck_type": bottleneck.bottleneck_type.value,
                        "severity": bottleneck.severity,
                        "description": bottleneck.description,
                        "affected_metrics": [m.value for m in bottleneck.affected_metrics],
                        "impact_score": bottleneck.impact_score,
                        "recommendations": bottleneck.recommendations,
                        "detected_at": bottleneck.detected_at,
                        "metadata": bottleneck.metadata
                    }
                    for bottleneck_id, bottleneck in self.performance_bottlenecks.items()
                },
                "performance_reports": [
                    {
                        "report_id": report.report_id,
                        "component_id": report.component_id,
                        "analysis_period": report.analysis_period,
                        "overall_performance": report.overall_performance.value,
                        "key_metrics": {m.value: v for m, v in report.key_metrics.items()},
                        "bottlenecks": [b.bottleneck_id for b in report.bottlenecks],
                        "recommendations": report.recommendations,
                        "capacity_utilization": report.capacity_utilization,
                        "scalability_score": report.scalability_score,
                        "generated_at": report.generated_at,
                        "metadata": report.metadata
                    }
                    for report in self.performance_reports
                ],
                "statistics": self.get_performance_statistics(),
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting performance data: {e}")
            return False
