"""
Metrics Collector for MCP Security Framework Benchmarking

This module provides comprehensive metrics collection capabilities for
benchmarking the security framework's performance and effectiveness.
"""

import time
import threading
import statistics
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import json
import asyncio
from datetime import datetime, timedelta

from pydantic import BaseModel, Field


class MetricType(Enum):
    """Metric type enumeration"""
    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"
    USABILITY = "usability"
    RELIABILITY = "reliability"


class MetricCategory(Enum):
    """Metric category enumeration"""
    ATTACK_SUCCESS_RATE = "attack_success_rate"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    RESPONSE_TIME = "response_time"
    DETECTION_ACCURACY = "detection_accuracy"
    THROUGHPUT = "throughput"
    RESOURCE_UTILIZATION = "resource_utilization"
    COMPLIANCE_COVERAGE = "compliance_coverage"
    AVAILABILITY = "availability"


@dataclass
class MetricData:
    """Metric data structure"""
    metric_id: str
    metric_type: MetricType
    category: MetricCategory
    value: float
    timestamp: float
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkResult:
    """Benchmark result structure"""
    metric_category: MetricCategory
    current_value: float
    benchmark_value: float
    improvement_percentage: float
    status: str  # "excellent", "good", "acceptable", "poor"
    timestamp: float
    details: Dict[str, Any] = field(default_factory=dict)


class MetricsCollector:
    """
    Comprehensive metrics collector for security framework benchmarking
    
    Collects, stores, and analyzes metrics for security effectiveness,
    performance, compliance, and usability benchmarking.
    """
    
    def __init__(self, max_history_size: int = 10000):
        """
        Initialize metrics collector
        
        Args:
            max_history_size: Maximum number of metrics to store in history
        """
        self.max_history_size = max_history_size
        self.metrics_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=max_history_size)
        )
        self.current_metrics: Dict[str, float] = {}
        self.benchmark_results: Dict[MetricCategory, BenchmarkResult] = {}
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Benchmark thresholds (industry standards)
        self.benchmark_thresholds = {
            MetricCategory.ATTACK_SUCCESS_RATE: {
                "excellent": 0.05,  # <5%
                "good": 0.15,       # 5-15%
                "acceptable": 0.30, # 15-30%
                "poor": 1.0         # >30%
            },
            MetricCategory.FALSE_POSITIVE_RATE: {
                "excellent": 0.02,  # <2%
                "good": 0.05,       # 2-5%
                "acceptable": 0.10, # 5-10%
                "poor": 1.0         # >10%
            },
            MetricCategory.RESPONSE_TIME: {
                "excellent": 60.0,   # <1 minute
                "good": 300.0,       # 1-5 minutes
                "acceptable": 900.0, # 5-15 minutes
                "poor": float('inf') # >15 minutes
            },
            MetricCategory.DETECTION_ACCURACY: {
                "excellent": 0.95,   # >95%
                "good": 0.90,        # 90-95%
                "acceptable": 0.80,  # 80-90%
                "poor": 0.0          # <80%
            },
            MetricCategory.THROUGHPUT: {
                "excellent": 10000.0, # >10K req/s
                "good": 5000.0,       # 5K-10K req/s
                "acceptable": 1000.0, # 1K-5K req/s
                "poor": 0.0           # <1K req/s
            },
            MetricCategory.RESOURCE_UTILIZATION: {
                "excellent": 0.20,   # <20% overhead
                "good": 0.40,        # 20-40% overhead
                "acceptable": 0.60,  # 40-60% overhead
                "poor": 1.0          # >60% overhead
            },
            MetricCategory.COMPLIANCE_COVERAGE: {
                "excellent": 0.95,   # >95%
                "good": 0.85,        # 85-95%
                "acceptable": 0.70,  # 70-85%
                "poor": 0.0          # <70%
            },
            MetricCategory.AVAILABILITY: {
                "excellent": 0.9999, # >99.99%
                "good": 0.999,       # 99.9-99.99%
                "acceptable": 0.99,  # 99-99.9%
                "poor": 0.0          # <99%
            }
        }
    
    def collect_metric(
        self,
        metric_id: str,
        metric_type: MetricType,
        category: MetricCategory,
        value: float,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Collect a metric value
        
        Args:
            metric_id: Unique identifier for the metric
            metric_type: Type of metric
            category: Category of metric
            value: Metric value
            context: Additional context information
            metadata: Additional metadata
        """
        with self._lock:
            metric_data = MetricData(
                metric_id=metric_id,
                metric_type=metric_type,
                category=category,
                value=value,
                timestamp=time.time(),
                context=context or {},
                metadata=metadata or {}
            )
            
            # Store in history
            self.metrics_history[metric_id].append(metric_data)
            
            # Update current metrics
            self.current_metrics[metric_id] = value
            
            # Update benchmark results
            self._update_benchmark_result(category, value)
    
    def collect_security_metric(
        self,
        metric_id: str,
        category: MetricCategory,
        value: float,
        attack_type: Optional[str] = None,
        threat_level: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Collect security-specific metric
        
        Args:
            metric_id: Unique identifier for the metric
            category: Category of metric
            value: Metric value
            attack_type: Type of attack (if applicable)
            threat_level: Threat level (if applicable)
            **kwargs: Additional context information
        """
        context = {
            "attack_type": attack_type,
            "threat_level": threat_level,
            **kwargs
        }
        
        self.collect_metric(
            metric_id=metric_id,
            metric_type=MetricType.SECURITY,
            category=category,
            value=value,
            context=context
        )
    
    def collect_performance_metric(
        self,
        metric_id: str,
        category: MetricCategory,
        value: float,
        operation_type: Optional[str] = None,
        resource_type: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Collect performance-specific metric
        
        Args:
            metric_id: Unique identifier for the metric
            category: Category of metric
            value: Metric value
            operation_type: Type of operation
            resource_type: Type of resource
            **kwargs: Additional context information
        """
        context = {
            "operation_type": operation_type,
            "resource_type": resource_type,
            **kwargs
        }
        
        self.collect_metric(
            metric_id=metric_id,
            metric_type=MetricType.PERFORMANCE,
            category=category,
            value=value,
            context=context
        )
    
    def collect_compliance_metric(
        self,
        metric_id: str,
        category: MetricCategory,
        value: float,
        standard: Optional[str] = None,
        requirement: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Collect compliance-specific metric
        
        Args:
            metric_id: Unique identifier for the metric
            category: Category of metric
            value: Metric value
            standard: Compliance standard
            requirement: Specific requirement
            **kwargs: Additional context information
        """
        context = {
            "standard": standard,
            "requirement": requirement,
            **kwargs
        }
        
        self.collect_metric(
            metric_id=metric_id,
            metric_type=MetricType.COMPLIANCE,
            category=category,
            value=value,
            context=context
        )
    
    def get_metric_history(
        self,
        metric_id: str,
        time_window: Optional[timedelta] = None
    ) -> List[MetricData]:
        """
        Get metric history
        
        Args:
            metric_id: Metric identifier
            time_window: Time window for filtering
            
        Returns:
            List of metric data within the time window
        """
        with self._lock:
            if metric_id not in self.metrics_history:
                return []
            
            history = list(self.metrics_history[metric_id])
            
            if time_window:
                cutoff_time = time.time() - time_window.total_seconds()
                history = [m for m in history if m.timestamp >= cutoff_time]
            
            return history
    
    def get_current_metric(self, metric_id: str) -> Optional[float]:
        """
        Get current metric value
        
        Args:
            metric_id: Metric identifier
            
        Returns:
            Current metric value or None if not found
        """
        return self.current_metrics.get(metric_id)
    
    def get_benchmark_result(self, category: MetricCategory) -> Optional[BenchmarkResult]:
        """
        Get benchmark result for a category
        
        Args:
            category: Metric category
            
        Returns:
            Benchmark result or None if not available
        """
        return self.benchmark_results.get(category)
    
    def get_all_benchmark_results(self) -> Dict[MetricCategory, BenchmarkResult]:
        """
        Get all benchmark results
        
        Returns:
            Dictionary of all benchmark results
        """
        return self.benchmark_results.copy()
    
    def calculate_statistics(
        self,
        metric_id: str,
        time_window: Optional[timedelta] = None
    ) -> Dict[str, float]:
        """
        Calculate statistics for a metric
        
        Args:
            metric_id: Metric identifier
            time_window: Time window for calculation
            
        Returns:
            Dictionary of statistics
        """
        history = self.get_metric_history(metric_id, time_window)
        
        if not history:
            return {}
        
        values = [m.value for m in history]
        
        return {
            "count": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
            "latest": values[-1] if values else 0.0
        }
    
    def get_metric_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive metric summary
        
        Returns:
            Dictionary containing metric summary
        """
        with self._lock:
            summary = {
                "total_metrics": len(self.current_metrics),
                "metric_categories": {},
                "benchmark_results": {},
                "overall_score": 0.0
            }
            
            # Calculate category summaries
            for category in MetricCategory:
                category_metrics = [
                    m for metrics in self.metrics_history.values()
                    for m in metrics if m.category == category
                ]
                
                if category_metrics:
                    values = [m.value for m in category_metrics]
                    summary["metric_categories"][category.value] = {
                        "count": len(values),
                        "mean": statistics.mean(values),
                        "latest": values[-1] if values else 0.0
                    }
            
            # Add benchmark results
            for category, result in self.benchmark_results.items():
                summary["benchmark_results"][category.value] = {
                    "current_value": result.current_value,
                    "benchmark_value": result.benchmark_value,
                    "improvement_percentage": result.improvement_percentage,
                    "status": result.status
                }
            
            # Calculate overall score
            if self.benchmark_results:
                status_scores = {
                    "excellent": 100,
                    "good": 75,
                    "acceptable": 50,
                    "poor": 25
                }
                
                total_score = sum(
                    status_scores.get(result.status, 0)
                    for result in self.benchmark_results.values()
                )
                summary["overall_score"] = total_score / len(self.benchmark_results)
            
            return summary
    
    def _update_benchmark_result(self, category: MetricCategory, value: float) -> None:
        """
        Update benchmark result for a category
        
        Args:
            category: Metric category
            value: Current metric value
        """
        if category not in self.benchmark_thresholds:
            return
        
        thresholds = self.benchmark_thresholds[category]
        
        # Determine status based on thresholds
        if value <= thresholds["excellent"]:
            status = "excellent"
            benchmark_value = thresholds["excellent"]
        elif value <= thresholds["good"]:
            status = "good"
            benchmark_value = thresholds["good"]
        elif value <= thresholds["acceptable"]:
            status = "acceptable"
            benchmark_value = thresholds["acceptable"]
        else:
            status = "poor"
            benchmark_value = thresholds["poor"]
        
        # Calculate improvement percentage
        if benchmark_value > 0:
            improvement_percentage = ((benchmark_value - value) / benchmark_value) * 100
        else:
            improvement_percentage = 0.0
        
        # Create benchmark result
        result = BenchmarkResult(
            metric_category=category,
            current_value=value,
            benchmark_value=benchmark_value,
            improvement_percentage=improvement_percentage,
            status=status,
            timestamp=time.time()
        )
        
        self.benchmark_results[category] = result
    
    def export_metrics(self, file_path: str) -> None:
        """
        Export metrics to file
        
        Args:
            file_path: Path to export file
        """
        with self._lock:
            export_data = {
                "timestamp": time.time(),
                "current_metrics": self.current_metrics,
                "benchmark_results": {
                    category.value: {
                        "current_value": result.current_value,
                        "benchmark_value": result.benchmark_value,
                        "improvement_percentage": result.improvement_percentage,
                        "status": result.status,
                        "timestamp": result.timestamp
                    }
                    for category, result in self.benchmark_results.items()
                },
                "summary": self.get_metric_summary()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
    
    def import_metrics(self, file_path: str) -> None:
        """
        Import metrics from file
        
        Args:
            file_path: Path to import file
        """
        with open(file_path, 'r') as f:
            import_data = json.load(f)
        
        with self._lock:
            # Import current metrics
            self.current_metrics.update(import_data.get("current_metrics", {}))
            
            # Import benchmark results
            for category_str, result_data in import_data.get("benchmark_results", {}).items():
                try:
                    category = MetricCategory(category_str)
                    result = BenchmarkResult(
                        metric_category=category,
                        current_value=result_data["current_value"],
                        benchmark_value=result_data["benchmark_value"],
                        improvement_percentage=result_data["improvement_percentage"],
                        status=result_data["status"],
                        timestamp=result_data["timestamp"]
                    )
                    self.benchmark_results[category] = result
                except ValueError:
                    continue  # Skip invalid categories
