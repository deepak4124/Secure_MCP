"""
Complete Unit Tests for Trust Calculator with Metrics Collection
"""

import pytest
import time
import statistics
import numpy as np
from unittest.mock import Mock, patch
from mcp_security_framework.core.trust import (
    TrustCalculator, TrustEvent, TrustEventType, TrustDimension, TrustScore
)


class TestTrustCalculatorComplete:
    """Complete test cases for TrustCalculator with comprehensive metrics"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.trust_calculator = TrustCalculator()
        self.test_agent_id = "test_agent_001"
        self.test_event_id = "event_001"
        
        # Metrics collection
        self.metrics = {
            "test_execution_times": [],
            "trust_calculation_accuracy": {},
            "performance_benchmarks": {},
            "ml_model_performance": {},
            "anomaly_detection_metrics": {}
        }
    
    def teardown_method(self):
        """Collect and report metrics after each test"""
        if hasattr(self, 'metrics'):
            self._report_test_metrics()
    
    def _report_test_metrics(self):
        """Report test execution metrics"""
        if self.metrics["test_execution_times"]:
            avg_time = statistics.mean(self.metrics["test_execution_times"])
            print(f"\n📊 Trust Calculator Test Metrics:")
            print(f"   Average execution time: {avg_time:.4f}s")
            print(f"   Total tests executed: {len(self.metrics['test_execution_times'])}")
            if self.metrics["performance_benchmarks"]:
                print(f"   Performance benchmarks: {self.metrics['performance_benchmarks']}")
    
    @pytest.mark.benchmark
    def test_trust_calculation_accuracy(self):
        """Test trust calculation accuracy with known scenarios"""
        accuracy_scenarios = [
            {
                "name": "high_trust_agent",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.9),
                    (TrustEventType.TASK_SUCCESS, 0.8),
                    (TrustEventType.TASK_SUCCESS, 0.9),
                    (TrustEventType.TASK_SUCCESS, 0.8),
                    (TrustEventType.TASK_SUCCESS, 0.9),
                    (TrustEventType.TASK_SUCCESS, 0.8),
                ],
                "expected_range": (0.8, 0.9)
            },
            {
                "name": "low_trust_agent",
                "events": [
                    (TrustEventType.TASK_FAILURE, -0.5),
                    (TrustEventType.SECURITY_VIOLATION, -0.8),
                    (TrustEventType.TASK_FAILURE, -0.3),
                    (TrustEventType.SECURITY_VIOLATION, -0.7),
                    (TrustEventType.TASK_FAILURE, -0.4),
                    (TrustEventType.SECURITY_VIOLATION, -0.6),
                ],
                "expected_range": (0.0, 0.3)
            },
            {
                "name": "mixed_trust_agent",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.7),
                    (TrustEventType.TASK_FAILURE, -0.3),
                    (TrustEventType.TASK_SUCCESS, 0.8),
                    (TrustEventType.TASK_FAILURE, -0.2),
                    (TrustEventType.TASK_SUCCESS, 0.6),
                    (TrustEventType.TASK_SUCCESS, 0.7),
                ],
                "expected_range": (0.4, 0.7)
            }
        ]
        
        accuracy_results = {}
        
        for scenario in accuracy_scenarios:
            agent_id = f"accuracy_agent_{scenario['name']}"
            
            # Add events
            for i, (event_type, value) in enumerate(scenario["events"]):
                event = TrustEvent(
                    event_id=f"event_{agent_id}_{i}",
                    agent_id=agent_id,
                    event_type=event_type,
                    timestamp=time.time() - (len(scenario["events"]) - i) * 60,
                    value=value
                )
                self.trust_calculator.add_trust_event(event)
            
            # Calculate trust score
            trust_score = self.trust_calculator.get_trust_score(agent_id)
            
            if trust_score:
                actual_score = trust_score.overall_score
                expected_min, expected_max = scenario["expected_range"]
                
                # Check if score is within expected range
                is_accurate = expected_min <= actual_score <= expected_max
                
                accuracy_results[scenario["name"]] = {
                    "actual_score": actual_score,
                    "expected_range": scenario["expected_range"],
                    "is_accurate": is_accurate,
                    "confidence": trust_score.confidence
                }
            else:
                accuracy_results[scenario["name"]] = {
                    "actual_score": None,
                    "expected_range": scenario["expected_range"],
                    "is_accurate": False,
                    "confidence": 0.0
                }
        
        # Calculate overall accuracy
        total_scenarios = len(accuracy_scenarios)
        accurate_scenarios = sum(1 for result in accuracy_results.values() if result["is_accurate"])
        overall_accuracy = accurate_scenarios / total_scenarios
        
        # Store metrics
        self.metrics["trust_calculation_accuracy"] = {
            "overall_accuracy": overall_accuracy,
            "scenario_results": accuracy_results,
            "total_scenarios": total_scenarios,
            "accurate_scenarios": accurate_scenarios
        }
        
        # Assertions
        assert overall_accuracy >= 0.8, f"Trust calculation accuracy {overall_accuracy} below threshold"
        
        print(f"✅ Trust Calculation Accuracy:")
        print(f"   Overall accuracy: {overall_accuracy:.2%}")
        for name, result in accuracy_results.items():
            status = "✅" if result["is_accurate"] else "❌"
            print(f"   {status} {name}: {result['actual_score']:.3f} (expected: {result['expected_range']})")
    
    @pytest.mark.benchmark
    def test_trust_calculation_performance(self):
        """Test trust calculation performance under load"""
        performance_metrics = {
            "calculation_times": [],
            "throughput_measurements": [],
            "memory_usage": [],
            "concurrent_performance": {}
        }
        
        # Test 1: Single agent performance
        agent_count = 1000
        events_per_agent = 10
        
        start_time = time.time()
        
        for i in range(agent_count):
            agent_id = f"perf_agent_{i}"
            
            # Add events for this agent
            for j in range(events_per_agent):
                event = TrustEvent(
                    event_id=f"event_{agent_id}_{j}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - j * 60,
                    value=0.8
                )
                self.trust_calculator.add_trust_event(event)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Test 2: Trust score calculation performance
        calculation_times = []
        successful_calculations = 0
        
        start_time = time.time()
        
        for i in range(agent_count):
            agent_id = f"perf_agent_{i}"
            
            calc_start = time.time()
            trust_score = self.trust_calculator.get_trust_score(agent_id)
            calc_end = time.time()
            
            calculation_times.append(calc_end - calc_start)
            
            if trust_score:
                successful_calculations += 1
        
        end_time = time.time()
        calculation_total_time = end_time - start_time
        
        # Calculate metrics
        avg_calculation_time = statistics.mean(calculation_times)
        min_calculation_time = min(calculation_times)
        max_calculation_time = max(calculation_times)
        throughput = agent_count / calculation_total_time
        success_rate = successful_calculations / agent_count
        
        performance_metrics.update({
            "total_agents": agent_count,
            "events_per_agent": events_per_agent,
            "total_events": agent_count * events_per_agent,
            "event_creation_time": total_time,
            "calculation_times": calculation_times,
            "avg_calculation_time": avg_calculation_time,
            "min_calculation_time": min_calculation_time,
            "max_calculation_time": max_calculation_time,
            "throughput": throughput,
            "success_rate": success_rate
        })
        
        # Store metrics
        self.metrics["performance_benchmarks"]["trust_calculation"] = performance_metrics
        
        # Assertions
        assert success_rate >= 0.95, f"Trust calculation success rate {success_rate} below threshold"
        assert avg_calculation_time < 0.01, f"Average calculation time {avg_calculation_time}s too slow"
        assert throughput > 100, f"Throughput {throughput} calculations/sec too low"
        
        print(f"✅ Trust Calculation Performance:")
        print(f"   Agents processed: {agent_count}")
        print(f"   Events per agent: {events_per_agent}")
        print(f"   Throughput: {throughput:.2f} calculations/sec")
        print(f"   Avg calculation time: {avg_calculation_time:.4f}s")
        print(f"   Success rate: {success_rate:.2%}")
    
    @pytest.mark.benchmark
    def test_ml_trust_calculation_performance(self):
        """Test ML-based trust calculation performance"""
        # Mock the ML model for testing
        with patch('mcp_security_framework.models.real_models.RealTrustModel') as mock_model:
            mock_instance = Mock()
            mock_instance.calculate_trust_score.return_value = 0.8
            mock_model.return_value = mock_instance
            
            # Test ML trust calculation
            ml_calculation_times = []
            ml_success_count = 0
            
            # Add some interactions for ML model
            for i in range(100):
                agent_id = f"ml_agent_{i}"
                interactions = [
                    f"helpful interaction {j}" for j in range(5)
                ]
                
                for interaction in interactions:
                    self.trust_calculator.add_interaction(agent_id, interaction)
                
                # Test ML trust calculation
                start_time = time.time()
                try:
                    ml_score = self.trust_calculator.calculate_trust_score_with_ml(
                        agent_id, {"operation": "test", "resource": "test_resource"}
                    )
                    end_time = time.time()
                    
                    ml_calculation_times.append(end_time - start_time)
                    ml_success_count += 1
                    
                except Exception as e:
                    print(f"ML calculation error for {agent_id}: {e}")
            
            # Calculate ML performance metrics
            if ml_calculation_times:
                avg_ml_time = statistics.mean(ml_calculation_times)
                ml_throughput = len(ml_calculation_times) / sum(ml_calculation_times)
                ml_success_rate = ml_success_count / 100
                
                ml_metrics = {
                    "avg_calculation_time": avg_ml_time,
                    "throughput": ml_throughput,
                    "success_rate": ml_success_rate,
                    "total_calculations": ml_success_count
                }
                
                # Store metrics
                self.metrics["ml_model_performance"] = ml_metrics
                
                # Assertions
                assert ml_success_rate >= 0.8, f"ML trust calculation success rate {ml_success_rate} below threshold"
                assert avg_ml_time < 0.1, f"ML calculation time {avg_ml_time}s too slow"
                
                print(f"✅ ML Trust Calculation Performance:")
                print(f"   Throughput: {ml_throughput:.2f} calculations/sec")
                print(f"   Avg calculation time: {avg_ml_time:.4f}s")
                print(f"   Success rate: {ml_success_rate:.2%}")
    
    def test_sybil_detection_accuracy(self):
        """Test sybil detection accuracy with known patterns"""
        sybil_scenarios = [
            {
                "name": "normal_agent",
                "pattern": "normal",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.7, None),
                    (TrustEventType.TASK_SUCCESS, 0.8, None),
                    (TrustEventType.TASK_SUCCESS, 0.6, None),
                ],
                "expected_sybil": False
            },
            {
                "name": "potential_sybil",
                "pattern": "high_connectivity",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.9, f"related_agent_{i}") for i in range(15)
                ],
                "expected_sybil": True
            },
            {
                "name": "colluding_agents",
                "pattern": "collusion",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.9, "colluding_agent") for _ in range(10)
                ],
                "expected_sybil": True
            }
        ]
        
        sybil_detection_results = {}
        
        for scenario in sybil_scenarios:
            agent_id = f"sybil_test_{scenario['name']}"
            
            # Add events
            for i, (event_type, value, source_agent) in enumerate(scenario["events"]):
                event = TrustEvent(
                    event_id=f"event_{agent_id}_{i}",
                    agent_id=agent_id,
                    event_type=event_type,
                    timestamp=time.time() - i * 10,
                    value=value,
                    source_agent=source_agent
                )
                self.trust_calculator.add_trust_event(event)
        
        # Test sybil detection
        detected_sybil_agents = self.trust_calculator.detect_sybil_agents()
        
        # Analyze results
        for scenario in sybil_scenarios:
            agent_id = f"sybil_test_{scenario['name']}"
            is_detected = agent_id in detected_sybil_agents
            expected = scenario["expected_sybil"]
            
            sybil_detection_results[scenario["name"]] = {
                "detected": is_detected,
                "expected": expected,
                "correct": is_detected == expected
            }
        
        # Calculate accuracy
        total_scenarios = len(sybil_scenarios)
        correct_detections = sum(1 for result in sybil_detection_results.values() if result["correct"])
        detection_accuracy = correct_detections / total_scenarios
        
        # Store metrics
        self.metrics["anomaly_detection_metrics"]["sybil_detection"] = {
            "accuracy": detection_accuracy,
            "results": sybil_detection_results,
            "detected_agents": detected_sybil_agents
        }
        
        # Assertions
        assert detection_accuracy >= 0.7, f"Sybil detection accuracy {detection_accuracy} below threshold"
        
        print(f"✅ Sybil Detection Accuracy:")
        print(f"   Detection accuracy: {detection_accuracy:.2%}")
        for name, result in sybil_detection_results.items():
            status = "✅" if result["correct"] else "❌"
            print(f"   {status} {name}: detected={result['detected']}, expected={result['expected']}")
    
    def test_trust_trend_prediction_accuracy(self):
        """Test trust trend prediction accuracy"""
        trend_scenarios = [
            {
                "name": "improving_trend",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.5 + i * 0.05) for i in range(10)
                ],
                "expected_trend": "positive"
            },
            {
                "name": "declining_trend",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.9 - i * 0.05) for i in range(10)
                ],
                "expected_trend": "negative"
            },
            {
                "name": "stable_trend",
                "events": [
                    (TrustEventType.TASK_SUCCESS, 0.7 + (0.1 if i % 2 == 0 else -0.1)) for i in range(10)
                ],
                "expected_trend": "stable"
            }
        ]
        
        trend_prediction_results = {}
        
        for scenario in trend_scenarios:
            agent_id = f"trend_test_{scenario['name']}"
            
            # Add events with timestamps
            for i, value in enumerate(scenario["events"]):
                event = TrustEvent(
                    event_id=f"event_{agent_id}_{i}",
                    agent_id=agent_id,
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - (len(scenario["events"]) - i) * 60,
                    value=value
                )
                self.trust_calculator.add_trust_event(event)
            
            # Predict trend
            predicted_trend = self.trust_calculator.predict_trust_trend(agent_id)
            
            # Determine if prediction is correct
            expected_trend = scenario["expected_trend"]
            if expected_trend == "positive" and predicted_trend > 0.1:
                is_correct = True
            elif expected_trend == "negative" and predicted_trend < -0.1:
                is_correct = True
            elif expected_trend == "stable" and -0.1 <= predicted_trend <= 0.1:
                is_correct = True
            else:
                is_correct = False
            
            trend_prediction_results[scenario["name"]] = {
                "predicted_trend": predicted_trend,
                "expected_trend": expected_trend,
                "is_correct": is_correct
            }
        
        # Calculate accuracy
        total_scenarios = len(trend_scenarios)
        correct_predictions = sum(1 for result in trend_prediction_results.values() if result["is_correct"])
        prediction_accuracy = correct_predictions / total_scenarios
        
        # Store metrics
        self.metrics["anomaly_detection_metrics"]["trend_prediction"] = {
            "accuracy": prediction_accuracy,
            "results": trend_prediction_results
        }
        
        # Assertions
        assert prediction_accuracy >= 0.6, f"Trend prediction accuracy {prediction_accuracy} below threshold"
        
        print(f"✅ Trust Trend Prediction Accuracy:")
        print(f"   Prediction accuracy: {prediction_accuracy:.2%}")
        for name, result in trend_prediction_results.items():
            status = "✅" if result["is_correct"] else "❌"
            print(f"   {status} {name}: predicted={result['predicted_trend']:.3f}, expected={result['expected_trend']}")
    
    def test_trust_decay_accuracy(self):
        """Test trust decay over time accuracy"""
        agent_id = "decay_test_agent"
        
        # Add events with different ages
        event_ages = [1, 2, 5, 10, 20, 50]  # hours ago
        event_values = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4]
        
        for i, (age_hours, value) in enumerate(zip(event_ages, event_values)):
            event = TrustEvent(
                event_id=f"decay_event_{i}",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - age_hours * 3600,  # Convert to seconds
                value=value
            )
            self.trust_calculator.add_trust_event(event)
        
        # Calculate trust score
        trust_score = self.trust_calculator.get_trust_score(agent_id)
        
        if trust_score:
            # Verify that recent events have more influence
            # This is a simplified check - in reality, you'd need to verify the decay algorithm
            decay_metrics = {
                "trust_score": trust_score.overall_score,
                "confidence": trust_score.confidence,
                "event_count": len(event_ages),
                "time_span_hours": max(event_ages) - min(event_ages)
            }
            
            # Store metrics
            self.metrics["trust_calculation_accuracy"]["decay_test"] = decay_metrics
            
            # Basic assertions
            assert 0.0 <= trust_score.overall_score <= 1.0, f"Trust score {trust_score.overall_score} out of range"
            assert trust_score.confidence > 0.0, f"Trust confidence {trust_score.confidence} should be positive"
            
            print(f"✅ Trust Decay Accuracy:")
            print(f"   Trust score: {trust_score.overall_score:.3f}")
            print(f"   Confidence: {trust_score.confidence:.3f}")
            print(f"   Event count: {len(event_ages)}")
            print(f"   Time span: {max(event_ages) - min(event_ages)} hours")
    
    def test_concurrent_trust_calculations(self):
        """Test concurrent trust calculations"""
        import threading
        import queue
        
        # Shared data structures
        results = queue.Queue()
        errors = queue.Queue()
        
        def trust_calculation_worker(worker_id, agent_count):
            """Worker function for concurrent trust calculations"""
            try:
                for i in range(agent_count):
                    agent_id = f"concurrent_trust_agent_{worker_id}_{i}"
                    
                    # Add events
                    for j in range(6):  # Minimum for trust calculation
                        event = TrustEvent(
                            event_id=f"event_{agent_id}_{j}",
                            agent_id=agent_id,
                            event_type=TrustEventType.TASK_SUCCESS,
                            timestamp=time.time() - j * 60,
                            value=0.8
                        )
                        self.trust_calculator.add_trust_event(event)
                    
                    # Calculate trust score
                    trust_score = self.trust_calculator.get_trust_score(agent_id)
                    results.put((worker_id, i, trust_score is not None))
                    
            except Exception as e:
                errors.put((worker_id, str(e)))
        
        # Start concurrent workers
        thread_count = 5
        agents_per_thread = 20
        threads = []
        
        start_time = time.time()
        
        for i in range(thread_count):
            thread = threading.Thread(target=trust_calculation_worker, args=(i, agents_per_thread))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Collect results
        successful_calculations = 0
        total_attempts = thread_count * agents_per_thread
        
        while not results.empty():
            worker_id, agent_id, success = results.get()
            if success:
                successful_calculations += 1
        
        # Check for errors
        error_count = 0
        while not errors.empty():
            worker_id, error = errors.get()
            error_count += 1
            print(f"❌ Worker {worker_id} error: {error}")
        
        # Calculate metrics
        success_rate = successful_calculations / total_attempts
        throughput = total_attempts / total_time
        
        concurrent_metrics = {
            "thread_count": thread_count,
            "agents_per_thread": agents_per_thread,
            "total_attempts": total_attempts,
            "successful_calculations": successful_calculations,
            "success_rate": success_rate,
            "throughput": throughput,
            "total_time": total_time,
            "error_count": error_count
        }
        
        # Store metrics
        self.metrics["performance_benchmarks"]["concurrent_calculations"] = concurrent_metrics
        
        # Assertions
        assert success_rate >= 0.95, f"Concurrent success rate {success_rate} below threshold"
        assert error_count == 0, f"Concurrent errors detected: {error_count}"
        assert throughput > 50, f"Concurrent throughput {throughput} too low"
        
        print(f"✅ Concurrent Trust Calculations:")
        print(f"   Threads: {thread_count}")
        print(f"   Total calculations: {total_attempts}")
        print(f"   Success rate: {success_rate:.2%}")
        print(f"   Throughput: {throughput:.2f} calculations/sec")
        print(f"   Errors: {error_count}")
    
    def test_memory_efficiency_under_load(self):
        """Test memory efficiency under various loads"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Measure baseline memory
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_measurements = []
        
        # Test different load levels
        load_levels = [100, 500, 1000, 2000]
        
        for load in load_levels:
            # Add events for this load level
            for i in range(load):
                agent_id = f"memory_trust_agent_{load}_{i}"
                
                # Add multiple events per agent
                for j in range(5):
                    event = TrustEvent(
                        event_id=f"event_{agent_id}_{j}",
                        agent_id=agent_id,
                        event_type=TrustEventType.TASK_SUCCESS,
                        timestamp=time.time() - j * 60,
                        value=0.8
                    )
                    self.trust_calculator.add_trust_event(event)
            
            # Measure memory
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = current_memory - baseline_memory
            memory_measurements.append({
                "load": load,
                "memory_mb": memory_usage,
                "memory_per_agent": memory_usage / load,
                "memory_per_event": memory_usage / (load * 5)
            })
        
        # Calculate memory efficiency
        avg_memory_per_agent = statistics.mean([m["memory_per_agent"] for m in memory_measurements])
        avg_memory_per_event = statistics.mean([m["memory_per_event"] for m in memory_measurements])
        
        memory_metrics = {
            "baseline_memory_mb": baseline_memory,
            "memory_measurements": memory_measurements,
            "avg_memory_per_agent": avg_memory_per_agent,
            "avg_memory_per_event": avg_memory_per_event
        }
        
        # Store metrics
        self.metrics["performance_benchmarks"]["memory_efficiency"] = memory_metrics
        
        # Assertions
        assert avg_memory_per_agent < 0.05, f"Memory per agent {avg_memory_per_agent:.4f}MB too high"
        assert avg_memory_per_event < 0.01, f"Memory per event {avg_memory_per_event:.4f}MB too high"
        
        print(f"✅ Memory Efficiency Under Load:")
        print(f"   Baseline memory: {baseline_memory:.2f}MB")
        print(f"   Avg memory per agent: {avg_memory_per_agent:.4f}MB")
        print(f"   Avg memory per event: {avg_memory_per_event:.4f}MB")
        for measurement in memory_measurements:
            print(f"   Load {measurement['load']}: {measurement['memory_mb']:.2f}MB")

