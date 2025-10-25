"""
Fault Tolerance Assessment System for MCP Security Framework

This module provides comprehensive fault tolerance analysis including:
- System resilience assessment
- Failure mode analysis
- Recovery time estimation
- Redundancy evaluation
- Single point of failure detection
- Disaster recovery planning
- Business continuity assessment
"""

import time
import math
import random
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import networkx as nx
from collections import defaultdict, deque
import numpy as np
from scipy import stats

from pydantic import BaseModel, Field


class FailureType(Enum):
    """Failure type enumeration"""
    HARDWARE_FAILURE = "hardware_failure"
    SOFTWARE_FAILURE = "software_failure"
    NETWORK_FAILURE = "network_failure"
    HUMAN_ERROR = "human_error"
    NATURAL_DISASTER = "natural_disaster"
    CYBER_ATTACK = "cyber_attack"
    POWER_OUTAGE = "power_outage"
    DATA_CORRUPTION = "data_corruption"


class ComponentType(Enum):
    """Component type enumeration"""
    AGENT = "agent"
    TOOL = "tool"
    NETWORK_NODE = "network_node"
    DATABASE = "database"
    API_SERVICE = "api_service"
    STORAGE = "storage"
    COMPUTE = "compute"
    SECURITY_SERVICE = "security_service"


class RecoveryStrategy(Enum):
    """Recovery strategy enumeration"""
    ACTIVE_STANDBY = "active_standby"
    PASSIVE_STANDBY = "passive_standby"
    LOAD_BALANCING = "load_balancing"
    REPLICATION = "replication"
    BACKUP_RESTORE = "backup_restore"
    FAILOVER = "failover"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    MANUAL_INTERVENTION = "manual_intervention"


@dataclass
class SystemComponent:
    """System component representation"""
    component_id: str
    component_type: ComponentType
    name: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)
    failure_rate: float = 0.001  # Failures per hour
    recovery_time: float = 3600  # Recovery time in seconds
    availability: float = 0.999  # Target availability
    criticality: float = 0.5  # Criticality score (0-1)
    redundancy_level: int = 1
    recovery_strategy: RecoveryStrategy = RecoveryStrategy.MANUAL_INTERVENTION
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureMode:
    """Failure mode analysis result"""
    component_id: str
    failure_type: FailureType
    probability: float
    impact: float
    detection_time: float
    recovery_time: float
    mitigation_measures: List[str]
    risk_score: float


@dataclass
class FaultToleranceMetrics:
    """Fault tolerance metrics"""
    system_availability: float
    mean_time_to_failure: float
    mean_time_to_recovery: float
    recovery_time_objective: float
    recovery_point_objective: float
    single_points_of_failure: List[str]
    redundancy_coverage: float
    disaster_recovery_capability: float


@dataclass
class ResilienceAssessment:
    """System resilience assessment"""
    overall_resilience: float
    component_resilience: Dict[str, float]
    failure_scenarios: List[Dict[str, Any]]
    recovery_capabilities: Dict[str, float]
    business_impact: Dict[str, float]
    recommendations: List[str]


class FaultToleranceAnalyzer:
    """
    Comprehensive fault tolerance analysis system
    
    Features:
    - System resilience assessment
    - Failure mode analysis
    - Recovery time estimation
    - Redundancy evaluation
    - Single point of failure detection
    - Disaster recovery planning
    - Business continuity assessment
    - Monte Carlo simulation
    """
    
    def __init__(self):
        """Initialize fault tolerance analyzer"""
        self.components: Dict[str, SystemComponent] = {}
        self.component_graph = nx.DiGraph()
        self.failure_modes: Dict[str, List[FailureMode]] = {}
        self.redundancy_groups: Dict[str, List[str]] = {}
        self.recovery_procedures: Dict[str, Dict[str, Any]] = {}
        
        # Analysis parameters
        self.simulation_runs = 10000
        self.time_horizon = 8760  # 1 year in hours
        self.availability_threshold = 0.99
        self.recovery_time_threshold = 3600  # 1 hour
        
        # Initialize default components
        self._initialize_default_components()
    
    def _initialize_default_components(self):
        """Initialize default system components"""
        # Core security components
        components = [
            SystemComponent(
                component_id="identity_manager",
                component_type=ComponentType.SECURITY_SERVICE,
                name="Identity Manager",
                description="Manages agent identities and authentication",
                failure_rate=0.0001,
                recovery_time=1800,
                availability=0.9999,
                criticality=0.9,
                redundancy_level=2,
                recovery_strategy=RecoveryStrategy.ACTIVE_STANDBY
            ),
            SystemComponent(
                component_id="trust_calculator",
                component_type=ComponentType.SECURITY_SERVICE,
                name="Trust Calculator",
                description="Calculates trust scores for agents",
                failure_rate=0.0002,
                recovery_time=900,
                availability=0.999,
                criticality=0.8,
                redundancy_level=1,
                recovery_strategy=RecoveryStrategy.PASSIVE_STANDBY
            ),
            SystemComponent(
                component_id="policy_engine",
                component_type=ComponentType.SECURITY_SERVICE,
                name="Policy Engine",
                description="Enforces security policies",
                failure_rate=0.0001,
                recovery_time=600,
                availability=0.9999,
                criticality=0.95,
                redundancy_level=2,
                recovery_strategy=RecoveryStrategy.ACTIVE_STANDBY
            ),
            SystemComponent(
                component_id="mcp_gateway",
                component_type=ComponentType.API_SERVICE,
                name="MCP Gateway",
                description="Gateway for MCP tool access",
                failure_rate=0.0005,
                recovery_time=300,
                availability=0.999,
                criticality=0.85,
                redundancy_level=3,
                recovery_strategy=RecoveryStrategy.LOAD_BALANCING
            ),
            SystemComponent(
                component_id="tool_registry",
                component_type=ComponentType.DATABASE,
                name="Tool Registry",
                description="Registry of available tools",
                failure_rate=0.0003,
                recovery_time=1200,
                availability=0.9995,
                criticality=0.7,
                redundancy_level=2,
                recovery_strategy=RecoveryStrategy.REPLICATION
            )
        ]
        
        for component in components:
            self.add_component(component)
    
    def add_component(self, component: SystemComponent) -> bool:
        """
        Add a system component
        
        Args:
            component: System component to add
            
        Returns:
            True if component added successfully
        """
        if component.component_id in self.components:
            return False
        
        self.components[component.component_id] = component
        self.component_graph.add_node(component.component_id, **component.metadata)
        
        # Add dependencies
        for dep_id in component.dependencies:
            if dep_id in self.components:
                self.component_graph.add_edge(dep_id, component.component_id)
                self.components[dep_id].dependents.append(component.component_id)
        
        return True
    
    def add_dependency(self, component_id: str, dependency_id: str) -> bool:
        """
        Add a dependency between components
        
        Args:
            component_id: Component that depends on dependency
            dependency_id: Component that is depended upon
            
        Returns:
            True if dependency added successfully
        """
        if component_id not in self.components or dependency_id not in self.components:
            return False
        
        if dependency_id not in self.components[component_id].dependencies:
            self.components[component_id].dependencies.append(dependency_id)
            self.components[dependency_id].dependents.append(component_id)
            self.component_graph.add_edge(dependency_id, component_id)
        
        return True
    
    def analyze_failure_modes(self, component_id: str) -> List[FailureMode]:
        """
        Analyze failure modes for a component
        
        Args:
            component_id: Component identifier
            
        Returns:
            List of failure modes
        """
        if component_id not in self.components:
            return []
        
        component = self.components[component_id]
        failure_modes = []
        
        # Hardware failure
        if component.component_type in [ComponentType.AGENT, ComponentType.COMPUTE, ComponentType.STORAGE]:
            failure_modes.append(FailureMode(
                component_id=component_id,
                failure_type=FailureType.HARDWARE_FAILURE,
                probability=component.failure_rate * 0.4,
                impact=component.criticality,
                detection_time=300,  # 5 minutes
                recovery_time=component.recovery_time,
                mitigation_measures=[
                    "Hardware redundancy",
                    "Predictive maintenance",
                    "Spare parts inventory"
                ],
                risk_score=component.failure_rate * 0.4 * component.criticality
            ))
        
        # Software failure
        failure_modes.append(FailureMode(
            component_id=component_id,
            failure_type=FailureType.SOFTWARE_FAILURE,
            probability=component.failure_rate * 0.3,
            impact=component.criticality,
            detection_time=180,  # 3 minutes
            recovery_time=component.recovery_time * 0.8,
            mitigation_measures=[
                "Software testing",
                "Version control",
                "Rollback procedures"
            ],
            risk_score=component.failure_rate * 0.3 * component.criticality
        ))
        
        # Network failure
        if component.component_type in [ComponentType.NETWORK_NODE, ComponentType.API_SERVICE]:
            failure_modes.append(FailureMode(
                component_id=component_id,
                failure_type=FailureType.NETWORK_FAILURE,
                probability=component.failure_rate * 0.2,
                impact=component.criticality,
                detection_time=60,  # 1 minute
                recovery_time=component.recovery_time * 0.6,
                mitigation_measures=[
                    "Network redundancy",
                    "Load balancing",
                    "Failover mechanisms"
                ],
                risk_score=component.failure_rate * 0.2 * component.criticality
            ))
        
        # Human error
        failure_modes.append(FailureMode(
            component_id=component_id,
            failure_type=FailureType.HUMAN_ERROR,
            probability=component.failure_rate * 0.05,
            impact=component.criticality * 0.8,
            detection_time=600,  # 10 minutes
            recovery_time=component.recovery_time * 1.2,
            mitigation_measures=[
                "Training programs",
                "Access controls",
                "Audit trails"
            ],
            risk_score=component.failure_rate * 0.05 * component.criticality * 0.8
        ))
        
        # Cyber attack
        if component.component_type == ComponentType.SECURITY_SERVICE:
            failure_modes.append(FailureMode(
                component_id=component_id,
                failure_type=FailureType.CYBER_ATTACK,
                probability=component.failure_rate * 0.05,
                impact=component.criticality * 1.2,
                detection_time=1800,  # 30 minutes
                recovery_time=component.recovery_time * 2.0,
                mitigation_measures=[
                    "Security monitoring",
                    "Intrusion detection",
                    "Incident response"
                ],
                risk_score=component.failure_rate * 0.05 * component.criticality * 1.2
            ))
        
        self.failure_modes[component_id] = failure_modes
        return failure_modes
    
    def identify_single_points_of_failure(self) -> List[str]:
        """
        Identify single points of failure in the system
        
        Returns:
            List of component IDs that are single points of failure
        """
        single_points = []
        
        for component_id, component in self.components.items():
            # Check if component has no redundancy
            if component.redundancy_level <= 1:
                # Check if component is critical
                if component.criticality > 0.7:
                    # Check if many components depend on it
                    dependents_count = len(component.dependents)
                    if dependents_count > 2:
                        single_points.append(component_id)
        
        return single_points
    
    def calculate_system_availability(self) -> float:
        """
        Calculate overall system availability
        
        Returns:
            System availability (0-1)
        """
        if not self.components:
            return 0.0
        
        # Calculate availability for each component considering redundancy
        component_availabilities = {}
        
        for component_id, component in self.components.items():
            # Basic availability calculation
            mtbf = 1.0 / component.failure_rate if component.failure_rate > 0 else float('inf')
            mttr = component.recovery_time / 3600  # Convert to hours
            
            # Availability with redundancy
            if component.redundancy_level > 1:
                # Parallel redundancy - at least one must work
                single_availability = mtbf / (mtbf + mttr)
                component_availability = 1.0 - (1.0 - single_availability) ** component.redundancy_level
            else:
                # No redundancy
                component_availability = mtbf / (mtbf + mttr)
            
            component_availabilities[component_id] = component_availability
        
        # Calculate system availability considering dependencies
        system_availability = self._calculate_dependent_availability(component_availabilities)
        
        return system_availability
    
    def _calculate_dependent_availability(self, component_availabilities: Dict[str, float]) -> float:
        """Calculate system availability considering component dependencies"""
        # For simplicity, use the minimum availability of critical path components
        critical_components = [comp_id for comp_id, comp in self.components.items() 
                             if comp.criticality > 0.8]
        
        if not critical_components:
            return 1.0
        
        # Find the critical path (longest dependency chain)
        critical_path_availability = 1.0
        
        for component_id in critical_components:
            component_availability = component_availabilities.get(component_id, 1.0)
            critical_path_availability *= component_availability
        
        return critical_path_availability
    
    def estimate_recovery_time(self, failed_components: List[str]) -> float:
        """
        Estimate recovery time for failed components
        
        Args:
            failed_components: List of failed component IDs
            
        Returns:
            Estimated recovery time in seconds
        """
        if not failed_components:
            return 0.0
        
        # Calculate recovery time considering dependencies
        recovery_times = []
        
        for component_id in failed_components:
            if component_id not in self.components:
                continue
            
            component = self.components[component_id]
            
            # Base recovery time
            base_recovery_time = component.recovery_time
            
            # Adjust based on recovery strategy
            strategy_multiplier = {
                RecoveryStrategy.ACTIVE_STANDBY: 0.1,
                RecoveryStrategy.PASSIVE_STANDBY: 0.3,
                RecoveryStrategy.LOAD_BALANCING: 0.2,
                RecoveryStrategy.REPLICATION: 0.4,
                RecoveryStrategy.BACKUP_RESTORE: 1.0,
                RecoveryStrategy.FAILOVER: 0.5,
                RecoveryStrategy.GRACEFUL_DEGRADATION: 0.8,
                RecoveryStrategy.MANUAL_INTERVENTION: 2.0
            }.get(component.recovery_strategy, 1.0)
            
            adjusted_recovery_time = base_recovery_time * strategy_multiplier
            recovery_times.append(adjusted_recovery_time)
        
        # Return maximum recovery time (bottleneck)
        return max(recovery_times) if recovery_times else 0.0
    
    def simulate_system_failures(self, simulation_duration: int = None) -> Dict[str, Any]:
        """
        Simulate system failures using Monte Carlo method
        
        Args:
            simulation_duration: Duration of simulation in hours
            
        Returns:
            Simulation results
        """
        if simulation_duration is None:
            simulation_duration = self.time_horizon
        
        results = {
            "total_failures": 0,
            "system_downtime": 0,
            "component_failures": defaultdict(int),
            "failure_cascades": 0,
            "recovery_times": [],
            "availability_samples": []
        }
        
        for _ in range(self.simulation_runs):
            # Simulate one year of operation
            current_time = 0
            system_downtime = 0
            component_states = {comp_id: True for comp_id in self.components.keys()}
            failure_events = []
            
            while current_time < simulation_duration:
                # Calculate next failure time for each component
                next_failures = {}
                
                for component_id, component in self.components.items():
                    if component_states[component_id]:  # Component is working
                        # Exponential distribution for failure times
                        failure_time = -math.log(random.random()) / component.failure_rate
                        next_failures[component_id] = current_time + failure_time
                
                if not next_failures:
                    break
                
                # Find next failure
                next_component = min(next_failures.keys(), key=lambda x: next_failures[x])
                next_failure_time = next_failures[next_component]
                
                # Update time
                current_time = next_failure_time
                
                if current_time >= simulation_duration:
                    break
                
                # Simulate failure
                component_states[next_component] = False
                results["component_failures"][next_component] += 1
                results["total_failures"] += 1
                
                # Check for cascade failures
                cascade_components = self._simulate_cascade_failure(next_component, component_states)
                if cascade_components:
                    results["failure_cascades"] += 1
                
                # Calculate recovery time
                failed_components = [comp_id for comp_id, state in component_states.items() if not state]
                recovery_time = self.estimate_recovery_time(failed_components)
                results["recovery_times"].append(recovery_time)
                
                # Calculate downtime
                downtime = min(recovery_time / 3600, simulation_duration - current_time)
                system_downtime += downtime
                
                # Restore components
                for comp_id in failed_components:
                    component_states[comp_id] = True
                
                current_time += recovery_time / 3600
            
            # Calculate availability for this simulation run
            availability = 1.0 - (system_downtime / simulation_duration)
            results["availability_samples"].append(availability)
        
        # Calculate statistics
        results["mean_availability"] = np.mean(results["availability_samples"])
        results["availability_std"] = np.std(results["availability_samples"])
        results["mean_recovery_time"] = np.mean(results["recovery_times"]) if results["recovery_times"] else 0
        results["total_system_downtime"] = sum(results["availability_samples"]) / len(results["availability_samples"])
        
        return results
    
    def _simulate_cascade_failure(self, failed_component: str, component_states: Dict[str, bool]) -> List[str]:
        """Simulate cascade failure from a failed component"""
        cascade_components = []
        
        # Find components that depend on the failed component
        for component_id, component in self.components.items():
            if (component_states[component_id] and  # Component is working
                failed_component in component.dependencies):  # Depends on failed component
                
                # Check if component can still function without the dependency
                if not self._can_function_without_dependency(component_id, failed_component, component_states):
                    component_states[component_id] = False
                    cascade_components.append(component_id)
        
        return cascade_components
    
    def _can_function_without_dependency(self, component_id: str, failed_dependency: str, 
                                       component_states: Dict[str, bool]) -> bool:
        """Check if a component can function without a specific dependency"""
        component = self.components[component_id]
        
        # Check if component has redundancy for this dependency
        if component.redundancy_level > 1:
            # Check if other dependencies are still working
            working_dependencies = sum(1 for dep in component.dependencies 
                                     if dep != failed_dependency and component_states.get(dep, False))
            
            if working_dependencies > 0:
                return True
        
        # Check if component has alternative paths
        return False
    
    def assess_disaster_recovery(self) -> Dict[str, Any]:
        """
        Assess disaster recovery capabilities
        
        Returns:
            Disaster recovery assessment
        """
        assessment = {
            "recovery_time_objective": 0,
            "recovery_point_objective": 0,
            "backup_coverage": 0,
            "geographic_redundancy": False,
            "data_replication": False,
            "failover_capability": False,
            "overall_score": 0
        }
        
        # Calculate RTO (Recovery Time Objective)
        max_recovery_time = max(comp.recovery_time for comp in self.components.values())
        assessment["recovery_time_objective"] = max_recovery_time
        
        # Calculate RPO (Recovery Point Objective) - assume 1 hour for now
        assessment["recovery_point_objective"] = 3600
        
        # Check backup coverage
        components_with_backup = sum(1 for comp in self.components.values() 
                                   if comp.recovery_strategy in [RecoveryStrategy.BACKUP_RESTORE, 
                                                               RecoveryStrategy.REPLICATION])
        assessment["backup_coverage"] = components_with_backup / len(self.components) if self.components else 0
        
        # Check geographic redundancy (simplified)
        assessment["geographic_redundancy"] = any(comp.redundancy_level > 1 for comp in self.components.values())
        
        # Check data replication
        assessment["data_replication"] = any(comp.recovery_strategy == RecoveryStrategy.REPLICATION 
                                           for comp in self.components.values())
        
        # Check failover capability
        assessment["failover_capability"] = any(comp.recovery_strategy in [RecoveryStrategy.FAILOVER, 
                                                                         RecoveryStrategy.ACTIVE_STANDBY]
                                              for comp in self.components.values())
        
        # Calculate overall score
        score_components = [
            assessment["backup_coverage"],
            1.0 if assessment["geographic_redundancy"] else 0.0,
            1.0 if assessment["data_replication"] else 0.0,
            1.0 if assessment["failover_capability"] else 0.0
        ]
        assessment["overall_score"] = sum(score_components) / len(score_components)
        
        return assessment
    
    def generate_resilience_recommendations(self) -> List[str]:
        """Generate recommendations for improving system resilience"""
        recommendations = []
        
        # Check for single points of failure
        single_points = self.identify_single_points_of_failure()
        if single_points:
            recommendations.append(f"Add redundancy for single points of failure: {', '.join(single_points)}")
        
        # Check availability
        system_availability = self.calculate_system_availability()
        if system_availability < self.availability_threshold:
            recommendations.append(f"Improve system availability (current: {system_availability:.3f}, target: {self.availability_threshold})")
        
        # Check recovery times
        long_recovery_components = [comp_id for comp_id, comp in self.components.items() 
                                  if comp.recovery_time > self.recovery_time_threshold]
        if long_recovery_components:
            recommendations.append(f"Reduce recovery time for components: {', '.join(long_recovery_components)}")
        
        # Check redundancy levels
        low_redundancy_components = [comp_id for comp_id, comp in self.components.items() 
                                   if comp.redundancy_level == 1 and comp.criticality > 0.7]
        if low_redundancy_components:
            recommendations.append(f"Increase redundancy for critical components: {', '.join(low_redundancy_components)}")
        
        # Check recovery strategies
        manual_recovery_components = [comp_id for comp_id, comp in self.components.items() 
                                    if comp.recovery_strategy == RecoveryStrategy.MANUAL_INTERVENTION and comp.criticality > 0.8]
        if manual_recovery_components:
            recommendations.append(f"Implement automated recovery for critical components: {', '.join(manual_recovery_components)}")
        
        return recommendations
    
    def get_fault_tolerance_metrics(self) -> FaultToleranceMetrics:
        """Get comprehensive fault tolerance metrics"""
        system_availability = self.calculate_system_availability()
        
        # Calculate MTBF and MTTR
        total_failure_rate = sum(comp.failure_rate for comp in self.components.values())
        mean_time_to_failure = 1.0 / total_failure_rate if total_failure_rate > 0 else float('inf')
        
        recovery_times = [comp.recovery_time for comp in self.components.values()]
        mean_time_to_recovery = sum(recovery_times) / len(recovery_times) if recovery_times else 0
        
        # Calculate RTO and RPO
        recovery_time_objective = max(recovery_times) if recovery_times else 0
        recovery_point_objective = 3600  # 1 hour default
        
        # Identify single points of failure
        single_points_of_failure = self.identify_single_points_of_failure()
        
        # Calculate redundancy coverage
        redundant_components = sum(1 for comp in self.components.values() if comp.redundancy_level > 1)
        redundancy_coverage = redundant_components / len(self.components) if self.components else 0
        
        # Assess disaster recovery capability
        dr_assessment = self.assess_disaster_recovery()
        disaster_recovery_capability = dr_assessment["overall_score"]
        
        return FaultToleranceMetrics(
            system_availability=system_availability,
            mean_time_to_failure=mean_time_to_failure,
            mean_time_to_recovery=mean_time_to_recovery,
            recovery_time_objective=recovery_time_objective,
            recovery_point_objective=recovery_point_objective,
            single_points_of_failure=single_points_of_failure,
            redundancy_coverage=redundancy_coverage,
            disaster_recovery_capability=disaster_recovery_capability
        )
    
    def export_analysis(self, file_path: str) -> bool:
        """Export fault tolerance analysis to file"""
        try:
            # Get metrics
            metrics = self.get_fault_tolerance_metrics()
            
            # Run simulation
            simulation_results = self.simulate_system_failures()
            
            # Get disaster recovery assessment
            dr_assessment = self.assess_disaster_recovery()
            
            # Get recommendations
            recommendations = self.generate_resilience_recommendations()
            
            export_data = {
                "components": {
                    comp_id: {
                        "component_id": comp.component_id,
                        "component_type": comp.component_type.value,
                        "name": comp.name,
                        "description": comp.description,
                        "dependencies": comp.dependencies,
                        "dependents": comp.dependents,
                        "failure_rate": comp.failure_rate,
                        "recovery_time": comp.recovery_time,
                        "availability": comp.availability,
                        "criticality": comp.criticality,
                        "redundancy_level": comp.redundancy_level,
                        "recovery_strategy": comp.recovery_strategy.value,
                        "metadata": comp.metadata
                    }
                    for comp_id, comp in self.components.items()
                },
                "failure_modes": {
                    comp_id: [
                        {
                            "component_id": fm.component_id,
                            "failure_type": fm.failure_type.value,
                            "probability": fm.probability,
                            "impact": fm.impact,
                            "detection_time": fm.detection_time,
                            "recovery_time": fm.recovery_time,
                            "mitigation_measures": fm.mitigation_measures,
                            "risk_score": fm.risk_score
                        }
                        for fm in failure_modes
                    ]
                    for comp_id, failure_modes in self.failure_modes.items()
                },
                "metrics": {
                    "system_availability": metrics.system_availability,
                    "mean_time_to_failure": metrics.mean_time_to_failure,
                    "mean_time_to_recovery": metrics.mean_time_to_recovery,
                    "recovery_time_objective": metrics.recovery_time_objective,
                    "recovery_point_objective": metrics.recovery_point_objective,
                    "single_points_of_failure": metrics.single_points_of_failure,
                    "redundancy_coverage": metrics.redundancy_coverage,
                    "disaster_recovery_capability": metrics.disaster_recovery_capability
                },
                "simulation_results": simulation_results,
                "disaster_recovery_assessment": dr_assessment,
                "recommendations": recommendations,
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting fault tolerance analysis: {e}")
            return False
