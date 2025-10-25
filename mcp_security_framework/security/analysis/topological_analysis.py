"""
Topological Analysis for MCP Security Framework

This module provides comprehensive network structure security analysis including:
- Network topology analysis
- Centrality metrics calculation
- Vulnerability propagation analysis
- Attack path identification
- Network resilience assessment
- Community detection and analysis
"""

import time
import math
import networkx as nx
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, Counter
import numpy as np
from scipy import stats

from pydantic import BaseModel, Field


class NetworkMetric(Enum):
    """Network metric enumeration"""
    DEGREE_CENTRALITY = "degree_centrality"
    BETWEENNESS_CENTRALITY = "betweenness_centrality"
    CLOSENESS_CENTRALITY = "closeness_centrality"
    EIGENVECTOR_CENTRALITY = "eigenvector_centrality"
    PAGERANK = "pagerank"
    CLUSTERING_COEFFICIENT = "clustering_coefficient"
    ASSORTATIVITY = "assortativity"


class VulnerabilityType(Enum):
    """Vulnerability type enumeration"""
    SINGLE_POINT_FAILURE = "single_point_failure"
    CASCADE_FAILURE = "cascade_failure"
    ISOLATION_VULNERABILITY = "isolation_vulnerability"
    CONCENTRATION_RISK = "concentration_risk"
    PATH_VULNERABILITY = "path_vulnerability"


class AttackPathType(Enum):
    """Attack path type enumeration"""
    SHORTEST_PATH = "shortest_path"
    HIGH_TRUST_PATH = "high_trust_path"
    LOW_SECURITY_PATH = "low_security_path"
    PRIVILEGE_ESCALATION_PATH = "privilege_escalation_path"
    LATERAL_MOVEMENT_PATH = "lateral_movement_path"


@dataclass
class NetworkNode:
    """Network node representation"""
    node_id: str
    node_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    security_level: float = 0.5
    trust_score: float = 0.5
    vulnerability_score: float = 0.0


@dataclass
class NetworkEdge:
    """Network edge representation"""
    source: str
    target: str
    edge_type: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    security_level: float = 0.5
    trust_score: float = 0.5


@dataclass
class TopologicalVulnerability:
    """Topological vulnerability assessment result"""
    vulnerability_type: VulnerabilityType
    affected_nodes: List[str]
    severity: float
    description: str
    impact_radius: int
    mitigation_strategies: List[str]
    risk_score: float


@dataclass
class AttackPath:
    """Attack path representation"""
    path_id: str
    path_type: AttackPathType
    nodes: List[str]
    edges: List[Tuple[str, str]]
    total_risk: float
    path_length: int
    security_weaknesses: List[str]
    exploitation_difficulty: float


@dataclass
class NetworkResilience:
    """Network resilience assessment"""
    overall_resilience: float
    connectivity_resilience: float
    redundancy_score: float
    fault_tolerance: float
    recovery_capability: float
    critical_nodes: List[str]
    weak_links: List[Tuple[str, str]]


@dataclass
class CommunityStructure:
    """Community structure analysis result"""
    communities: Dict[int, List[str]]
    modularity: float
    community_count: int
    largest_community_size: int
    community_connectivity: Dict[int, float]
    inter_community_risk: float


class TopologicalAnalyzer:
    """
    Comprehensive topological analysis system for network security
    
    Features:
    - Network topology analysis
    - Centrality metrics calculation
    - Vulnerability propagation analysis
    - Attack path identification
    - Network resilience assessment
    - Community detection and analysis
    - Dynamic network monitoring
    """
    
    def __init__(self):
        """Initialize topological analyzer"""
        self.network = nx.Graph()
        self.node_data: Dict[str, NetworkNode] = {}
        self.edge_data: Dict[Tuple[str, str], NetworkEdge] = {}
        self.metrics_cache: Dict[str, Dict[str, float]] = {}
        self.vulnerabilities: List[TopologicalVulnerability] = []
        self.attack_paths: List[AttackPath] = []
        self.resilience_profile: Optional[NetworkResilience] = None
        self.community_structure: Optional[CommunityStructure] = None
        
        # Analysis parameters
        self.centrality_threshold = 0.7
        self.vulnerability_threshold = 0.6
        self.resilience_threshold = 0.5
    
    def add_node(self, node: NetworkNode) -> bool:
        """
        Add a node to the network
        
        Args:
            node: Network node to add
            
        Returns:
            True if node added successfully
        """
        if node.node_id in self.node_data:
            return False
        
        self.node_data[node.node_id] = node
        self.network.add_node(node.node_id, **node.properties)
        self._invalidate_cache()
        return True
    
    def add_edge(self, edge: NetworkEdge) -> bool:
        """
        Add an edge to the network
        
        Args:
            edge: Network edge to add
            
        Returns:
            True if edge added successfully
        """
        edge_key = (edge.source, edge.target)
        if edge_key in self.edge_data:
            return False
        
        self.edge_data[edge_key] = edge
        self.network.add_edge(edge.source, edge.target, weight=edge.weight, **edge.properties)
        self._invalidate_cache()
        return True
    
    def remove_node(self, node_id: str) -> bool:
        """
        Remove a node from the network
        
        Args:
            node_id: Node identifier
            
        Returns:
            True if node removed successfully
        """
        if node_id not in self.node_data:
            return False
        
        del self.node_data[node_id]
        self.network.remove_node(node_id)
        self._invalidate_cache()
        return True
    
    def remove_edge(self, source: str, target: str) -> bool:
        """
        Remove an edge from the network
        
        Args:
            source: Source node identifier
            target: Target node identifier
            
        Returns:
            True if edge removed successfully
        """
        edge_key = (source, target)
        if edge_key not in self.edge_data:
            return False
        
        del self.edge_data[edge_key]
        self.network.remove_edge(source, target)
        self._invalidate_cache()
        return True
    
    def calculate_centrality_metrics(self) -> Dict[str, Dict[str, float]]:
        """
        Calculate centrality metrics for all nodes
        
        Returns:
            Dictionary of centrality metrics by node
        """
        if not self.network.nodes():
            return {}
        
        metrics = {}
        
        # Degree centrality
        degree_centrality = nx.degree_centrality(self.network)
        metrics[NetworkMetric.DEGREE_CENTRALITY.value] = degree_centrality
        
        # Betweenness centrality
        betweenness_centrality = nx.betweenness_centrality(self.network)
        metrics[NetworkMetric.BETWEENNESS_CENTRALITY.value] = betweenness_centrality
        
        # Closeness centrality
        closeness_centrality = nx.closeness_centrality(self.network)
        metrics[NetworkMetric.CLOSENESS_CENTRALITY.value] = closeness_centrality
        
        # Eigenvector centrality
        try:
            eigenvector_centrality = nx.eigenvector_centrality(self.network, max_iter=1000)
            metrics[NetworkMetric.EIGENVECTOR_CENTRALITY.value] = eigenvector_centrality
        except nx.PowerIterationFailedConvergence:
            # Fallback to degree centrality if eigenvector fails
            metrics[NetworkMetric.EIGENVECTOR_CENTRALITY.value] = degree_centrality
        
        # PageRank
        pagerank = nx.pagerank(self.network)
        metrics[NetworkMetric.PAGERANK.value] = pagerank
        
        # Clustering coefficient
        clustering_coefficient = nx.clustering(self.network)
        metrics[NetworkMetric.CLUSTERING_COEFFICIENT.value] = clustering_coefficient
        
        self.metrics_cache = metrics
        return metrics
    
    def identify_critical_nodes(self, threshold: float = None) -> List[str]:
        """
        Identify critical nodes in the network
        
        Args:
            threshold: Centrality threshold for critical nodes
            
        Returns:
            List of critical node IDs
        """
        if threshold is None:
            threshold = self.centrality_threshold
        
        metrics = self.calculate_centrality_metrics()
        critical_nodes = set()
        
        # Check each centrality metric
        for metric_name, node_scores in metrics.items():
            for node_id, score in node_scores.items():
                if score >= threshold:
                    critical_nodes.add(node_id)
        
        return list(critical_nodes)
    
    def analyze_vulnerabilities(self) -> List[TopologicalVulnerability]:
        """
        Analyze topological vulnerabilities in the network
        
        Returns:
            List of identified vulnerabilities
        """
        vulnerabilities = []
        
        # Single point of failure analysis
        spf_vulns = self._analyze_single_point_failures()
        vulnerabilities.extend(spf_vulns)
        
        # Cascade failure analysis
        cf_vulns = self._analyze_cascade_failures()
        vulnerabilities.extend(cf_vulns)
        
        # Isolation vulnerability analysis
        iso_vulns = self._analyze_isolation_vulnerabilities()
        vulnerabilities.extend(iso_vulns)
        
        # Concentration risk analysis
        cr_vulns = self._analyze_concentration_risks()
        vulnerabilities.extend(cr_vulns)
        
        # Path vulnerability analysis
        pv_vulns = self._analyze_path_vulnerabilities()
        vulnerabilities.extend(pv_vulns)
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def _analyze_single_point_failures(self) -> List[TopologicalVulnerability]:
        """Analyze single point of failure vulnerabilities"""
        vulnerabilities = []
        metrics = self.calculate_centrality_metrics()
        
        # High betweenness centrality indicates potential single point of failure
        betweenness = metrics.get(NetworkMetric.BETWEENNESS_CENTRALITY.value, {})
        
        for node_id, score in betweenness.items():
            if score > 0.8:  # Very high betweenness
                # Calculate impact radius (nodes that would be affected)
                impact_radius = self._calculate_impact_radius(node_id)
                
                vulnerabilities.append(TopologicalVulnerability(
                    vulnerability_type=VulnerabilityType.SINGLE_POINT_FAILURE,
                    affected_nodes=[node_id],
                    severity=score,
                    description=f"Node {node_id} has high betweenness centrality ({score:.3f}), creating single point of failure risk",
                    impact_radius=impact_radius,
                    mitigation_strategies=[
                        "Add redundant paths",
                        "Implement failover mechanisms",
                        "Increase monitoring for critical nodes",
                        "Distribute critical functions"
                    ],
                    risk_score=score * (impact_radius / len(self.network.nodes()))
                ))
        
        return vulnerabilities
    
    def _analyze_cascade_failures(self) -> List[TopologicalVulnerability]:
        """Analyze cascade failure vulnerabilities"""
        vulnerabilities = []
        
        # Identify nodes with high degree centrality that could trigger cascades
        metrics = self.calculate_centrality_metrics()
        degree_centrality = metrics.get(NetworkMetric.DEGREE_CENTRALITY.value, {})
        
        for node_id, score in degree_centrality.items():
            if score > 0.7:  # High degree centrality
                # Simulate cascade failure
                cascade_size = self._simulate_cascade_failure(node_id)
                
                if cascade_size > len(self.network.nodes()) * 0.3:  # Significant cascade
                    vulnerabilities.append(TopologicalVulnerability(
                        vulnerability_type=VulnerabilityType.CASCADE_FAILURE,
                        affected_nodes=[node_id],
                        severity=score,
                        description=f"Node {node_id} could trigger cascade failure affecting {cascade_size} nodes",
                        impact_radius=cascade_size,
                        mitigation_strategies=[
                            "Implement circuit breakers",
                            "Add isolation mechanisms",
                            "Reduce node connectivity",
                            "Implement graceful degradation"
                        ],
                        risk_score=score * (cascade_size / len(self.network.nodes()))
                    ))
        
        return vulnerabilities
    
    def _analyze_isolation_vulnerabilities(self) -> List[TopologicalVulnerability]:
        """Analyze isolation vulnerabilities"""
        vulnerabilities = []
        
        # Find nodes with low connectivity that could become isolated
        metrics = self.calculate_centrality_metrics()
        degree_centrality = metrics.get(NetworkMetric.DEGREE_CENTRALITY.value, {})
        
        for node_id, score in degree_centrality.items():
            if score < 0.2:  # Low connectivity
                # Check if removal would isolate the node
                temp_network = self.network.copy()
                temp_network.remove_node(node_id)
                
                if not nx.is_connected(temp_network):
                    vulnerabilities.append(TopologicalVulnerability(
                        vulnerability_type=VulnerabilityType.ISOLATION_VULNERABILITY,
                        affected_nodes=[node_id],
                        severity=1.0 - score,
                        description=f"Node {node_id} has low connectivity and could become isolated",
                        impact_radius=1,
                        mitigation_strategies=[
                            "Increase node connectivity",
                            "Add backup connections",
                            "Implement reconnection mechanisms",
                            "Monitor connectivity status"
                        ],
                        risk_score=1.0 - score
                    ))
        
        return vulnerabilities
    
    def _analyze_concentration_risks(self) -> List[TopologicalVulnerability]:
        """Analyze concentration risks"""
        vulnerabilities = []
        
        # Identify areas of high node concentration
        communities = self._detect_communities()
        if communities:
            for community_id, nodes in communities.communities.items():
                if len(nodes) > len(self.network.nodes()) * 0.4:  # Large community
                    # Calculate internal connectivity
                    internal_edges = 0
                    total_possible_edges = len(nodes) * (len(nodes) - 1) // 2
                    
                    for node1 in nodes:
                        for node2 in nodes:
                            if node1 < node2 and self.network.has_edge(node1, node2):
                                internal_edges += 1
                    
                    concentration_ratio = internal_edges / total_possible_edges if total_possible_edges > 0 else 0
                    
                    if concentration_ratio > 0.6:  # High concentration
                        vulnerabilities.append(TopologicalVulnerability(
                            vulnerability_type=VulnerabilityType.CONCENTRATION_RISK,
                            affected_nodes=nodes,
                            severity=concentration_ratio,
                            description=f"Community {community_id} has high concentration risk with {concentration_ratio:.3f} internal connectivity",
                            impact_radius=len(nodes),
                            mitigation_strategies=[
                                "Distribute nodes across communities",
                                "Reduce internal connectivity",
                                "Add external connections",
                                "Implement load balancing"
                            ],
                            risk_score=concentration_ratio * (len(nodes) / len(self.network.nodes()))
                        ))
        
        return vulnerabilities
    
    def _analyze_path_vulnerabilities(self) -> List[TopologicalVulnerability]:
        """Analyze path vulnerabilities"""
        vulnerabilities = []
        
        # Find critical paths in the network
        metrics = self.calculate_centrality_metrics()
        betweenness = metrics.get(NetworkMetric.BETWEENNESS_CENTRALITY.value, {})
        
        # Identify edges that are part of many shortest paths
        edge_betweenness = nx.edge_betweenness_centrality(self.network)
        
        for (source, target), score in edge_betweenness.items():
            if score > 0.5:  # High edge betweenness
                vulnerabilities.append(TopologicalVulnerability(
                    vulnerability_type=VulnerabilityType.PATH_VULNERABILITY,
                    affected_nodes=[source, target],
                    severity=score,
                    description=f"Edge ({source}, {target}) is part of many shortest paths, creating path vulnerability",
                    impact_radius=2,
                    mitigation_strategies=[
                        "Add alternative paths",
                        "Increase edge capacity",
                        "Implement path diversity",
                        "Monitor path usage"
                    ],
                    risk_score=score
                ))
        
        return vulnerabilities
    
    def identify_attack_paths(self, source: str, target: str, max_paths: int = 5) -> List[AttackPath]:
        """
        Identify potential attack paths between nodes
        
        Args:
            source: Source node identifier
            target: Target node identifier
            max_paths: Maximum number of paths to return
            
        Returns:
            List of identified attack paths
        """
        if source not in self.network or target not in self.network:
            return []
        
        attack_paths = []
        
        # Shortest path
        try:
            shortest_path = nx.shortest_path(self.network, source, target)
            if shortest_path:
                attack_paths.append(self._create_attack_path(
                    "shortest", AttackPathType.SHORTEST_PATH, shortest_path
                ))
        except nx.NetworkXNoPath:
            pass
        
        # High trust path (path with highest average trust)
        trust_path = self._find_high_trust_path(source, target)
        if trust_path:
            attack_paths.append(self._create_attack_path(
                "high_trust", AttackPathType.HIGH_TRUST_PATH, trust_path
            ))
        
        # Low security path (path with lowest average security)
        security_path = self._find_low_security_path(source, target)
        if security_path:
            attack_paths.append(self._create_attack_path(
                "low_security", AttackPathType.LOW_SECURITY_PATH, security_path
            ))
        
        # Privilege escalation path
        privilege_path = self._find_privilege_escalation_path(source, target)
        if privilege_path:
            attack_paths.append(self._create_attack_path(
                "privilege_escalation", AttackPathType.PRIVILEGE_ESCALATION_PATH, privilege_path
            ))
        
        # Sort by total risk and return top paths
        attack_paths.sort(key=lambda p: p.total_risk, reverse=True)
        self.attack_paths = attack_paths[:max_paths]
        
        return self.attack_paths
    
    def _create_attack_path(self, path_id: str, path_type: AttackPathType, nodes: List[str]) -> AttackPath:
        """Create an attack path object"""
        edges = [(nodes[i], nodes[i+1]) for i in range(len(nodes)-1)]
        
        # Calculate total risk
        total_risk = 0.0
        security_weaknesses = []
        
        for node in nodes:
            node_data = self.node_data.get(node)
            if node_data:
                total_risk += (1.0 - node_data.security_level) * 0.5
                if node_data.security_level < 0.3:
                    security_weaknesses.append(f"Low security node: {node}")
        
        for source, target in edges:
            edge_data = self.edge_data.get((source, target))
            if edge_data:
                total_risk += (1.0 - edge_data.security_level) * 0.3
                if edge_data.security_level < 0.3:
                    security_weaknesses.append(f"Low security edge: ({source}, {target})")
        
        # Calculate exploitation difficulty (inverse of risk)
        exploitation_difficulty = max(0.0, 1.0 - total_risk)
        
        return AttackPath(
            path_id=path_id,
            path_type=path_type,
            nodes=nodes,
            edges=edges,
            total_risk=total_risk,
            path_length=len(nodes) - 1,
            security_weaknesses=security_weaknesses,
            exploitation_difficulty=exploitation_difficulty
        )
    
    def _find_high_trust_path(self, source: str, target: str) -> Optional[List[str]]:
        """Find path with highest average trust score"""
        try:
            # Use Dijkstra with trust-based weights
            def trust_weight(u, v, d):
                edge_data = self.edge_data.get((u, v))
                if edge_data:
                    return 1.0 - edge_data.trust_score  # Lower trust = higher weight
                return 1.0
            
            path = nx.dijkstra_path(self.network, source, target, weight=trust_weight)
            return path
        except nx.NetworkXNoPath:
            return None
    
    def _find_low_security_path(self, source: str, target: str) -> Optional[List[str]]:
        """Find path with lowest average security level"""
        try:
            # Use Dijkstra with security-based weights
            def security_weight(u, v, d):
                edge_data = self.edge_data.get((u, v))
                if edge_data:
                    return 1.0 - edge_data.security_level  # Lower security = higher weight
                return 1.0
            
            path = nx.dijkstra_path(self.network, source, target, weight=security_weight)
            return path
        except nx.NetworkXNoPath:
            return None
    
    def _find_privilege_escalation_path(self, source: str, target: str) -> Optional[List[str]]:
        """Find path that represents privilege escalation"""
        try:
            # Find path where target has higher privilege than source
            source_data = self.node_data.get(source)
            target_data = self.node_data.get(target)
            
            if not source_data or not target_data:
                return None
            
            # If target has higher privilege, find path
            if target_data.properties.get('privilege_level', 0) > source_data.properties.get('privilege_level', 0):
                return nx.shortest_path(self.network, source, target)
            
            return None
        except nx.NetworkXNoPath:
            return None
    
    def assess_network_resilience(self) -> NetworkResilience:
        """
        Assess overall network resilience
        
        Returns:
            Network resilience assessment
        """
        if not self.network.nodes():
            return NetworkResilience(
                overall_resilience=0.0,
                connectivity_resilience=0.0,
                redundancy_score=0.0,
                fault_tolerance=0.0,
                recovery_capability=0.0,
                critical_nodes=[],
                weak_links=[]
            )
        
        # Connectivity resilience
        connectivity_resilience = self._calculate_connectivity_resilience()
        
        # Redundancy score
        redundancy_score = self._calculate_redundancy_score()
        
        # Fault tolerance
        fault_tolerance = self._calculate_fault_tolerance()
        
        # Recovery capability
        recovery_capability = self._calculate_recovery_capability()
        
        # Overall resilience
        overall_resilience = (
            connectivity_resilience * 0.3 +
            redundancy_score * 0.25 +
            fault_tolerance * 0.25 +
            recovery_capability * 0.2
        )
        
        # Identify critical nodes and weak links
        critical_nodes = self.identify_critical_nodes()
        weak_links = self._identify_weak_links()
        
        resilience = NetworkResilience(
            overall_resilience=overall_resilience,
            connectivity_resilience=connectivity_resilience,
            redundancy_score=redundancy_score,
            fault_tolerance=fault_tolerance,
            recovery_capability=recovery_capability,
            critical_nodes=critical_nodes,
            weak_links=weak_links
        )
        
        self.resilience_profile = resilience
        return resilience
    
    def _calculate_connectivity_resilience(self) -> float:
        """Calculate connectivity resilience"""
        if not self.network.nodes():
            return 0.0
        
        # Check if network is connected
        if not nx.is_connected(self.network):
            return 0.0
        
        # Calculate average shortest path length
        avg_path_length = nx.average_shortest_path_length(self.network)
        max_possible_length = len(self.network.nodes()) - 1
        
        # Lower average path length = higher resilience
        connectivity_resilience = 1.0 - (avg_path_length / max_possible_length)
        
        return max(0.0, min(1.0, connectivity_resilience))
    
    def _calculate_redundancy_score(self) -> float:
        """Calculate network redundancy score"""
        if not self.network.nodes():
            return 0.0
        
        # Calculate edge connectivity
        try:
            edge_connectivity = nx.edge_connectivity(self.network)
        except nx.NetworkXError:
            edge_connectivity = 0
        
        # Calculate node connectivity
        try:
            node_connectivity = nx.node_connectivity(self.network)
        except nx.NetworkXError:
            node_connectivity = 0
        
        # Normalize by network size
        max_connectivity = min(len(self.network.nodes()) - 1, len(self.network.edges()))
        
        if max_connectivity == 0:
            return 0.0
        
        redundancy_score = (edge_connectivity + node_connectivity) / (2 * max_connectivity)
        return max(0.0, min(1.0, redundancy_score))
    
    def _calculate_fault_tolerance(self) -> float:
        """Calculate fault tolerance"""
        if not self.network.nodes():
            return 0.0
        
        # Simulate random node failures
        failure_simulations = 100
        successful_connections = 0
        
        for _ in range(failure_simulations):
            # Randomly remove 10% of nodes
            nodes_to_remove = max(1, len(self.network.nodes()) // 10)
            nodes = list(self.network.nodes())
            np.random.shuffle(nodes)
            nodes_to_remove = nodes[:nodes_to_remove]
            
            # Create temporary network without removed nodes
            temp_network = self.network.copy()
            temp_network.remove_nodes_from(nodes_to_remove)
            
            # Check if network remains connected
            if nx.is_connected(temp_network):
                successful_connections += 1
        
        fault_tolerance = successful_connections / failure_simulations
        return fault_tolerance
    
    def _calculate_recovery_capability(self) -> float:
        """Calculate recovery capability"""
        if not self.network.nodes():
            return 0.0
        
        # Calculate clustering coefficient (indicates local connectivity)
        clustering_coeffs = nx.clustering(self.network)
        avg_clustering = sum(clustering_coeffs.values()) / len(clustering_coeffs)
        
        # Calculate degree distribution (more uniform = better recovery)
        degrees = [d for n, d in self.network.degree()]
        if degrees:
            degree_variance = np.var(degrees)
            degree_mean = np.mean(degrees)
            coefficient_of_variation = degree_variance / degree_mean if degree_mean > 0 else 0
            
            # Lower coefficient of variation = better recovery
            recovery_capability = 1.0 / (1.0 + coefficient_of_variation)
        else:
            recovery_capability = 0.0
        
        # Combine with clustering coefficient
        recovery_capability = (recovery_capability + avg_clustering) / 2
        
        return max(0.0, min(1.0, recovery_capability))
    
    def _identify_weak_links(self) -> List[Tuple[str, str]]:
        """Identify weak links in the network"""
        weak_links = []
        
        # Find edges with low security or trust scores
        for (source, target), edge_data in self.edge_data.items():
            if (edge_data.security_level < 0.3 or 
                edge_data.trust_score < 0.3 or 
                edge_data.weight < 0.3):
                weak_links.append((source, target))
        
        return weak_links
    
    def detect_communities(self) -> CommunityStructure:
        """
        Detect community structure in the network
        
        Returns:
            Community structure analysis
        """
        if not self.network.nodes():
            return CommunityStructure(
                communities={},
                modularity=0.0,
                community_count=0,
                largest_community_size=0,
                community_connectivity={},
                inter_community_risk=0.0
            )
        
        # Use Louvain algorithm for community detection
        try:
            communities = nx.community.louvain_communities(self.network)
        except:
            # Fallback to simple connected components
            communities = list(nx.connected_components(self.network))
        
        # Convert to dictionary format
        community_dict = {i: list(community) for i, community in enumerate(communities)}
        
        # Calculate modularity
        try:
            modularity = nx.community.modularity(self.network, communities)
        except:
            modularity = 0.0
        
        # Calculate community statistics
        community_count = len(communities)
        largest_community_size = max(len(community) for community in communities) if communities else 0
        
        # Calculate community connectivity
        community_connectivity = {}
        for i, community in enumerate(communities):
            internal_edges = 0
            external_edges = 0
            
            for node in community:
                for neighbor in self.network.neighbors(node):
                    if neighbor in community:
                        internal_edges += 1
                    else:
                        external_edges += 1
            
            total_edges = internal_edges + external_edges
            connectivity = internal_edges / total_edges if total_edges > 0 else 0
            community_connectivity[i] = connectivity
        
        # Calculate inter-community risk
        inter_community_risk = 1.0 - (sum(community_connectivity.values()) / len(community_connectivity)) if community_connectivity else 0.0
        
        community_structure = CommunityStructure(
            communities=community_dict,
            modularity=modularity,
            community_count=community_count,
            largest_community_size=largest_community_size,
            community_connectivity=community_connectivity,
            inter_community_risk=inter_community_risk
        )
        
        self.community_structure = community_structure
        return community_structure
    
    def _calculate_impact_radius(self, node_id: str) -> int:
        """Calculate impact radius for a node failure"""
        if node_id not in self.network:
            return 0
        
        # Calculate how many nodes would be affected by removing this node
        temp_network = self.network.copy()
        temp_network.remove_node(node_id)
        
        # Count nodes in largest connected component
        if temp_network.nodes():
            largest_component = max(nx.connected_components(temp_network), key=len)
            return len(largest_component)
        
        return 0
    
    def _simulate_cascade_failure(self, initial_node: str) -> int:
        """Simulate cascade failure starting from a node"""
        if initial_node not in self.network:
            return 0
        
        # Simple cascade simulation: remove node and count affected nodes
        temp_network = self.network.copy()
        temp_network.remove_node(initial_node)
        
        # Count nodes that become disconnected
        original_size = len(self.network.nodes())
        remaining_size = len(temp_network.nodes())
        
        return original_size - remaining_size
    
    def _invalidate_cache(self):
        """Invalidate cached metrics"""
        self.metrics_cache = {}
    
    def export_analysis(self, file_path: str) -> bool:
        """Export topological analysis to file"""
        try:
            analysis_data = {
                "network_metrics": self.calculate_centrality_metrics(),
                "vulnerabilities": [
                    {
                        "vulnerability_type": v.vulnerability_type.value,
                        "affected_nodes": v.affected_nodes,
                        "severity": v.severity,
                        "description": v.description,
                        "impact_radius": v.impact_radius,
                        "mitigation_strategies": v.mitigation_strategies,
                        "risk_score": v.risk_score
                    }
                    for v in self.vulnerabilities
                ],
                "attack_paths": [
                    {
                        "path_id": p.path_id,
                        "path_type": p.path_type.value,
                        "nodes": p.nodes,
                        "edges": p.edges,
                        "total_risk": p.total_risk,
                        "path_length": p.path_length,
                        "security_weaknesses": p.security_weaknesses,
                        "exploitation_difficulty": p.exploitation_difficulty
                    }
                    for p in self.attack_paths
                ],
                "resilience": {
                    "overall_resilience": self.resilience_profile.overall_resilience if self.resilience_profile else 0.0,
                    "connectivity_resilience": self.resilience_profile.connectivity_resilience if self.resilience_profile else 0.0,
                    "redundancy_score": self.resilience_profile.redundancy_score if self.resilience_profile else 0.0,
                    "fault_tolerance": self.resilience_profile.fault_tolerance if self.resilience_profile else 0.0,
                    "recovery_capability": self.resilience_profile.recovery_capability if self.resilience_profile else 0.0,
                    "critical_nodes": self.resilience_profile.critical_nodes if self.resilience_profile else [],
                    "weak_links": self.resilience_profile.weak_links if self.resilience_profile else []
                },
                "communities": {
                    "communities": self.community_structure.communities if self.community_structure else {},
                    "modularity": self.community_structure.modularity if self.community_structure else 0.0,
                    "community_count": self.community_structure.community_count if self.community_structure else 0,
                    "largest_community_size": self.community_structure.largest_community_size if self.community_structure else 0,
                    "community_connectivity": self.community_structure.community_connectivity if self.community_structure else {},
                    "inter_community_risk": self.community_structure.inter_community_risk if self.community_structure else 0.0
                },
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(analysis_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting topological analysis: {e}")
            return False
