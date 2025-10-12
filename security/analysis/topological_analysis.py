"""
Topological Security Analysis

This module provides comprehensive network topology security analysis including:
- Network structure analysis
- Centrality risk assessment
- Attack path detection
- Network resilience evaluation
"""

import time
import math
import networkx as nx
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque

from pydantic import BaseModel, Field


class NetworkNodeType(Enum):
    """Network node type enumeration"""
    AGENT = "agent"
    MCP_SERVER = "mcp_server"
    GATEWAY = "gateway"
    COORDINATOR = "coordinator"
    MONITOR = "monitor"
    DATABASE = "database"
    EXTERNAL = "external"


class ConnectionType(Enum):
    """Connection type enumeration"""
    DIRECT = "direct"
    PROXY = "proxy"
    ENCRYPTED = "encrypted"
    UNENCRYPTED = "unencrypted"
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class TopologyRiskLevel(Enum):
    """Topology risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NetworkNode:
    """Network node data structure"""
    node_id: str
    node_type: NetworkNodeType
    trust_score: float
    security_level: str
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkConnection:
    """Network connection data structure"""
    source_id: str
    target_id: str
    connection_type: ConnectionType
    security_level: str
    bandwidth: float = 0.0
    latency: float = 0.0
    reliability: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TopologyVulnerability:
    """Topology vulnerability data structure"""
    vulnerability_type: str
    risk_level: TopologyRiskLevel
    description: str
    affected_nodes: List[str]
    impact_score: float  # 0.0 to 1.0
    likelihood_score: float  # 0.0 to 1.0
    mitigation_suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TopologyMetrics:
    """Topology security metrics data structure"""
    total_nodes: int
    total_connections: int
    network_density: float
    average_path_length: float
    clustering_coefficient: float
    centralization_score: float
    resilience_score: float  # 0.0 to 1.0
    vulnerability_count: int
    critical_nodes: int
    last_analyzed: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class TopologicalSecurityAnalyzer:
    """
    Comprehensive topological security analysis system
    
    Features:
    - Network structure analysis
    - Centrality risk assessment
    - Attack path detection
    - Network resilience evaluation
    - Vulnerability identification
    """
    
    def __init__(self):
        """Initialize topological security analyzer"""
        self.network_graph = nx.Graph()
        self.nodes: Dict[str, NetworkNode] = {}
        self.connections: Dict[str, NetworkConnection] = {}
        self.vulnerabilities: List[TopologyVulnerability] = []
        self.metrics: Optional[TopologyMetrics] = None
        
        # Risk assessment parameters
        self.centrality_thresholds = {
            "high_centrality": 0.7,
            "critical_centrality": 0.9
        }
        
        self.resilience_weights = {
            "redundancy": 0.3,
            "diversity": 0.25,
            "centralization": 0.2,
            "connectivity": 0.25
        }
        
        # Node type risk levels
        self.node_type_risks = {
            NetworkNodeType.AGENT: 0.3,
            NetworkNodeType.MCP_SERVER: 0.5,
            NetworkNodeType.GATEWAY: 0.7,
            NetworkNodeType.COORDINATOR: 0.8,
            NetworkNodeType.MONITOR: 0.6,
            NetworkNodeType.DATABASE: 0.9,
            NetworkNodeType.EXTERNAL: 0.8
        }
    
    def add_node(self, node: NetworkNode) -> bool:
        """
        Add a node to the network topology
        
        Args:
            node: Network node to add
            
        Returns:
            True if node added successfully
        """
        try:
            self.nodes[node.node_id] = node
            self.network_graph.add_node(
                node.node_id,
                node_type=node.node_type.value,
                trust_score=node.trust_score,
                security_level=node.security_level,
                capabilities=node.capabilities,
                metadata=node.metadata
            )
            return True
            
        except Exception as e:
            print(f"Error adding node {node.node_id}: {e}")
            return False
    
    def add_connection(self, connection: NetworkConnection) -> bool:
        """
        Add a connection to the network topology
        
        Args:
            connection: Network connection to add
            
        Returns:
            True if connection added successfully
        """
        try:
            connection_id = f"{connection.source_id}->{connection.target_id}"
            self.connections[connection_id] = connection
            
            # Add edge to network graph
            self.network_graph.add_edge(
                connection.source_id,
                connection.target_id,
                connection_type=connection.connection_type.value,
                security_level=connection.security_level,
                bandwidth=connection.bandwidth,
                latency=connection.latency,
                reliability=connection.reliability,
                metadata=connection.metadata
            )
            
            return True
            
        except Exception as e:
            print(f"Error adding connection {connection_id}: {e}")
            return False
    
    def analyze_network_topology(self) -> Dict[str, Any]:
        """
        Analyze the overall network topology
        
        Returns:
            Comprehensive topology analysis
        """
        try:
            if len(self.network_graph.nodes()) == 0:
                return {"error": "No nodes in network"}
            
            # Calculate basic network metrics
            basic_metrics = self._calculate_basic_metrics()
            
            # Analyze centrality risks
            centrality_analysis = self._analyze_centrality_risks()
            
            # Detect attack paths
            attack_paths = self._detect_attack_paths()
            
            # Evaluate network resilience
            resilience_analysis = self._evaluate_network_resilience()
            
            # Identify vulnerabilities
            vulnerabilities = self._identify_topology_vulnerabilities()
            
            # Generate comprehensive analysis
            analysis = {
                "basic_metrics": basic_metrics,
                "centrality_analysis": centrality_analysis,
                "attack_paths": attack_paths,
                "resilience_analysis": resilience_analysis,
                "vulnerabilities": vulnerabilities,
                "recommendations": self._generate_topology_recommendations(),
                "analyzed_at": time.time()
            }
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing network topology: {e}")
            return {"error": str(e)}
    
    def _calculate_basic_metrics(self) -> Dict[str, Any]:
        """Calculate basic network metrics"""
        try:
            num_nodes = self.network_graph.number_of_nodes()
            num_edges = self.network_graph.number_of_edges()
            
            # Network density
            max_edges = num_nodes * (num_nodes - 1) / 2
            density = num_edges / max_edges if max_edges > 0 else 0
            
            # Average path length
            try:
                avg_path_length = nx.average_shortest_path_length(self.network_graph)
            except nx.NetworkXError:
                avg_path_length = 0
            
            # Clustering coefficient
            clustering_coeff = nx.average_clustering(self.network_graph)
            
            # Centralization
            centralization = self._calculate_centralization()
            
            return {
                "total_nodes": num_nodes,
                "total_edges": num_edges,
                "density": round(density, 3),
                "average_path_length": round(avg_path_length, 3),
                "clustering_coefficient": round(clustering_coeff, 3),
                "centralization": round(centralization, 3)
            }
            
        except Exception as e:
            print(f"Error calculating basic metrics: {e}")
            return {}
    
    def _calculate_centralization(self) -> float:
        """Calculate network centralization"""
        try:
            if len(self.network_graph.nodes()) == 0:
                return 0.0
            
            # Calculate degree centrality
            degree_centrality = nx.degree_centrality(self.network_graph)
            
            # Calculate betweenness centrality
            betweenness_centrality = nx.betweenness_centrality(self.network_graph)
            
            # Calculate closeness centrality
            closeness_centrality = nx.closeness_centrality(self.network_graph)
            
            # Combine centrality measures
            max_degree = max(degree_centrality.values()) if degree_centrality else 0
            max_betweenness = max(betweenness_centrality.values()) if betweenness_centrality else 0
            max_closeness = max(closeness_centrality.values()) if closeness_centrality else 0
            
            # Weighted average
            centralization = (max_degree * 0.4 + max_betweenness * 0.4 + max_closeness * 0.2)
            
            return centralization
            
        except Exception as e:
            print(f"Error calculating centralization: {e}")
            return 0.0
    
    def _analyze_centrality_risks(self) -> Dict[str, Any]:
        """Analyze centrality-based risks"""
        try:
            centrality_analysis = {
                "high_centrality_nodes": [],
                "critical_nodes": [],
                "single_points_of_failure": [],
                "risk_assessment": {}
            }
            
            # Calculate centrality measures
            degree_centrality = nx.degree_centrality(self.network_graph)
            betweenness_centrality = nx.betweenness_centrality(self.network_graph)
            closeness_centrality = nx.closeness_centrality(self.network_graph)
            
            # Identify high centrality nodes
            for node_id, centrality in degree_centrality.items():
                if centrality >= self.centrality_thresholds["high_centrality"]:
                    centrality_analysis["high_centrality_nodes"].append({
                        "node_id": node_id,
                        "degree_centrality": round(centrality, 3),
                        "betweenness_centrality": round(betweenness_centrality.get(node_id, 0), 3),
                        "closeness_centrality": round(closeness_centrality.get(node_id, 0), 3),
                        "risk_level": "critical" if centrality >= self.centrality_thresholds["critical_centrality"] else "high"
                    })
            
            # Identify critical nodes (high centrality + high risk node type)
            for node_id in self.network_graph.nodes():
                node = self.nodes.get(node_id)
                if node:
                    node_risk = self.node_type_risks.get(node.node_type, 0.5)
                    centrality = degree_centrality.get(node_id, 0)
                    
                    if centrality >= 0.5 and node_risk >= 0.7:
                        centrality_analysis["critical_nodes"].append({
                            "node_id": node_id,
                            "node_type": node.node_type.value,
                            "centrality": round(centrality, 3),
                            "node_risk": round(node_risk, 3),
                            "combined_risk": round((centrality + node_risk) / 2, 3)
                        })
            
            # Identify single points of failure
            for node_id in self.network_graph.nodes():
                if self.network_graph.degree(node_id) == 1:
                    centrality_analysis["single_points_of_failure"].append({
                        "node_id": node_id,
                        "degree": 1,
                        "risk": "medium"
                    })
            
            # Overall risk assessment
            centrality_analysis["risk_assessment"] = {
                "high_centrality_count": len(centrality_analysis["high_centrality_nodes"]),
                "critical_nodes_count": len(centrality_analysis["critical_nodes"]),
                "single_points_of_failure_count": len(centrality_analysis["single_points_of_failure"]),
                "overall_risk": "high" if len(centrality_analysis["critical_nodes"]) > 2 else
                              "medium" if len(centrality_analysis["high_centrality_nodes"]) > 3 else "low"
            }
            
            return centrality_analysis
            
        except Exception as e:
            print(f"Error analyzing centrality risks: {e}")
            return {}
    
    def _detect_attack_paths(self) -> Dict[str, Any]:
        """Detect potential attack paths in the network"""
        try:
            attack_paths = {
                "shortest_paths": {},
                "vulnerable_paths": [],
                "attack_surface": {},
                "recommendations": []
            }
            
            # Find shortest paths between all pairs of nodes
            for source in self.network_graph.nodes():
                for target in self.network_graph.nodes():
                    if source != target:
                        try:
                            path = nx.shortest_path(self.network_graph, source, target)
                            path_length = len(path) - 1
                            
                            if path_length <= 3:  # Short paths are more vulnerable
                                attack_paths["shortest_paths"][f"{source}->{target}"] = {
                                    "path": path,
                                    "length": path_length,
                                    "risk_level": "high" if path_length <= 2 else "medium"
                                }
                        except nx.NetworkXNoPath:
                            continue
            
            # Identify vulnerable paths (through low-trust nodes)
            for path_id, path_info in attack_paths["shortest_paths"].items():
                path = path_info["path"]
                vulnerable_nodes = []
                
                for node_id in path:
                    node = self.nodes.get(node_id)
                    if node and node.trust_score < 0.5:
                        vulnerable_nodes.append({
                            "node_id": node_id,
                            "trust_score": node.trust_score,
                            "risk": "high" if node.trust_score < 0.3 else "medium"
                        })
                
                if vulnerable_nodes:
                    attack_paths["vulnerable_paths"].append({
                        "path_id": path_id,
                        "path": path,
                        "vulnerable_nodes": vulnerable_nodes,
                        "overall_risk": "high" if any(n["risk"] == "high" for n in vulnerable_nodes) else "medium"
                    })
            
            # Calculate attack surface
            attack_paths["attack_surface"] = {
                "total_paths": len(attack_paths["shortest_paths"]),
                "vulnerable_paths": len(attack_paths["vulnerable_paths"]),
                "high_risk_paths": len([p for p in attack_paths["vulnerable_paths"] if p["overall_risk"] == "high"]),
                "attack_surface_score": len(attack_paths["vulnerable_paths"]) / max(1, len(attack_paths["shortest_paths"]))
            }
            
            return attack_paths
            
        except Exception as e:
            print(f"Error detecting attack paths: {e}")
            return {}
    
    def _evaluate_network_resilience(self) -> Dict[str, Any]:
        """Evaluate network resilience"""
        try:
            resilience_analysis = {
                "redundancy_score": 0.0,
                "diversity_score": 0.0,
                "centralization_penalty": 0.0,
                "connectivity_score": 0.0,
                "overall_resilience": 0.0,
                "recommendations": []
            }
            
            # Calculate redundancy score
            redundancy_score = self._calculate_redundancy_score()
            resilience_analysis["redundancy_score"] = redundancy_score
            
            # Calculate diversity score
            diversity_score = self._calculate_diversity_score()
            resilience_analysis["diversity_score"] = diversity_score
            
            # Calculate centralization penalty
            centralization_penalty = self._calculate_centralization_penalty()
            resilience_analysis["centralization_penalty"] = centralization_penalty
            
            # Calculate connectivity score
            connectivity_score = self._calculate_connectivity_score()
            resilience_analysis["connectivity_score"] = connectivity_score
            
            # Calculate overall resilience
            overall_resilience = (
                redundancy_score * self.resilience_weights["redundancy"] +
                diversity_score * self.resilience_weights["diversity"] +
                (1 - centralization_penalty) * self.resilience_weights["centralization"] +
                connectivity_score * self.resilience_weights["connectivity"]
            )
            resilience_analysis["overall_resilience"] = round(overall_resilience, 3)
            
            # Generate recommendations
            if overall_resilience < 0.5:
                resilience_analysis["recommendations"].append("CRITICAL: Network resilience is very low")
            elif overall_resilience < 0.7:
                resilience_analysis["recommendations"].append("HIGH: Network resilience needs improvement")
            
            if redundancy_score < 0.5:
                resilience_analysis["recommendations"].append("Add redundant connections to improve fault tolerance")
            
            if diversity_score < 0.5:
                resilience_analysis["recommendations"].append("Increase node diversity to reduce single points of failure")
            
            if centralization_penalty > 0.7:
                resilience_analysis["recommendations"].append("Reduce network centralization to improve resilience")
            
            return resilience_analysis
            
        except Exception as e:
            print(f"Error evaluating network resilience: {e}")
            return {}
    
    def _calculate_redundancy_score(self) -> float:
        """Calculate network redundancy score"""
        try:
            if len(self.network_graph.nodes()) < 2:
                return 0.0
            
            # Count redundant paths
            redundant_paths = 0
            total_pairs = 0
            
            for source in self.network_graph.nodes():
                for target in self.network_graph.nodes():
                    if source != target:
                        total_pairs += 1
                        try:
                            # Find all simple paths
                            paths = list(nx.all_simple_paths(self.network_graph, source, target, cutoff=4))
                            if len(paths) > 1:
                                redundant_paths += 1
                        except nx.NetworkXNoPath:
                            continue
            
            return redundant_paths / max(1, total_pairs)
            
        except Exception as e:
            print(f"Error calculating redundancy score: {e}")
            return 0.0
    
    def _calculate_diversity_score(self) -> float:
        """Calculate node diversity score"""
        try:
            if len(self.nodes) == 0:
                return 0.0
            
            # Count node types
            node_types = defaultdict(int)
            for node in self.nodes.values():
                node_types[node.node_type] += 1
            
            # Calculate diversity (Shannon entropy)
            total_nodes = len(self.nodes)
            diversity = 0.0
            
            for count in node_types.values():
                if count > 0:
                    p = count / total_nodes
                    diversity -= p * math.log2(p)
            
            # Normalize to 0-1 scale
            max_diversity = math.log2(len(node_types)) if len(node_types) > 1 else 1.0
            return diversity / max_diversity if max_diversity > 0 else 0.0
            
        except Exception as e:
            print(f"Error calculating diversity score: {e}")
            return 0.0
    
    def _calculate_centralization_penalty(self) -> float:
        """Calculate centralization penalty"""
        try:
            if len(self.network_graph.nodes()) == 0:
                return 0.0
            
            # Calculate degree centralization
            degree_centrality = nx.degree_centrality(self.network_graph)
            max_centrality = max(degree_centrality.values()) if degree_centrality else 0
            
            return max_centrality
            
        except Exception as e:
            print(f"Error calculating centralization penalty: {e}")
            return 0.0
    
    def _calculate_connectivity_score(self) -> float:
        """Calculate network connectivity score"""
        try:
            if len(self.network_graph.nodes()) == 0:
                return 0.0
            
            # Check if network is connected
            if not nx.is_connected(self.network_graph):
                return 0.0
            
            # Calculate connectivity based on edge connectivity
            try:
                edge_connectivity = nx.edge_connectivity(self.network_graph)
                node_connectivity = nx.node_connectivity(self.network_graph)
                
                # Normalize connectivity scores
                max_possible_edges = len(self.network_graph.nodes()) - 1
                edge_score = min(1.0, edge_connectivity / max_possible_edges)
                node_score = min(1.0, node_connectivity / max_possible_edges)
                
                return (edge_score + node_score) / 2
                
            except nx.NetworkXError:
                return 0.5  # Default score for connected networks
            
        except Exception as e:
            print(f"Error calculating connectivity score: {e}")
            return 0.0
    
    def _identify_topology_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Identify topology-based vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Single points of failure
            for node_id in self.network_graph.nodes():
                if self.network_graph.degree(node_id) == 1:
                    vulnerabilities.append({
                        "type": "single_point_of_failure",
                        "risk_level": "medium",
                        "description": f"Node {node_id} is a single point of failure",
                        "affected_nodes": [node_id],
                        "impact_score": 0.6,
                        "likelihood_score": 0.7,
                        "mitigation_suggestions": [
                            "Add redundant connections",
                            "Implement failover mechanisms",
                            "Monitor node health closely"
                        ]
                    })
            
            # High centrality vulnerabilities
            degree_centrality = nx.degree_centrality(self.network_graph)
            for node_id, centrality in degree_centrality.items():
                if centrality >= self.centrality_thresholds["critical_centrality"]:
                    vulnerabilities.append({
                        "type": "high_centrality_risk",
                        "risk_level": "critical",
                        "description": f"Node {node_id} has critical centrality risk",
                        "affected_nodes": [node_id],
                        "impact_score": 0.9,
                        "likelihood_score": 0.8,
                        "mitigation_suggestions": [
                            "Implement additional security controls",
                            "Add monitoring and alerting",
                            "Consider load distribution",
                            "Implement access restrictions"
                        ]
                    })
            
            # Low trust path vulnerabilities
            for source in self.network_graph.nodes():
                for target in self.network_graph.nodes():
                    if source != target:
                        try:
                            path = nx.shortest_path(self.network_graph, source, target)
                            low_trust_nodes = [n for n in path if self.nodes.get(n, {}).get('trust_score', 1.0) < 0.3]
                            
                            if low_trust_nodes:
                                vulnerabilities.append({
                                    "type": "low_trust_path",
                                    "risk_level": "high",
                                    "description": f"Path from {source} to {target} contains low-trust nodes",
                                    "affected_nodes": low_trust_nodes,
                                    "impact_score": 0.7,
                                    "likelihood_score": 0.6,
                                    "mitigation_suggestions": [
                                        "Improve trust scores of intermediate nodes",
                                        "Use alternative paths with higher trust",
                                        "Implement additional verification"
                                    ]
                                })
                        except nx.NetworkXNoPath:
                            continue
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error identifying topology vulnerabilities: {e}")
            return []
    
    def _generate_topology_recommendations(self) -> List[str]:
        """Generate topology security recommendations"""
        recommendations = []
        
        try:
            # Basic recommendations
            recommendations.extend([
                "Regular network topology analysis",
                "Monitor node centrality changes",
                "Implement network segmentation",
                "Add redundant connections for critical nodes",
                "Implement failover mechanisms",
                "Monitor trust scores across the network",
                "Regular security assessment of network paths"
            ])
            
            # Dynamic recommendations based on analysis
            analysis = self.analyze_network_topology()
            
            if analysis.get("centrality_analysis", {}).get("risk_assessment", {}).get("overall_risk") == "high":
                recommendations.append("URGENT: Address high centrality risks immediately")
            
            if analysis.get("resilience_analysis", {}).get("overall_resilience", 1.0) < 0.5:
                recommendations.append("CRITICAL: Improve network resilience")
            
            if analysis.get("attack_paths", {}).get("attack_surface", {}).get("attack_surface_score", 0) > 0.5:
                recommendations.append("HIGH: Reduce attack surface by securing vulnerable paths")
            
        except Exception as e:
            print(f"Error generating topology recommendations: {e}")
        
        return recommendations
    
    def get_topology_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive topology security report"""
        try:
            analysis = self.analyze_network_topology()
            
            report = {
                "network_summary": {
                    "total_nodes": len(self.nodes),
                    "total_connections": len(self.connections),
                    "node_types": {t.value: sum(1 for n in self.nodes.values() if n.node_type == t) 
                                 for t in NetworkNodeType},
                    "connection_types": {t.value: sum(1 for c in self.connections.values() if c.connection_type == t)
                                       for t in ConnectionType}
                },
                "security_analysis": analysis,
                "vulnerabilities": self.vulnerabilities,
                "recommendations": self._generate_topology_recommendations(),
                "generated_at": time.time()
            }
            
            return report
            
        except Exception as e:
            print(f"Error generating topology security report: {e}")
            return {"error": str(e)}
