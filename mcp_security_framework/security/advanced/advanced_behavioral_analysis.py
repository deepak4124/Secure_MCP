"""
Inference Safety Analyzer for MCP Security Framework

Detects anomalies in tool execution sequences, such as parasitic toolchains
and high-privilege escalations during inference.
"""

from typing import Dict, List, Any, Tuple
import time

class InferenceSafetyAnalyzer:
    """
    Analyzes sequences of tool executions in real-time to detect
    potentially malicious chaining and indirect prompt injections.
    """
    def __init__(self):
        self.execution_history: Dict[str, List[Dict[str, Any]]] = {}
        
    def log_execution(self, agent_id: str, tool_id: str, parameters: Dict[str, Any], risk_level: str):
        if agent_id not in self.execution_history:
            self.execution_history[agent_id] = []
            
        self.execution_history[agent_id].append({
            "tool_id": tool_id,
            "risk_level": risk_level,
            "timestamp": time.time(),
            "parameters": parameters
        })
        
        # Keep last 10 executions
        if len(self.execution_history[agent_id]) > 10:
            self.execution_history[agent_id] = self.execution_history[agent_id][-10:]
            
    def check_safety(self, agent_id: str, current_tool_id: str, current_risk: str) -> Tuple[bool, str]:
        """
        Check if the current tool execution is safe given the recent history.
        """
        history = self.execution_history.get(agent_id, [])
        if not history:
            return True, "Safe"
            
        last_exec = history[-1]
        time_since_last = time.time() - last_exec["timestamp"]
        
        # Heuristic: Parasitic toolchain detection
        # If a low-risk read tool is immediately followed by a critical write tool
        if last_exec["risk_level"] in ["low", "minimal"] and current_risk in ["high", "critical"]:
            if time_since_last < 2.0:  # Suspiciously fast execution (LLM might be hijacked)
                return False, "Parasitic toolchain detected: High-risk operation immediately following low-risk read."
                
        return True, "Safe"
