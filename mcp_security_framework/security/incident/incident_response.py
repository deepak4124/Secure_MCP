"""
Incident Response System for MCP Security Framework

This module provides comprehensive incident response capabilities including:
- Incident detection and classification
- Response time metrics and tracking
- Automated response workflows
- Escalation procedures
- Post-incident analysis
- Incident correlation and pattern detection
"""

import time
import asyncio
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
import threading
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel, Field


class IncidentSeverity(Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(Enum):
    """Incident status enumeration"""
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentType(Enum):
    """Incident type enumeration"""
    SECURITY_BREACH = "security_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_INFECTION = "malware_infection"
    DENIAL_OF_SERVICE = "denial_of_service"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    SYSTEM_COMPROMISE = "system_compromise"
    NETWORK_INTRUSION = "network_intrusion"
    POLICY_VIOLATION = "policy_violation"


class ResponseAction(Enum):
    """Response action enumeration"""
    ISOLATE_AGENT = "isolate_agent"
    REVOKE_ACCESS = "revoke_access"
    BLOCK_IP = "block_ip"
    QUARANTINE_DATA = "quarantine_data"
    ESCALATE_TO_ADMIN = "escalate_to_admin"
    NOTIFY_SECURITY_TEAM = "notify_security_team"
    ACTIVATE_BACKUP = "activate_backup"
    SHUTDOWN_SYSTEM = "shutdown_system"
    COLLECT_EVIDENCE = "collect_evidence"
    UPDATE_POLICIES = "update_policies"


@dataclass
class Incident:
    """Incident data structure"""
    incident_id: str
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus
    title: str
    description: str
    affected_agents: List[str]
    affected_systems: List[str]
    detected_at: float
    first_response_time: Optional[float] = None
    containment_time: Optional[float] = None
    eradication_time: Optional[float] = None
    recovery_time: Optional[float] = None
    closed_at: Optional[float] = None
    assigned_to: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    response_actions: List[ResponseAction] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseTimeMetrics:
    """Response time metrics data structure"""
    incident_id: str
    detection_to_response: Optional[float] = None
    response_to_containment: Optional[float] = None
    containment_to_eradication: Optional[float] = None
    eradication_to_recovery: Optional[float] = None
    total_resolution_time: Optional[float] = None
    sla_compliance: bool = False
    sla_target: float = 3600  # 1 hour default SLA


@dataclass
class IncidentCorrelation:
    """Incident correlation result"""
    correlation_id: str
    related_incidents: List[str]
    correlation_type: str
    confidence: float
    pattern_description: str
    common_indicators: List[str]
    timeline: List[Dict[str, Any]]


@dataclass
class ResponseWorkflow:
    """Response workflow definition"""
    workflow_id: str
    name: str
    description: str
    incident_types: List[IncidentType]
    severity_levels: List[IncidentSeverity]
    steps: List[Dict[str, Any]]
    escalation_rules: List[Dict[str, Any]]
    sla_targets: Dict[str, float]


class IncidentResponseSystem:
    """
    Comprehensive incident response system
    
    Features:
    - Incident detection and classification
    - Response time metrics and tracking
    - Automated response workflows
    - Escalation procedures
    - Post-incident analysis
    - Incident correlation and pattern detection
    - SLA monitoring and compliance
    """
    
    def __init__(self):
        """Initialize incident response system"""
        self.incidents: Dict[str, Incident] = {}
        self.response_metrics: Dict[str, ResponseTimeMetrics] = {}
        self.correlations: List[IncidentCorrelation] = []
        self.workflows: Dict[str, ResponseWorkflow] = {}
        self.response_handlers: Dict[str, Callable] = {}
        self.escalation_rules: List[Dict[str, Any]] = []
        self.sla_targets: Dict[IncidentSeverity, float] = {
            IncidentSeverity.LOW: 14400,      # 4 hours
            IncidentSeverity.MEDIUM: 7200,    # 2 hours
            IncidentSeverity.HIGH: 3600,      # 1 hour
            IncidentSeverity.CRITICAL: 1800   # 30 minutes
        }
        
        # Response tracking
        self.active_incidents: Set[str] = set()
        self.response_queue: deque = deque()
        self.metrics_history: deque = deque(maxlen=1000)
        
        # Initialize default workflows
        self._initialize_default_workflows()
        
        # Start background processing
        self._start_background_processing()
    
    def _initialize_default_workflows(self):
        """Initialize default response workflows"""
        # Critical incident workflow
        critical_workflow = ResponseWorkflow(
            workflow_id="critical_incident",
            name="Critical Incident Response",
            description="Workflow for critical security incidents",
            incident_types=[IncidentType.SECURITY_BREACH, IncidentType.SYSTEM_COMPROMISE],
            severity_levels=[IncidentSeverity.CRITICAL],
            steps=[
                {
                    "step_id": "immediate_containment",
                    "name": "Immediate Containment",
                    "action": ResponseAction.ISOLATE_AGENT,
                    "timeout": 300,  # 5 minutes
                    "required": True
                },
                {
                    "step_id": "escalate_admin",
                    "name": "Escalate to Administrator",
                    "action": ResponseAction.ESCALATE_TO_ADMIN,
                    "timeout": 600,  # 10 minutes
                    "required": True
                },
                {
                    "step_id": "collect_evidence",
                    "name": "Collect Evidence",
                    "action": ResponseAction.COLLECT_EVIDENCE,
                    "timeout": 1800,  # 30 minutes
                    "required": True
                }
            ],
            escalation_rules=[
                {
                    "condition": "step_timeout",
                    "action": "escalate_to_security_team",
                    "timeout": 1800
                }
            ],
            sla_targets={
                "first_response": 300,    # 5 minutes
                "containment": 1800,      # 30 minutes
                "eradication": 7200,      # 2 hours
                "recovery": 14400         # 4 hours
            }
        )
        
        # Medium incident workflow
        medium_workflow = ResponseWorkflow(
            workflow_id="medium_incident",
            name="Medium Incident Response",
            description="Workflow for medium severity incidents",
            incident_types=[IncidentType.UNAUTHORIZED_ACCESS, IncidentType.POLICY_VIOLATION],
            severity_levels=[IncidentSeverity.MEDIUM],
            steps=[
                {
                    "step_id": "investigate",
                    "name": "Investigate Incident",
                    "action": ResponseAction.COLLECT_EVIDENCE,
                    "timeout": 3600,  # 1 hour
                    "required": True
                },
                {
                    "step_id": "contain_if_needed",
                    "name": "Contain if Necessary",
                    "action": ResponseAction.ISOLATE_AGENT,
                    "timeout": 7200,  # 2 hours
                    "required": False
                }
            ],
            escalation_rules=[
                {
                    "condition": "severity_increase",
                    "action": "upgrade_to_critical_workflow",
                    "threshold": 0.8
                }
            ],
            sla_targets={
                "first_response": 1800,   # 30 minutes
                "containment": 7200,      # 2 hours
                "eradication": 14400,     # 4 hours
                "recovery": 28800         # 8 hours
            }
        )
        
        self.workflows["critical_incident"] = critical_workflow
        self.workflows["medium_incident"] = medium_workflow
    
    def _start_background_processing(self):
        """Start background processing for incident response"""
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.processing_thread = threading.Thread(target=self._background_processor, daemon=True)
        self.processing_thread.start()
    
    def _background_processor(self):
        """Background processor for incident response tasks"""
        while True:
            try:
                # Process response queue
                if self.response_queue:
                    incident_id = self.response_queue.popleft()
                    asyncio.run(self._process_incident_response(incident_id))
                
                # Check for SLA violations
                self._check_sla_violations()
                
                # Update metrics
                self._update_metrics()
                
                time.sleep(1)  # Process every second
                
            except Exception as e:
                print(f"Error in background processor: {e}")
                time.sleep(5)
    
    async def create_incident(
        self,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        title: str,
        description: str,
        affected_agents: List[str] = None,
        affected_systems: List[str] = None,
        metadata: Dict[str, Any] = None
    ) -> str:
        """
        Create a new incident
        
        Args:
            incident_type: Type of incident
            severity: Severity level
            title: Incident title
            description: Incident description
            affected_agents: List of affected agent IDs
            affected_systems: List of affected system IDs
            metadata: Additional metadata
            
        Returns:
            Incident ID
        """
        incident_id = str(uuid.uuid4())
        current_time = time.time()
        
        incident = Incident(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.DETECTED,
            title=title,
            description=description,
            affected_agents=affected_agents or [],
            affected_systems=affected_systems or [],
            detected_at=current_time,
            metadata=metadata or {}
        )
        
        self.incidents[incident_id] = incident
        self.active_incidents.add(incident_id)
        
        # Initialize response metrics
        self.response_metrics[incident_id] = ResponseTimeMetrics(
            incident_id=incident_id,
            sla_target=self.sla_targets.get(severity, 3600)
        )
        
        # Add to response queue
        self.response_queue.append(incident_id)
        
        # Check for correlations
        await self._check_incident_correlations(incident_id)
        
        return incident_id
    
    async def _process_incident_response(self, incident_id: str):
        """Process incident response workflow"""
        if incident_id not in self.incidents:
            return
        
        incident = self.incidents[incident_id]
        
        # Find appropriate workflow
        workflow = self._find_workflow(incident)
        if not workflow:
            return
        
        # Execute workflow steps
        for step in workflow.steps:
            await self._execute_workflow_step(incident_id, step)
            
            # Check if incident is resolved
            if incident.status in [IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]:
                break
    
    def _find_workflow(self, incident: Incident) -> Optional[ResponseWorkflow]:
        """Find appropriate workflow for incident"""
        for workflow in self.workflows.values():
            if (incident.incident_type in workflow.incident_types and
                incident.severity in workflow.severity_levels):
                return workflow
        return None
    
    async def _execute_workflow_step(self, incident_id: str, step: Dict[str, Any]):
        """Execute a workflow step"""
        incident = self.incidents[incident_id]
        action = step.get("action")
        timeout = step.get("timeout", 3600)
        required = step.get("required", True)
        
        try:
            # Execute the action
            if action in self.response_handlers:
                success = await self.response_handlers[action](incident_id, step)
                if success:
                    incident.response_actions.append(action)
            else:
                # Default action handling
                success = await self._default_action_handler(action, incident_id, step)
            
            # Update incident status based on action
            if action == ResponseAction.ISOLATE_AGENT:
                incident.status = IncidentStatus.CONTAINED
                incident.containment_time = time.time()
            elif action == ResponseAction.COLLECT_EVIDENCE:
                incident.status = IncidentStatus.INVESTIGATING
            elif action == ResponseAction.ESCALATE_TO_ADMIN:
                incident.assigned_to = "admin"
            
        except Exception as e:
            print(f"Error executing workflow step {step.get('step_id')}: {e}")
            if required:
                # Escalate if required step fails
                await self._escalate_incident(incident_id, f"Required step failed: {step.get('step_id')}")
    
    async def _default_action_handler(self, action: ResponseAction, incident_id: str, step: Dict[str, Any]) -> bool:
        """Default action handler for response actions"""
        incident = self.incidents[incident_id]
        
        if action == ResponseAction.ISOLATE_AGENT:
            # Simulate agent isolation
            print(f"Isolating agents for incident {incident_id}: {incident.affected_agents}")
            return True
        
        elif action == ResponseAction.REVOKE_ACCESS:
            # Simulate access revocation
            print(f"Revoking access for incident {incident_id}")
            return True
        
        elif action == ResponseAction.ESCALATE_TO_ADMIN:
            # Simulate escalation
            print(f"Escalating incident {incident_id} to administrator")
            return True
        
        elif action == ResponseAction.NOTIFY_SECURITY_TEAM:
            # Simulate notification
            print(f"Notifying security team for incident {incident_id}")
            return True
        
        elif action == ResponseAction.COLLECT_EVIDENCE:
            # Simulate evidence collection
            print(f"Collecting evidence for incident {incident_id}")
            return True
        
        return False
    
    async def _escalate_incident(self, incident_id: str, reason: str):
        """Escalate incident"""
        if incident_id not in self.incidents:
            return
        
        incident = self.incidents[incident_id]
        
        # Increase severity if possible
        if incident.severity == IncidentSeverity.LOW:
            incident.severity = IncidentSeverity.MEDIUM
        elif incident.severity == IncidentSeverity.MEDIUM:
            incident.severity = IncidentSeverity.HIGH
        elif incident.severity == IncidentSeverity.HIGH:
            incident.severity = IncidentSeverity.CRITICAL
        
        # Add escalation to metadata
        if "escalations" not in incident.metadata:
            incident.metadata["escalations"] = []
        
        incident.metadata["escalations"].append({
            "timestamp": time.time(),
            "reason": reason,
            "new_severity": incident.severity.value
        })
        
        print(f"Escalated incident {incident_id} to {incident.severity.value}: {reason}")
    
    async def _check_incident_correlations(self, incident_id: str):
        """Check for incident correlations"""
        if incident_id not in self.incidents:
            return
        
        new_incident = self.incidents[incident_id]
        correlations = []
        
        # Check against existing incidents
        for existing_id, existing_incident in self.incidents.items():
            if existing_id == incident_id:
                continue
            
            # Check for correlations
            correlation_score = self._calculate_correlation_score(new_incident, existing_incident)
            
            if correlation_score > 0.7:  # High correlation threshold
                correlations.append({
                    "incident_id": existing_id,
                    "score": correlation_score,
                    "indicators": self._get_common_indicators(new_incident, existing_incident)
                })
        
        # Create correlation if found
        if correlations:
            correlation_id = str(uuid.uuid4())
            related_incidents = [c["incident_id"] for c in correlations]
            related_incidents.append(incident_id)
            
            correlation = IncidentCorrelation(
                correlation_id=correlation_id,
                related_incidents=related_incidents,
                correlation_type="pattern_match",
                confidence=max(c["score"] for c in correlations),
                pattern_description=f"Correlated incidents with {len(correlations)} matches",
                common_indicators=list(set().union(*[c["indicators"] for c in correlations])),
                timeline=self._build_correlation_timeline(related_incidents)
            )
            
            self.correlations.append(correlation)
            print(f"Created correlation {correlation_id} for incidents: {related_incidents}")
    
    def _calculate_correlation_score(self, incident1: Incident, incident2: Incident) -> float:
        """Calculate correlation score between two incidents"""
        score = 0.0
        
        # Same incident type
        if incident1.incident_type == incident2.incident_type:
            score += 0.3
        
        # Same affected agents
        common_agents = set(incident1.affected_agents) & set(incident2.affected_agents)
        if common_agents:
            score += 0.4 * (len(common_agents) / max(len(incident1.affected_agents), len(incident2.affected_agents)))
        
        # Same affected systems
        common_systems = set(incident1.affected_systems) & set(incident2.affected_systems)
        if common_systems:
            score += 0.2 * (len(common_systems) / max(len(incident1.affected_systems), len(incident2.affected_systems)))
        
        # Time proximity (within 24 hours)
        time_diff = abs(incident1.detected_at - incident2.detected_at)
        if time_diff < 86400:  # 24 hours
            score += 0.1 * (1.0 - time_diff / 86400)
        
        return min(1.0, score)
    
    def _get_common_indicators(self, incident1: Incident, incident2: Incident) -> List[str]:
        """Get common indicators between incidents"""
        indicators = []
        
        # Common agents
        common_agents = set(incident1.affected_agents) & set(incident2.affected_agents)
        if common_agents:
            indicators.append(f"Common affected agents: {list(common_agents)}")
        
        # Common systems
        common_systems = set(incident1.affected_systems) & set(incident2.affected_systems)
        if common_systems:
            indicators.append(f"Common affected systems: {list(common_systems)}")
        
        # Same incident type
        if incident1.incident_type == incident2.incident_type:
            indicators.append(f"Same incident type: {incident1.incident_type.value}")
        
        return indicators
    
    def _build_correlation_timeline(self, incident_ids: List[str]) -> List[Dict[str, Any]]:
        """Build timeline for correlated incidents"""
        timeline = []
        
        for incident_id in incident_ids:
            if incident_id in self.incidents:
                incident = self.incidents[incident_id]
                timeline.append({
                    "incident_id": incident_id,
                    "timestamp": incident.detected_at,
                    "type": incident.incident_type.value,
                    "severity": incident.severity.value,
                    "status": incident.status.value
                })
        
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline
    
    def _check_sla_violations(self):
        """Check for SLA violations"""
        current_time = time.time()
        
        for incident_id, metrics in self.response_metrics.items():
            if incident_id not in self.incidents:
                continue
            
            incident = self.incidents[incident_id]
            
            # Check first response SLA
            if incident.status != IncidentStatus.DETECTED and not metrics.detection_to_response:
                time_since_detection = current_time - incident.detected_at
                if time_since_detection > metrics.sla_target:
                    print(f"SLA violation: First response overdue for incident {incident_id}")
                    # Trigger escalation
                    asyncio.create_task(self._escalate_incident(incident_id, "SLA violation: First response overdue"))
    
    def _update_metrics(self):
        """Update response time metrics"""
        current_time = time.time()
        
        for incident_id, metrics in self.response_metrics.items():
            if incident_id not in self.incidents:
                continue
            
            incident = self.incidents[incident_id]
            
            # Update detection to response time
            if incident.first_response_time and not metrics.detection_to_response:
                metrics.detection_to_response = incident.first_response_time - incident.detected_at
            
            # Update response to containment time
            if incident.containment_time and not metrics.response_to_containment:
                metrics.response_to_containment = incident.containment_time - (incident.first_response_time or incident.detected_at)
            
            # Update containment to eradication time
            if incident.eradication_time and not metrics.containment_to_eradication:
                metrics.containment_to_eradication = incident.eradication_time - incident.containment_time
            
            # Update eradication to recovery time
            if incident.recovery_time and not metrics.eradication_to_recovery:
                metrics.eradication_to_recovery = incident.recovery_time - incident.eradication_time
            
            # Update total resolution time
            if incident.closed_at and not metrics.total_resolution_time:
                metrics.total_resolution_time = incident.closed_at - incident.detected_at
                metrics.sla_compliance = metrics.total_resolution_time <= metrics.sla_target
            
            # Add to metrics history
            if metrics.total_resolution_time:
                self.metrics_history.append({
                    "incident_id": incident_id,
                    "severity": incident.severity.value,
                    "type": incident.incident_type.value,
                    "total_time": metrics.total_resolution_time,
                    "sla_compliance": metrics.sla_compliance,
                    "timestamp": current_time
                })
    
    def update_incident_status(self, incident_id: str, status: IncidentStatus, notes: str = None):
        """Update incident status"""
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        old_status = incident.status
        incident.status = status
        
        # Update timestamps based on status
        current_time = time.time()
        
        if status == IncidentStatus.INVESTIGATING and not incident.first_response_time:
            incident.first_response_time = current_time
        elif status == IncidentStatus.CONTAINED and not incident.containment_time:
            incident.containment_time = current_time
        elif status == IncidentStatus.ERADICATED and not incident.eradication_time:
            incident.eradication_time = current_time
        elif status == IncidentStatus.RECOVERED and not incident.recovery_time:
            incident.recovery_time = current_time
        elif status in [IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE] and not incident.closed_at:
            incident.closed_at = current_time
            self.active_incidents.discard(incident_id)
        
        # Add status change to metadata
        if "status_changes" not in incident.metadata:
            incident.metadata["status_changes"] = []
        
        incident.metadata["status_changes"].append({
            "timestamp": current_time,
            "old_status": old_status.value,
            "new_status": status.value,
            "notes": notes
        })
        
        return True
    
    def add_evidence(self, incident_id: str, evidence: Dict[str, Any]):
        """Add evidence to incident"""
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        evidence["timestamp"] = time.time()
        incident.evidence.append(evidence)
        
        return True
    
    def assign_incident(self, incident_id: str, assignee: str):
        """Assign incident to a responder"""
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        incident.assigned_to = assignee
        
        return True
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        return self.incidents.get(incident_id)
    
    def get_active_incidents(self) -> List[Incident]:
        """Get all active incidents"""
        return [self.incidents[incident_id] for incident_id in self.active_incidents if incident_id in self.incidents]
    
    def get_incident_metrics(self, incident_id: str) -> Optional[ResponseTimeMetrics]:
        """Get response time metrics for incident"""
        return self.response_metrics.get(incident_id)
    
    def get_overall_metrics(self) -> Dict[str, Any]:
        """Get overall incident response metrics"""
        if not self.metrics_history:
            return {}
        
        # Calculate average response times by severity
        severity_metrics = defaultdict(list)
        for metric in self.metrics_history:
            severity_metrics[metric["severity"]].append(metric["total_time"])
        
        avg_times = {}
        for severity, times in severity_metrics.items():
            avg_times[severity] = sum(times) / len(times)
        
        # Calculate SLA compliance rate
        total_incidents = len(self.metrics_history)
        compliant_incidents = sum(1 for m in self.metrics_history if m["sla_compliance"])
        compliance_rate = compliant_incidents / total_incidents if total_incidents > 0 else 0
        
        return {
            "total_incidents": total_incidents,
            "active_incidents": len(self.active_incidents),
            "sla_compliance_rate": compliance_rate,
            "average_response_times": avg_times,
            "correlations_found": len(self.correlations),
            "workflows_available": len(self.workflows)
        }
    
    def register_response_handler(self, action: ResponseAction, handler: Callable):
        """Register a custom response handler"""
        self.response_handlers[action] = handler
    
    def export_incident_data(self, file_path: str) -> bool:
        """Export incident data to file"""
        try:
            export_data = {
                "incidents": {
                    incident_id: {
                        "incident_id": incident.incident_id,
                        "incident_type": incident.incident_type.value,
                        "severity": incident.severity.value,
                        "status": incident.status.value,
                        "title": incident.title,
                        "description": incident.description,
                        "affected_agents": incident.affected_agents,
                        "affected_systems": incident.affected_systems,
                        "detected_at": incident.detected_at,
                        "first_response_time": incident.first_response_time,
                        "containment_time": incident.containment_time,
                        "eradication_time": incident.eradication_time,
                        "recovery_time": incident.recovery_time,
                        "closed_at": incident.closed_at,
                        "assigned_to": incident.assigned_to,
                        "evidence": incident.evidence,
                        "response_actions": [action.value for action in incident.response_actions],
                        "tags": list(incident.tags),
                        "metadata": incident.metadata
                    }
                    for incident_id, incident in self.incidents.items()
                },
                "response_metrics": {
                    incident_id: {
                        "incident_id": metrics.incident_id,
                        "detection_to_response": metrics.detection_to_response,
                        "response_to_containment": metrics.response_to_containment,
                        "containment_to_eradication": metrics.containment_to_eradication,
                        "eradication_to_recovery": metrics.eradication_to_recovery,
                        "total_resolution_time": metrics.total_resolution_time,
                        "sla_compliance": metrics.sla_compliance,
                        "sla_target": metrics.sla_target
                    }
                    for incident_id, metrics in self.response_metrics.items()
                },
                "correlations": [
                    {
                        "correlation_id": corr.correlation_id,
                        "related_incidents": corr.related_incidents,
                        "correlation_type": corr.correlation_type,
                        "confidence": corr.confidence,
                        "pattern_description": corr.pattern_description,
                        "common_indicators": corr.common_indicators,
                        "timeline": corr.timeline
                    }
                    for corr in self.correlations
                ],
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting incident data: {e}")
            return False
