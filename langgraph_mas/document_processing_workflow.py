"""
Document Processing Workflow for LangGraph MAS

This module implements a real document processing pipeline using LangGraph agents
with MCP tool integration and trust-aware task allocation.
"""

import asyncio
import time
import json
import base64
import hashlib
from typing import Dict, List, Optional, Any, TypedDict
from dataclasses import dataclass
from pathlib import Path
import mimetypes

# Document processing imports
import PyPDF2
from PIL import Image
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available, using fallback document type detection")

# Import our modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langgraph_mas.secure_langgraph_agent import SecureLangGraphAgent
from security.authentication.identity_management import IdentityManager, AgentType
from trust.trust_calculator import TrustCalculator, TrustEvent, TrustEventType
from integration.mcp_security_gateway import MCPSecurityGateway
from config.env_config import config


@dataclass
class DocumentTask:
    """Document processing task"""
    task_id: str
    document_path: str
    document_type: str
    task_type: str
    description: str
    parameters: Dict[str, Any]
    priority: str = "normal"
    created_at: float = 0.0
    assigned_agent: Optional[str] = None
    status: str = "pending"  # pending, in_progress, completed, failed
    result: Optional[Dict[str, Any]] = None


class DocumentProcessor:
    """
    Document processor for handling various document types
    """
    
    def __init__(self):
        """Initialize document processor"""
        self.supported_formats = config.SUPPORTED_FORMATS
        self.max_file_size = self._parse_file_size(config.MAX_FILE_SIZE)
    
    def _parse_file_size(self, size_str: str) -> int:
        """Parse file size string to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('B'):
            return int(size_str[:-1])
        else:
            return int(size_str)
    
    def detect_document_type(self, file_path: str) -> str:
        """Detect document type from file"""
        try:
            # Use file extension for detection (more reliable than magic)
            ext = Path(file_path).suffix.lower()
            
            if ext == '.pdf':
                return 'pdf'
            elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
                return 'image'
            elif ext == '.txt':
                return 'text'
            elif ext == '.docx':
                return 'docx'
            elif ext == '.json':
                return 'json'
            elif ext in ['.csv', '.xlsx']:
                return 'data'
            
            # Fallback: try to get MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                if mime_type == 'application/pdf':
                    return 'pdf'
                elif mime_type.startswith('image/'):
                    return 'image'
                elif mime_type == 'text/plain':
                    return 'text'
                elif mime_type in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                    return 'docx'
            
            return 'unknown'
            
        except Exception as e:
            print(f"Error detecting document type: {e}")
            return 'unknown'
    
    def validate_document(self, file_path: str) -> Dict[str, Any]:
        """Validate document for processing"""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "file_size": 0,
            "document_type": "unknown"
        }
        
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                validation_result["valid"] = False
                validation_result["errors"].append("File does not exist")
                return validation_result
            
            # Check file size
            file_size = os.path.getsize(file_path)
            validation_result["file_size"] = file_size
            
            if file_size > self.max_file_size:
                validation_result["valid"] = False
                validation_result["errors"].append(f"File too large: {file_size} bytes (max: {self.max_file_size})")
                return validation_result
            
            # Detect document type
            doc_type = self.detect_document_type(file_path)
            validation_result["document_type"] = doc_type
            
            # Check if document type is supported
            supported_types = ['pdf', 'image', 'text', 'docx', 'json', 'data']
            if doc_type not in supported_types:
                validation_result["valid"] = False
                validation_result["errors"].append(f"Unsupported document type: {doc_type}")
                return validation_result
            
            # Type-specific validation
            if doc_type == 'pdf':
                self._validate_pdf(file_path, validation_result)
            elif doc_type == 'image':
                self._validate_image(file_path, validation_result)
            elif doc_type == 'text':
                self._validate_text(file_path, validation_result)
            
        except Exception as e:
            validation_result["valid"] = False
            validation_result["errors"].append(f"Validation error: {str(e)}")
        
        return validation_result
    
    def _validate_pdf(self, file_path: str, validation_result: Dict[str, Any]):
        """Validate PDF file"""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                if len(pdf_reader.pages) == 0:
                    validation_result["warnings"].append("PDF has no pages")
                elif len(pdf_reader.pages) > 100:
                    validation_result["warnings"].append("PDF has many pages, processing may be slow")
        except Exception as e:
            validation_result["errors"].append(f"PDF validation failed: {str(e)}")
    
    def _validate_image(self, file_path: str, validation_result: Dict[str, Any]):
        """Validate image file"""
        try:
            with Image.open(file_path) as img:
                width, height = img.size
                if width > 4000 or height > 4000:
                    validation_result["warnings"].append("Image is very large, processing may be slow")
        except Exception as e:
            validation_result["errors"].append(f"Image validation failed: {str(e)}")
    
    def _validate_text(self, file_path: str, validation_result: Dict[str, Any]):
        """Validate text file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read(1000)  # Read first 1000 characters
                if len(content) == 0:
                    validation_result["warnings"].append("Text file appears to be empty")
        except Exception as e:
            validation_result["errors"].append(f"Text validation failed: {str(e)}")
    
    def extract_document_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from document"""
        metadata = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "document_type": self.detect_document_type(file_path),
            "created_at": time.time()
        }
        
        try:
            doc_type = metadata["document_type"]
            
            if doc_type == 'pdf':
                metadata.update(self._extract_pdf_metadata(file_path))
            elif doc_type == 'image':
                metadata.update(self._extract_image_metadata(file_path))
            elif doc_type == 'text':
                metadata.update(self._extract_text_metadata(file_path))
            
        except Exception as e:
            print(f"Error extracting metadata: {e}")
        
        return metadata
    
    def _extract_pdf_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract PDF metadata"""
        metadata = {}
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                metadata["page_count"] = len(pdf_reader.pages)
                
                if pdf_reader.metadata:
                    metadata["title"] = pdf_reader.metadata.get("/Title", "")
                    metadata["author"] = pdf_reader.metadata.get("/Author", "")
                    metadata["subject"] = pdf_reader.metadata.get("/Subject", "")
                    metadata["creator"] = pdf_reader.metadata.get("/Creator", "")
        except Exception as e:
            print(f"Error extracting PDF metadata: {e}")
        
        return metadata
    
    def _extract_image_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract image metadata"""
        metadata = {}
        try:
            with Image.open(file_path) as img:
                metadata["width"] = img.width
                metadata["height"] = img.height
                metadata["format"] = img.format
                metadata["mode"] = img.mode
                
                if hasattr(img, '_getexif') and img._getexif():
                    exif = img._getexif()
                    if exif:
                        metadata["has_exif"] = True
        except Exception as e:
            print(f"Error extracting image metadata: {e}")
        
        return metadata
    
    def _extract_text_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract text metadata"""
        metadata = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                metadata["character_count"] = len(content)
                metadata["line_count"] = len(content.splitlines())
                metadata["word_count"] = len(content.split())
        except Exception as e:
            print(f"Error extracting text metadata: {e}")
        
        return metadata


class DocumentProcessingMAS:
    """
    Multi-Agent System for Document Processing using LangGraph
    
    This system coordinates multiple LangGraph agents to process documents
    using MCP tools with trust-aware task allocation.
    """
    
    def __init__(
        self,
        identity_manager: IdentityManager,
        trust_calculator: TrustCalculator,
        mcp_gateway: MCPSecurityGateway
    ):
        """Initialize document processing MAS"""
        self.identity_manager = identity_manager
        self.trust_calculator = trust_calculator
        self.mcp_gateway = mcp_gateway
        self.document_processor = DocumentProcessor()
        
        # Agent management
        self.agents: List[SecureLangGraphAgent] = []
        self.agent_capabilities = {
            "document_analyzer": ["document_analysis", "content_extraction", "metadata_extraction"],
            "data_processor": ["data_processing", "data_validation", "data_transformation"],
            "insight_generator": ["data_analysis", "insight_generation", "pattern_recognition"],
            "report_creator": ["report_generation", "document_creation", "formatting"]
        }
        
        # Task management
        self.pending_tasks: List[DocumentTask] = []
        self.completed_tasks: List[DocumentTask] = []
        self.failed_tasks: List[DocumentTask] = []
    
    async def initialize_agents(self) -> None:
        """Initialize LangGraph agents for document processing"""
        print("Initializing LangGraph agents for document processing...")
        
        for agent_id, capabilities in self.agent_capabilities.items():
            # Create agent
            agent = SecureLangGraphAgent(
                agent_id=agent_id,
                agent_type=AgentType.WORKER,
                capabilities=capabilities,
                llm_model="gemini-1.5-flash",
                system_prompt=self._get_agent_system_prompt(agent_id, capabilities)
            )
            
            # Register agent
            await agent.register_with_system(self.identity_manager, self.mcp_gateway)
            
            # Bootstrap trust
            await self._bootstrap_agent_trust(agent)
            
            self.agents.append(agent)
            print(f"  Initialized agent: {agent_id} with capabilities: {capabilities}")
        
        print(f"Initialized {len(self.agents)} LangGraph agents")
    
    def _get_agent_system_prompt(self, agent_id: str, capabilities: List[str]) -> str:
        """Get system prompt for specific agent"""
        prompts = {
            "document_analyzer": f"""You are {agent_id}, a specialized document analysis agent.

Your primary capabilities: {', '.join(capabilities)}

Your role is to:
1. Analyze documents and extract key information
2. Identify document structure and content
3. Extract metadata and important details
4. Prepare data for further processing

Focus on accuracy and completeness in your analysis.""",

            "data_processor": f"""You are {agent_id}, a specialized data processing agent.

Your primary capabilities: {', '.join(capabilities)}

Your role is to:
1. Process and clean extracted data
2. Validate data quality and integrity
3. Transform data into structured formats
4. Ensure data consistency and accuracy

Focus on data quality and processing efficiency.""",

            "insight_generator": f"""You are {agent_id}, a specialized insight generation agent.

Your primary capabilities: {', '.join(capabilities)}

Your role is to:
1. Analyze processed data for patterns and trends
2. Generate meaningful insights and conclusions
3. Identify key findings and recommendations
4. Create summaries and highlights

Focus on generating valuable and actionable insights.""",

            "report_creator": f"""You are {agent_id}, a specialized report creation agent.

Your primary capabilities: {', '.join(capabilities)}

Your role is to:
1. Create comprehensive reports from processed data
2. Format information in clear, readable formats
3. Generate visualizations and summaries
4. Ensure professional presentation quality

Focus on clarity, completeness, and professional presentation."""
        }
        
        return prompts.get(agent_id, f"You are {agent_id} with capabilities: {', '.join(capabilities)}")
    
    async def _bootstrap_agent_trust(self, agent: SecureLangGraphAgent) -> None:
        """Bootstrap trust for new agent"""
        # Give initial trust events
        initial_events = [
            TrustEvent(
                event_id=f"bootstrap_{agent.agent_id}_1",
                agent_id=agent.agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=time.time() - 3600,
                value=0.8,
                context={"type": "bootstrap", "framework": "langgraph"}
            ),
            TrustEvent(
                event_id=f"bootstrap_{agent.agent_id}_2",
                agent_id=agent.agent_id,
                event_type=TrustEventType.COOPERATION_POSITIVE,
                timestamp=time.time() - 1800,
                value=0.7,
                context={"type": "bootstrap", "framework": "langgraph"}
            )
        ]
        
        for event in initial_events:
            self.trust_calculator.add_trust_event(event)
    
    async def process_document(self, document_path: str, processing_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Process a document using the MAS"""
        print(f"Processing document: {document_path}")
        
        # Validate document
        validation = self.document_processor.validate_document(document_path)
        if not validation["valid"]:
            return {
                "success": False,
                "error": f"Document validation failed: {validation['errors']}",
                "validation": validation
            }
        
        # Extract metadata
        metadata = self.document_processor.extract_document_metadata(document_path)
        
        # Create processing tasks
        tasks = await self._create_processing_tasks(document_path, metadata, processing_options or {})
        
        # Execute tasks with trust-aware allocation
        results = await self._execute_tasks_with_trust_allocation(tasks)
        
        # Aggregate results
        final_result = await self._aggregate_results(results, metadata)
        
        return final_result
    
    async def _create_processing_tasks(
        self, 
        document_path: str, 
        metadata: Dict[str, Any], 
        options: Dict[str, Any]
    ) -> List[DocumentTask]:
        """Create processing tasks for the document"""
        tasks = []
        doc_type = metadata["document_type"]
        
        # Task 1: Document Analysis
        tasks.append(DocumentTask(
            task_id=f"analyze_{int(time.time())}",
            document_path=document_path,
            document_type=doc_type,
            task_type="document_analysis",
            description=f"Analyze {doc_type} document and extract key information",
            parameters={
                "file_path": document_path,
                "document_type": doc_type,
                "extract_metadata": True,
                "extract_content": True
            }
        ))
        
        # Task 2: Data Processing
        tasks.append(DocumentTask(
            task_id=f"process_{int(time.time())}",
            document_path=document_path,
            document_type=doc_type,
            task_type="data_processing",
            description=f"Process and clean extracted data from {doc_type} document",
            parameters={
                "input_data": "from_analysis_task",
                "processing_type": "clean_and_validate",
                "output_format": "structured"
            }
        ))
        
        # Task 3: Insight Generation
        tasks.append(DocumentTask(
            task_id=f"insights_{int(time.time())}",
            document_path=document_path,
            document_type=doc_type,
            task_type="insight_generation",
            description=f"Generate insights and analysis from processed {doc_type} document",
            parameters={
                "input_data": "from_processing_task",
                "analysis_type": "comprehensive",
                "include_recommendations": True
            }
        ))
        
        # Task 4: Report Creation
        tasks.append(DocumentTask(
            task_id=f"report_{int(time.time())}",
            document_path=document_path,
            document_type=doc_type,
            task_type="report_creation",
            description=f"Create comprehensive report from {doc_type} document analysis",
            parameters={
                "input_data": "from_insights_task",
                "report_format": "comprehensive",
                "include_visualizations": True
            }
        ))
        
        return tasks
    
    async def _execute_tasks_with_trust_allocation(self, tasks: List[DocumentTask]) -> List[Dict[str, Any]]:
        """Execute tasks using trust-aware allocation"""
        results = []
        
        for task in tasks:
            # Find best agent for task
            best_agent = await self._find_best_agent_for_task(task)
            
            if best_agent:
                print(f"Allocating task {task.task_id} to agent {best_agent.agent_id}")
                
                # Execute task
                result = await best_agent.execute_task(
                    task_id=task.task_id,
                    task_type=task.task_type,
                    task_description=task.description,
                    parameters=task.parameters,
                    mcp_gateway=self.mcp_gateway,
                    trust_calculator=self.trust_calculator
                )
                
                results.append(result)
                
                # Update task status
                if result["success"]:
                    task.status = "completed"
                    task.result = result
                    self.completed_tasks.append(task)
                else:
                    task.status = "failed"
                    self.failed_tasks.append(task)
            else:
                print(f"No suitable agent found for task: {task.task_id}")
                task.status = "failed"
                self.failed_tasks.append(task)
        
        return results
    
    async def _find_best_agent_for_task(self, task: DocumentTask) -> Optional[SecureLangGraphAgent]:
        """Find the best agent for a task using trust-aware allocation"""
        suitable_agents = []
        
        for agent in self.agents:
            # Check if agent has required capabilities
            if not self._agent_has_capabilities(agent, task):
                continue
            
            # Get trust score
            trust_score = agent.get_trust_score(self.trust_calculator)
            if trust_score and trust_score > config.TRUST_THRESHOLD:
                suitable_agents.append((agent, trust_score))
            else:
                # Use default score for agents without sufficient trust
                suitable_agents.append((agent, 0.5))
        
        if not suitable_agents:
            return None
        
        # Sort by trust score (highest first)
        suitable_agents.sort(key=lambda x: x[1], reverse=True)
        return suitable_agents[0][0]
    
    def _agent_has_capabilities(self, agent: SecureLangGraphAgent, task: DocumentTask) -> bool:
        """Check if agent has required capabilities for task"""
        task_type_lower = task.task_type.lower()
        return any(cap.lower() in task_type_lower for cap in agent.capabilities)
    
    async def _aggregate_results(self, results: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate results from all tasks"""
        successful_results = [r for r in results if r["success"]]
        failed_results = [r for r in results if not r["success"]]
        
        return {
            "success": len(failed_results) == 0,
            "document_metadata": metadata,
            "processing_summary": {
                "total_tasks": len(results),
                "successful_tasks": len(successful_results),
                "failed_tasks": len(failed_results),
                "success_rate": len(successful_results) / len(results) if results else 0
            },
            "task_results": results,
            "final_insights": self._extract_final_insights(successful_results),
            "processing_time": sum(r.get("execution_time", 0) for r in results),
            "timestamp": time.time()
        }
    
    def _extract_final_insights(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract final insights from successful results"""
        insights = {
            "document_analysis": None,
            "data_processing": None,
            "insights_generation": None,
            "report_creation": None
        }
        
        for result in results:
            task_id = result.get("task_id", "")
            if "analyze" in task_id:
                insights["document_analysis"] = result.get("result")
            elif "process" in task_id:
                insights["data_processing"] = result.get("result")
            elif "insights" in task_id:
                insights["insight_generation"] = result.get("result")
            elif "report" in task_id:
                insights["report_creation"] = result.get("result")
        
        return insights
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        return {
            "agents": len(self.agents),
            "agent_stats": [agent.get_stats() for agent in self.agents],
            "completed_tasks": len(self.completed_tasks),
            "failed_tasks": len(self.failed_tasks),
            "trust_ranking": self.trust_calculator.get_trust_ranking(),
            "sybil_agents": self.trust_calculator.detect_sybil_agents(),
            "audit_log_entries": len(self.mcp_gateway.get_audit_log())
        }


# Example usage and testing
async def main():
    """Example usage of DocumentProcessingMAS"""
    from security.authentication.identity_management import IdentityManager
    from trust.trust_calculator import TrustCalculator
    from integration.mcp_security_gateway import MCPSecurityGateway
    
    # Initialize system components
    identity_manager = IdentityManager()
    trust_calculator = TrustCalculator(min_events=1)
    
    async with MCPSecurityGateway() as mcp_gateway:
        # Create document processing MAS
        mas = DocumentProcessingMAS(identity_manager, trust_calculator, mcp_gateway)
        
        # Initialize agents
        await mas.initialize_agents()
        
        # Process a sample document (you would provide a real file path)
        sample_document = "sample_document.pdf"  # Replace with actual file path
        
        if os.path.exists(sample_document):
            result = await mas.process_document(sample_document)
            print(f"Document processing result: {json.dumps(result, indent=2)}")
        else:
            print(f"Sample document not found: {sample_document}")
        
        # Show system stats
        stats = mas.get_system_stats()
        print(f"System stats: {json.dumps(stats, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())
