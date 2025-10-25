"""
Hugging Face Model Integration with MCP Security Framework
=========================================================

This demo shows how to integrate Hugging Face models with the MCP Security Framework
to create secure, intelligent agents with real ML capabilities.
"""

import asyncio
import time
import logging
import os
from typing import Dict, List, Optional, Any
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch

# Import MCP Security Framework components
from mcp_security_framework import (
    IdentityManager, TrustCalculator, MCPSecurityGateway,
    PolicyEngine, ToolRegistry, LangGraphSecurityAdapter,
    AgentType, TrustEventType
)
from mcp_security_framework.core.real_gateway import RealMCPSecurityGateway
from mcp_security_framework.core.registry import ToolManifest, ToolStatus

# Import HF configuration
from hf_config import setup_huggingface

class HFSecureAgent:
    """
    A secure agent that integrates Hugging Face models with MCP Security Framework
    """
    
    def __init__(self, agent_id: str, model_name: str = "distilbert-base-uncased-finetuned-sst-2-english"):
        self.agent_id = agent_id
        self.model_name = model_name
        self.logger = logging.getLogger(__name__)
        
        # Initialize HF authentication
        self.hf_authenticated = setup_huggingface()
        
        # Initialize MCP Security Framework
        self.identity_manager = IdentityManager()
        self.trust_calculator = TrustCalculator()
        self.mcp_gateway = RealMCPSecurityGateway()
        self.policy_engine = PolicyEngine()
        self.tool_registry = ToolRegistry()
        
        # Create security adapter
        self.security_adapter = LangGraphSecurityAdapter(
            identity_manager=self.identity_manager,
            trust_calculator=self.trust_calculator,
            policy_engine=self.policy_engine,
            mcp_gateway=self.mcp_gateway,
            tool_registry=self.tool_registry
        )
        
        # Initialize HF model
        self.model = None
        self.tokenizer = None
        self.classifier = None
        self._load_model()
        
        # Agent capabilities
        self.capabilities = [
            "text_classification", "sentiment_analysis", "secure_tool_execution",
            "trust_calculation", "security_monitoring"
        ]
        
        # Performance metrics
        self.metrics = {
            "requests_processed": 0,
            "successful_predictions": 0,
            "security_violations": 0,
            "average_response_time": 0.0
        }
    
    def _load_model(self):
        """Load Hugging Face model and tokenizer"""
        try:
            if not self.hf_authenticated:
                raise Exception("Hugging Face authentication failed")
            
            print(f"🔄 Loading model: {self.model_name}")
            
            # Load tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name, 
                use_auth_token=True
            )
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                use_auth_token=True
            )
            
            # Create pipeline for easy inference
            self.classifier = pipeline(
                "sentiment-analysis",
                model=self.model,
                tokenizer=self.tokenizer,
                return_all_scores=True
            )
            
            print(f"✅ Model loaded successfully: {self.model_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            print(f"❌ Model loading failed: {e}")
            self.model = None
            self.tokenizer = None
            self.classifier = None
    
    async def register_agent(self):
        """Register this agent with the security framework"""
        try:
            success, message = await self.security_adapter.register_agent(
                agent_id=self.agent_id,
                agent_type="worker",
                capabilities=self.capabilities,
                metadata={
                    "model": self.model_name,
                    "framework": "huggingface",
                    "security_level": "high"
                }
            )
            
            if success:
                print(f"✅ Agent registered: {message}")
                return True
            else:
                print(f"❌ Agent registration failed: {message}")
                return False
                
        except Exception as e:
            self.logger.error(f"Agent registration error: {e}")
            return False
    
    async def authenticate(self):
        """Authenticate the agent"""
        try:
            authenticated = await self.security_adapter.authenticate_agent(
                agent_id=self.agent_id,
                credentials={"auth_token": f"hf_{self.agent_id}"}
            )
            
            if authenticated:
                print(f"✅ Agent authenticated: {self.agent_id}")
                return True
            else:
                print(f"❌ Authentication failed: {self.agent_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    async def analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """
        Analyze sentiment of text using HF model with security controls
        """
        start_time = time.time()
        
        try:
            # Security check: validate input
            if not text or len(text.strip()) == 0:
                raise ValueError("Empty text input")
            
            if len(text) > 1000:  # Security limit
                raise ValueError("Text too long (max 1000 characters)")
            
            # Check if model is available
            if not self.classifier:
                raise Exception("Model not loaded")
            
            # Perform sentiment analysis
            results = self.classifier(text)
            
            # Process results
            sentiment_data = {
                "text": text[:100] + "..." if len(text) > 100 else text,
                "sentiment_scores": results[0],
                "predicted_label": max(results[0], key=lambda x: x['score'])['label'],
                "confidence": max(results[0], key=lambda x: x['score'])['score'],
                "processing_time": time.time() - start_time
            }
            
            # Update metrics
            self.metrics["requests_processed"] += 1
            self.metrics["successful_predictions"] += 1
            self.metrics["average_response_time"] = (
                (self.metrics["average_response_time"] * (self.metrics["requests_processed"] - 1) + 
                 sentiment_data["processing_time"]) / self.metrics["requests_processed"]
            )
            
            # Report positive trust event
            await self.security_adapter.report_trust_event(
                agent_id=self.agent_id,
                event_type="task_success",
                event_data={
                    "value": sentiment_data["confidence"],
                    "context": {
                        "task": "sentiment_analysis",
                        "quality": "high" if sentiment_data["confidence"] > 0.8 else "medium"
                    }
                }
            )
            
            return {
                "success": True,
                "data": sentiment_data,
                "security_status": "secure"
            }
            
        except Exception as e:
            self.logger.error(f"Sentiment analysis error: {e}")
            
            # Report negative trust event
            await self.security_adapter.report_trust_event(
                agent_id=self.agent_id,
                event_type="task_failure",
                event_data={
                    "value": 0.1,
                    "context": {"error": str(e), "task": "sentiment_analysis"}
                }
            )
            
            self.metrics["requests_processed"] += 1
            
            return {
                "success": False,
                "error": str(e),
                "security_status": "error"
            }
    
    async def secure_tool_execution(self, tool_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute tools through the security framework
        """
        try:
            # Request tool access
            allowed, reason = await self.security_adapter.request_tool_access(
                agent_id=self.agent_id,
                tool_id=tool_id,
                operation="execute",
                parameters=parameters
            )
            
            if not allowed:
                self.metrics["security_violations"] += 1
                return {
                    "success": False,
                    "error": f"Access denied: {reason}",
                    "security_status": "blocked"
                }
            
            # Execute tool
            result = await self.security_adapter.execute_tool(
                agent_id=self.agent_id,
                tool_id=tool_id,
                parameters=parameters
            )
            
            return {
                "success": result.get("success", False),
                "data": result.get("result"),
                "security_status": "secure"
            }
            
        except Exception as e:
            self.logger.error(f"Tool execution error: {e}")
            return {
                "success": False,
                "error": str(e),
                "security_status": "error"
            }
    
    def get_trust_score(self) -> Optional[Dict[str, Any]]:
        """Get current trust score"""
        try:
            trust_score = self.trust_calculator.get_trust_score(self.agent_id)
            if trust_score:
                return {
                    "overall_score": trust_score.overall_score,
                    "confidence": trust_score.confidence,
                    "event_count": trust_score.event_count,
                    "dimensions": {
                        "competence": trust_score.competence,
                        "reliability": trust_score.reliability,
                        "honesty": trust_score.honesty,
                        "cooperation": trust_score.cooperation,
                        "security": trust_score.security
                    }
                }
            return None
        except Exception as e:
            self.logger.error(f"Trust score error: {e}")
            return None
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        return {
            **self.metrics,
            "model_loaded": self.model is not None,
            "hf_authenticated": self.hf_authenticated,
            "capabilities": self.capabilities
        }


async def register_demo_tools(tool_registry: ToolRegistry):
    """Register demo tools for the agent to use"""
    
    tools = [
        ToolManifest(
            tool_id="text_processor",
            name="Text Processor",
            version="1.0.0",
            description="Processes and analyzes text content",
            author="HF Agent Demo",
            capabilities=["text_processing", "nlp"],
            parameters={
                "text": {"type": "string", "required": True},
                "operation": {"type": "string", "required": True}
            },
            risk_level="low",
            security_requirements=["input_validation", "access_logging"],
            dependencies=["transformers", "torch"]
        ),
        ToolManifest(
            tool_id="data_analyzer",
            name="Data Analyzer",
            version="1.0.0",
            description="Analyzes structured data",
            author="HF Agent Demo",
            capabilities=["data_analysis", "statistics"],
            parameters={
                "data": {"type": "object", "required": True},
                "analysis_type": {"type": "string", "required": True}
            },
            risk_level="medium",
            security_requirements=["data_encryption", "access_logging"],
            dependencies=["pandas", "numpy"]
        ),
        ToolManifest(
            tool_id="security_monitor",
            name="Security Monitor",
            version="1.0.0",
            description="Monitors security events and metrics",
            author="HF Agent Demo",
            capabilities=["security_monitoring", "audit_logging"],
            parameters={
                "monitor_type": {"type": "string", "required": True},
                "duration": {"type": "integer", "required": False}
            },
            risk_level="high",
            security_requirements=["privileged_access", "audit_logging"],
            dependencies=["psutil", "logging"]
        )
    ]
    
    for tool in tools:
        success, message = tool_registry.register_tool(tool)
        if success:
            print(f"✅ Registered tool: {tool.tool_id}")
        else:
            print(f"❌ Failed to register tool {tool.tool_id}: {message}")


async def main():
    """Main demo function"""
    print("🚀 Hugging Face + MCP Security Framework Demo")
    print("=" * 60)
    
    # Initialize agent
    agent = HFSecureAgent("hf_sentiment_agent", "distilbert-base-uncased-finetuned-sst-2-english")
    
    # Register and authenticate agent
    print("\n📝 Registering and authenticating agent...")
    await agent.register_agent()
    await agent.authenticate()
    
    # Register demo tools
    print("\n🔧 Registering demo tools...")
    await register_demo_tools(agent.tool_registry)
    
    # Test sentiment analysis
    print("\n📊 Testing sentiment analysis...")
    test_texts = [
        "I love this new AI framework! It's amazing!",
        "This is terrible. I hate it.",
        "The weather is okay today, nothing special.",
        "I'm so excited about the future of AI and machine learning!",
        "This product is mediocre at best."
    ]
    
    for text in test_texts:
        result = await agent.analyze_sentiment(text)
        if result["success"]:
            data = result["data"]
            print(f"  Text: '{data['text']}'")
            print(f"  Sentiment: {data['predicted_label']} (confidence: {data['confidence']:.3f})")
            print(f"  Processing time: {data['processing_time']:.3f}s")
        else:
            print(f"  Error: {result['error']}")
        print()
    
    # Test secure tool execution
    print("\n🔒 Testing secure tool execution...")
    tool_tests = [
        {
            "tool_id": "text_processor",
            "parameters": {"text": "Sample text", "operation": "analyze"}
        },
        {
            "tool_id": "data_analyzer", 
            "parameters": {"data": {"values": [1, 2, 3]}, "analysis_type": "basic"}
        },
        {
            "tool_id": "security_monitor",
            "parameters": {"monitor_type": "performance", "duration": 60}
        }
    ]
    
    for test in tool_tests:
        result = await agent.secure_tool_execution(test["tool_id"], test["parameters"])
        status = "✅ SUCCESS" if result["success"] else "❌ FAILED"
        print(f"  {test['tool_id']}: {status}")
        if not result["success"]:
            print(f"    Error: {result['error']}")
    
    # Display trust score
    print("\n📈 Agent trust score:")
    trust_score = agent.get_trust_score()
    if trust_score:
        print(f"  Overall: {trust_score['overall_score']:.3f}")
        print(f"  Confidence: {trust_score['confidence']:.3f}")
        print(f"  Events: {trust_score['event_count']}")
        print("  Dimensions:")
        for dim, score in trust_score['dimensions'].items():
            print(f"    {dim}: {score:.3f}")
    
    # Display metrics
    print("\n📊 Agent metrics:")
    metrics = agent.get_metrics()
    for key, value in metrics.items():
        if key != "capabilities":
            print(f"  {key}: {value}")
    
    # Display framework metrics
    print("\n🔍 Framework metrics:")
    framework_metrics = agent.mcp_gateway.get_real_time_metrics()
    for key, value in framework_metrics.items():
        print(f"  {key}: {value}")
    
    print("\n🎉 Demo completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Run the demo
    asyncio.run(main())
