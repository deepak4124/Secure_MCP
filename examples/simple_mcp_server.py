"""
Simple MCP Server for Testing
A basic MCP server that provides various tools for testing the security framework
"""

import asyncio
import json
import time
import random
from typing import Dict, Any, List
from aiohttp import web, web_request
import aiohttp_cors


class SimpleMCPServer:
    """Simple MCP server for testing purposes"""
    
    def __init__(self, port: int = 3000):
        self.port = port
        self.app = web.Application()
        self.tools = self._initialize_tools()
        self.setup_routes()
        self.setup_cors()
    
    def _initialize_tools(self) -> Dict[str, Dict[str, Any]]:
        """Initialize available tools"""
        return {
            "data_processor": {
                "name": "Data Processor",
                "description": "Processes and cleans datasets",
                "parameters": {
                    "dataset": {"type": "string", "required": True},
                    "operation": {"type": "string", "required": True, "options": ["clean", "validate", "transform"]}
                },
                "risk_level": "low",
                "capabilities": ["data_processing"]
            },
            "analyzer": {
                "name": "Data Analyzer", 
                "description": "Analyzes datasets and generates insights",
                "parameters": {
                    "data": {"type": "object", "required": True},
                    "analysis_type": {"type": "string", "required": True, "options": ["statistical", "trend", "correlation"]}
                },
                "risk_level": "low",
                "capabilities": ["data_analysis"]
            },
            "visualizer": {
                "name": "Data Visualizer",
                "description": "Creates visualizations from data",
                "parameters": {
                    "data": {"type": "object", "required": True},
                    "chart_type": {"type": "string", "required": True, "options": ["bar", "line", "pie", "scatter"]}
                },
                "risk_level": "low",
                "capabilities": ["visualization"]
            },
            "reporter": {
                "name": "Report Generator",
                "description": "Generates formatted reports",
                "parameters": {
                    "content": {"type": "object", "required": True},
                    "format": {"type": "string", "required": True, "options": ["html", "pdf", "markdown"]}
                },
                "risk_level": "low",
                "capabilities": ["reporting"]
            },
            "validator": {
                "name": "Data Validator",
                "description": "Validates data quality and integrity",
                "parameters": {
                    "data": {"type": "object", "required": True},
                    "rules": {"type": "array", "required": True}
                },
                "risk_level": "low",
                "capabilities": ["validation"]
            },
            "transformer": {
                "name": "Data Transformer",
                "description": "Transforms data between formats",
                "parameters": {
                    "data": {"type": "object", "required": True},
                    "target_format": {"type": "string", "required": True}
                },
                "risk_level": "low",
                "capabilities": ["transformation"]
            },
            "aggregator": {
                "name": "Data Aggregator",
                "description": "Aggregates data from multiple sources",
                "parameters": {
                    "sources": {"type": "array", "required": True},
                    "aggregation_type": {"type": "string", "required": True}
                },
                "risk_level": "medium",
                "capabilities": ["aggregation"]
            },
            "monitor": {
                "name": "System Monitor",
                "description": "Monitors system resources and performance",
                "parameters": {
                    "metrics": {"type": "array", "required": True},
                    "duration": {"type": "integer", "required": True}
                },
                "risk_level": "high",
                "capabilities": ["monitoring", "system_access"]
            }
        }
    
    def setup_routes(self):
        """Setup HTTP routes"""
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_get('/capabilities', self.get_capabilities)
        self.app.router.add_get('/tools', self.get_tools)
        self.app.router.add_post('/execute', self.execute_tool)
        self.app.router.add_get('/', self.root)
    
    def setup_cors(self):
        """Setup CORS for cross-origin requests"""
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        for route in list(self.app.router.routes()):
            cors.add(route)
    
    async def health_check(self, request: web_request.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "timestamp": time.time(),
            "server": "Simple MCP Server",
            "version": "1.0.0"
        })
    
    async def get_capabilities(self, request: web_request.Request) -> web.Response:
        """Get server capabilities"""
        return web.json_response({
            "server_name": "Simple MCP Server",
            "version": "1.0.0",
            "capabilities": [
                "data_processing",
                "data_analysis", 
                "visualization",
                "reporting",
                "validation",
                "transformation",
                "aggregation",
                "monitoring"
            ],
            "supported_formats": ["json", "csv", "xml"],
            "max_file_size": "10MB",
            "rate_limit": "100 requests/minute"
        })
    
    async def get_tools(self, request: web_request.Request) -> web.Response:
        """Get available tools"""
        tools_list = []
        for tool_id, tool_info in self.tools.items():
            tools_list.append({
                "id": tool_id,
                "name": tool_info["name"],
                "description": tool_info["description"],
                "parameters": tool_info["parameters"],
                "risk_level": tool_info["risk_level"],
                "capabilities": tool_info["capabilities"]
            })
        
        return web.json_response({
            "tools": tools_list,
            "total_tools": len(tools_list)
        })
    
    async def execute_tool(self, request: web_request.Request) -> web.Response:
        """Execute a tool"""
        try:
            data = await request.json()
            tool_id = data.get("tool_id")
            parameters = data.get("parameters", {})
            context = data.get("context", {})
            
            if not tool_id:
                return web.json_response({
                    "success": False,
                    "error": "tool_id is required"
                }, status=400)
            
            if tool_id not in self.tools:
                return web.json_response({
                    "success": False,
                    "error": f"Tool {tool_id} not found"
                }, status=404)
            
            # Simulate tool execution
            result = await self._simulate_tool_execution(tool_id, parameters, context)
            
            return web.json_response({
                "success": True,
                "result": result,
                "tool_id": tool_id,
                "execution_time": time.time(),
                "parameters": parameters
            })
            
        except Exception as e:
            return web.json_response({
                "success": False,
                "error": str(e)
            }, status=500)
    
    async def _simulate_tool_execution(self, tool_id: str, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate tool execution with realistic results"""
        tool_info = self.tools[tool_id]
        
        # Simulate processing time
        await asyncio.sleep(random.uniform(0.1, 0.5))
        
        # Generate realistic results based on tool type
        if tool_id == "data_processor":
            return {
                "processed_rows": random.randint(100, 1000),
                "cleaned_data": f"Processed {parameters.get('dataset', 'unknown')} with {parameters.get('operation', 'clean')}",
                "quality_score": random.uniform(0.8, 1.0),
                "processing_time": random.uniform(0.1, 0.3)
            }
        
        elif tool_id == "analyzer":
            return {
                "analysis_type": parameters.get("analysis_type", "statistical"),
                "insights": [
                    "Data shows positive trend over time",
                    "Strong correlation between variables A and B",
                    "Outliers detected in 5% of records"
                ],
                "confidence_score": random.uniform(0.7, 0.95),
                "data_points_analyzed": random.randint(50, 500)
            }
        
        elif tool_id == "visualizer":
            return {
                "chart_type": parameters.get("chart_type", "bar"),
                "chart_url": f"/charts/{random.randint(1000, 9999)}.png",
                "data_points": random.randint(10, 100),
                "rendering_time": random.uniform(0.05, 0.2)
            }
        
        elif tool_id == "reporter":
            return {
                "report_format": parameters.get("format", "html"),
                "report_url": f"/reports/{random.randint(1000, 9999)}.{parameters.get('format', 'html')}",
                "page_count": random.randint(1, 10),
                "generation_time": random.uniform(0.2, 0.8)
            }
        
        elif tool_id == "validator":
            return {
                "validation_rules": len(parameters.get("rules", [])),
                "passed_checks": random.randint(8, 10),
                "failed_checks": random.randint(0, 2),
                "data_quality_score": random.uniform(0.85, 1.0)
            }
        
        elif tool_id == "transformer":
            return {
                "source_format": "json",
                "target_format": parameters.get("target_format", "csv"),
                "transformed_records": random.randint(100, 1000),
                "transformation_time": random.uniform(0.1, 0.4)
            }
        
        elif tool_id == "aggregator":
            return {
                "sources_processed": len(parameters.get("sources", [])),
                "aggregated_records": random.randint(500, 2000),
                "aggregation_type": parameters.get("aggregation_type", "sum"),
                "processing_time": random.uniform(0.3, 0.8)
            }
        
        elif tool_id == "monitor":
            return {
                "metrics_collected": len(parameters.get("metrics", [])),
                "monitoring_duration": parameters.get("duration", 60),
                "system_status": "healthy",
                "resource_usage": {
                    "cpu": random.uniform(20, 80),
                    "memory": random.uniform(30, 70),
                    "disk": random.uniform(40, 90)
                }
            }
        
        else:
            return {
                "message": f"Tool {tool_id} executed successfully",
                "parameters": parameters,
                "context": context
            }
    
    async def root(self, request: web_request.Request) -> web.Response:
        """Root endpoint"""
        return web.json_response({
            "message": "Simple MCP Server",
            "version": "1.0.0",
            "endpoints": {
                "health": "/health",
                "capabilities": "/capabilities", 
                "tools": "/tools",
                "execute": "/execute"
            },
            "documentation": "https://github.com/mcp-security/framework"
        })
    
    async def start(self):
        """Start the server"""
        print(f"🚀 Starting Simple MCP Server on port {self.port}")
        print(f"📡 Server will be available at: http://localhost:{self.port}")
        print(f"🔧 Available tools: {len(self.tools)}")
        print(f"📋 Health check: http://localhost:{self.port}/health")
        print(f"🛠️  Tools list: http://localhost:{self.port}/tools")
        print("=" * 50)
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', self.port)
        await site.start()
        
        print(f"✅ MCP Server started successfully!")
        print("Press Ctrl+C to stop the server")
        
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            print("\n🛑 Shutting down MCP Server...")
            await runner.cleanup()


async def main():
    """Main function"""
    server = SimpleMCPServer(port=3000)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())