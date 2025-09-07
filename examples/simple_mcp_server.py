"""
Simple MCP Server for Testing

This is a basic MCP server that provides tools for testing the secure MAS system.
In a real deployment, you would connect to existing MCP servers.
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional
from aiohttp import web, ClientSession
import aiohttp_cors


class SimpleMCPServer:
    """
    Simple MCP server for testing purposes
    """
    
    def __init__(self, port: int = 3000):
        """Initialize simple MCP server"""
        self.port = port
        self.app = web.Application()
        self.tools = self._initialize_tools()
        self.setup_routes()
        self.setup_cors()
    
    def _initialize_tools(self) -> List[Dict[str, Any]]:
        """Initialize available tools"""
        return [
            {
                "id": "data_processor",
                "name": "Data Processor",
                "description": "Process and clean data files",
                "parameters": {
                    "input_file": {"type": "string", "required": True},
                    "output_format": {"type": "string", "default": "json"}
                },
                "capabilities": ["data_processing", "file_handling"],
                "risk_level": "low"
            },
            {
                "id": "analyzer",
                "name": "Data Analyzer", 
                "description": "Analyze data and generate insights",
                "parameters": {
                    "data_source": {"type": "string", "required": True},
                    "analysis_type": {"type": "string", "default": "basic"}
                },
                "capabilities": ["analysis", "insights"],
                "risk_level": "low"
            },
            {
                "id": "chart_generator",
                "name": "Chart Generator",
                "description": "Generate charts and visualizations",
                "parameters": {
                    "chart_type": {"type": "string", "required": True},
                    "data_points": {"type": "integer", "default": 100}
                },
                "capabilities": ["visualization", "charting"],
                "risk_level": "low"
            },
            {
                "id": "report_generator",
                "name": "Report Generator",
                "description": "Generate formatted reports",
                "parameters": {
                    "report_type": {"type": "string", "required": True},
                    "sections": {"type": "array", "default": []}
                },
                "capabilities": ["reporting", "formatting"],
                "risk_level": "low"
            },
            {
                "id": "validator",
                "name": "Data Validator",
                "description": "Validate data integrity and format",
                "parameters": {
                    "data": {"type": "object", "required": True},
                    "schema": {"type": "object", "default": {}}
                },
                "capabilities": ["validation", "data_quality"],
                "risk_level": "low"
            },
            {
                "id": "calculator",
                "name": "Calculator",
                "description": "Perform mathematical calculations",
                "parameters": {
                    "expression": {"type": "string", "required": True},
                    "precision": {"type": "integer", "default": 2}
                },
                "capabilities": ["calculation", "math"],
                "risk_level": "low"
            },
            {
                "id": "dashboard_builder",
                "name": "Dashboard Builder",
                "description": "Build interactive dashboards",
                "parameters": {
                    "components": {"type": "array", "required": True},
                    "layout": {"type": "string", "default": "grid"}
                },
                "capabilities": ["dashboard", "ui"],
                "risk_level": "low"
            },
            {
                "id": "formatter",
                "name": "Data Formatter",
                "description": "Format data for presentation",
                "parameters": {
                    "data": {"type": "object", "required": True},
                    "format": {"type": "string", "default": "pretty"}
                },
                "capabilities": ["formatting", "presentation"],
                "risk_level": "low"
            }
        ]
    
    def setup_routes(self):
        """Setup HTTP routes"""
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_get('/capabilities', self.get_capabilities)
        self.app.router.add_get('/tools', self.get_tools)
        self.app.router.add_post('/execute', self.execute_tool)
        self.app.router.add_get('/status', self.get_status)
    
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
    
    async def health_check(self, request):
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "timestamp": time.time(),
            "server": "simple_mcp_server"
        })
    
    async def get_capabilities(self, request):
        """Get server capabilities"""
        return web.json_response({
            "capabilities": [
                "data_processing",
                "analysis", 
                "visualization",
                "reporting",
                "validation",
                "calculation"
            ],
            "supported_formats": ["json", "csv", "xml"],
            "max_file_size": "100MB",
            "concurrent_requests": 10
        })
    
    async def get_tools(self, request):
        """Get available tools"""
        return web.json_response({
            "tools": self.tools,
            "count": len(self.tools)
        })
    
    async def execute_tool(self, request):
        """Execute a tool"""
        try:
            data = await request.json()
            tool_id = data.get("tool_id")
            parameters = data.get("parameters", {})
            context = data.get("context")
            
            # Find tool
            tool = next((t for t in self.tools if t["id"] == tool_id), None)
            if not tool:
                return web.json_response({
                    "success": False,
                    "error": f"Tool not found: {tool_id}"
                }, status=404)
            
            # Execute tool
            result = await self._execute_tool_logic(tool, parameters, context)
            
            return web.json_response({
                "success": True,
                "result": result,
                "tool_id": tool_id,
                "execution_time": time.time()
            })
            
        except Exception as e:
            return web.json_response({
                "success": False,
                "error": str(e)
            }, status=500)
    
    async def _execute_tool_logic(
        self, 
        tool: Dict[str, Any], 
        parameters: Dict[str, Any], 
        context: Optional[Dict[str, Any]]
    ) -> Any:
        """Execute tool logic"""
        tool_id = tool["id"]
        
        # Simulate tool execution
        await asyncio.sleep(0.1)  # Simulate processing time
        
        if tool_id == "data_processor":
            return {
                "processed_records": 1000,
                "output_file": f"processed_{parameters.get('input_file', 'data')}.json",
                "processing_time": 0.1,
                "status": "completed"
            }
        
        elif tool_id == "analyzer":
            return {
                "analysis_type": parameters.get("analysis_type", "basic"),
                "insights": [
                    "Data shows positive trend",
                    "Peak activity at 2 PM",
                    "Anomaly detected in record 42"
                ],
                "confidence": 0.85,
                "status": "completed"
            }
        
        elif tool_id == "chart_generator":
            return {
                "chart_type": parameters.get("chart_type", "line"),
                "chart_url": f"/charts/chart_{int(time.time())}.png",
                "data_points": parameters.get("data_points", 100),
                "status": "completed"
            }
        
        elif tool_id == "report_generator":
            return {
                "report_type": parameters.get("report_type", "standard"),
                "report_url": f"/reports/report_{int(time.time())}.pdf",
                "sections": parameters.get("sections", []),
                "page_count": 5,
                "status": "completed"
            }
        
        elif tool_id == "validator":
            return {
                "valid": True,
                "errors": [],
                "warnings": ["Minor formatting issue in field 'date'"],
                "validation_time": 0.05,
                "status": "completed"
            }
        
        elif tool_id == "calculator":
            return {
                "expression": parameters.get("expression", "2+2"),
                "result": 4.0,
                "precision": parameters.get("precision", 2),
                "status": "completed"
            }
        
        elif tool_id == "dashboard_builder":
            return {
                "dashboard_id": f"dashboard_{int(time.time())}",
                "components": parameters.get("components", []),
                "layout": parameters.get("layout", "grid"),
                "dashboard_url": f"/dashboards/dashboard_{int(time.time())}",
                "status": "completed"
            }
        
        elif tool_id == "formatter":
            return {
                "formatted_data": "Formatted data output",
                "format": parameters.get("format", "pretty"),
                "size": len(str(parameters.get("data", {}))),
                "status": "completed"
            }
        
        else:
            return {
                "message": f"Tool {tool_id} executed successfully",
                "parameters": parameters,
                "status": "completed"
            }
    
    async def get_status(self, request):
        """Get server status"""
        return web.json_response({
            "status": "running",
            "uptime": time.time(),
            "tools_available": len(self.tools),
            "active_connections": 0,  # Would track real connections
            "memory_usage": "50MB",   # Would track real memory
            "cpu_usage": "10%"        # Would track real CPU
        })
    
    async def start(self):
        """Start the server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', self.port)
        await site.start()
        print(f"Simple MCP Server started on http://localhost:{self.port}")
        print(f"Available tools: {len(self.tools)}")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down server...")
            await runner.cleanup()


async def main():
    """Main function to start the server"""
    server = SimpleMCPServer(port=3000)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
