"""
LangGraph Document Processing Demo

This demo shows a real multi-agent system using LangGraph agents with Gemini API
for document processing, integrated with the MCP security framework.
"""

import asyncio
import time
import json
import os
from typing import Dict, List, Optional, Any

# Import our modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langgraph_mas.document_processing_workflow import DocumentProcessingMAS, DocumentProcessor
from security.authentication.identity_management import IdentityManager
from trust.trust_calculator import TrustCalculator
from integration.mcp_security_gateway import MCPSecurityGateway
from examples.simple_mcp_server import SimpleMCPServer
from config.env_config import config


class LangGraphDocumentProcessingDemo:
    """
    Demo for LangGraph-based document processing MAS
    """
    
    def __init__(self):
        """Initialize the demo"""
        self.identity_manager = IdentityManager()
        self.trust_calculator = TrustCalculator(min_events=1)
        self.mcp_gateway = None
        self.mcp_server = None
        self.mas = None
        self.document_processor = DocumentProcessor()
    
    async def start_mcp_server(self, port: int = 3000):
        """Start the MCP server"""
        print(f"🚀 Starting MCP server on port {port}...")
        self.mcp_server = SimpleMCPServer(port=port)
        
        # Start server in background
        server_task = asyncio.create_task(self.mcp_server.start())
        
        # Wait for server to start
        await asyncio.sleep(3)
        print("✅ MCP server started successfully!")
        
        return server_task
    
    async def initialize_system(self):
        """Initialize the complete system"""
        print("🔧 Initializing LangGraph Document Processing MAS...")
        
        # Initialize MCP gateway
        self.mcp_gateway = MCPSecurityGateway()
        await self.mcp_gateway.__aenter__()
        
        # Discover and register MCP servers
        servers = await self.mcp_gateway.discover_mcp_servers()
        print(f"📡 Discovered {len(servers)} MCP servers")
        
        for server_url in servers:
            await self.mcp_gateway.register_mcp_server(server_url)
        
        # Discover tools
        for server_url in servers:
            tools = await self.mcp_gateway.discover_tools(server_url)
            print(f"🔧 Discovered {len(tools)} tools from {server_url}")
        
        verified_tools = self.mcp_gateway.get_verified_tools()
        print(f"✅ Total verified tools: {len(verified_tools)}")
        
        # Initialize MAS
        self.mas = DocumentProcessingMAS(
            self.identity_manager,
            self.trust_calculator,
            self.mcp_gateway
        )
        
        # Initialize agents
        await self.mas.initialize_agents()
        
        print("✅ System initialization complete!")
    
    def create_sample_documents(self) -> List[str]:
        """Create sample documents for testing"""
        sample_docs = []
        
        # Create sample text file
        sample_text = """
        Sample Document for Testing
        
        This is a sample document created for testing the LangGraph Document Processing MAS.
        
        Key Information:
        - Document Type: Text
        - Purpose: Testing
        - Created: 2025
        - Author: Demo System
        
        Content Summary:
        This document contains sample text that will be processed by the multi-agent system.
        The system will extract information, analyze content, and generate insights.
        
        Technical Details:
        - Framework: LangGraph
        - LLM: Gemini API
        - Security: MCP Security Framework
        - Processing: Trust-aware allocation
        """
        
        text_file = "sample_document.txt"
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(sample_text)
        sample_docs.append(text_file)
        
        # Create sample JSON data file
        sample_data = {
            "document_info": {
                "title": "Sample Data Document",
                "type": "structured_data",
                "created": "2025-01-09",
                "version": "1.0"
            },
            "content": {
                "sections": [
                    {"title": "Introduction", "content": "This is a sample data document."},
                    {"title": "Analysis", "content": "Sample analysis data for processing."},
                    {"title": "Conclusion", "content": "Sample conclusions and recommendations."}
                ],
                "metadata": {
                    "word_count": 45,
                    "section_count": 3,
                    "complexity": "medium"
                }
            },
            "processing_requirements": {
                "extract_metadata": True,
                "analyze_content": True,
                "generate_insights": True,
                "create_report": True
            }
        }
        
        json_file = "sample_data.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f, indent=2)
        sample_docs.append(json_file)
        
        print(f"📄 Created {len(sample_docs)} sample documents:")
        for doc in sample_docs:
            print(f"  - {doc}")
        
        return sample_docs
    
    async def process_documents(self, document_paths: List[str]):
        """Process multiple documents"""
        print(f"\n📋 Processing {len(document_paths)} documents...")
        
        results = []
        
        for i, doc_path in enumerate(document_paths, 1):
            print(f"\n--- Processing Document {i}/{len(document_paths)}: {doc_path} ---")
            
            try:
                # Process document
                result = await self.mas.process_document(
                    document_path=doc_path,
                    processing_options={
                        "extract_metadata": True,
                        "analyze_content": True,
                        "generate_insights": True,
                        "create_report": True
                    }
                )
                
                results.append(result)
                
                # Display results
                if result["success"]:
                    print(f"✅ Document processed successfully!")
                    print(f"   Processing time: {result['processing_time']:.2f} seconds")
                    print(f"   Success rate: {result['processing_summary']['success_rate']:.1%}")
                    
                    # Show insights
                    insights = result.get("final_insights", {})
                    if insights:
                        print(f"   Generated insights: {len([k for k, v in insights.items() if v])} types")
                else:
                    print(f"❌ Document processing failed: {result.get('error', 'Unknown error')}")
                
            except Exception as e:
                print(f"❌ Error processing {doc_path}: {e}")
                results.append({
                    "success": False,
                    "error": str(e),
                    "document_path": doc_path
                })
        
        return results
    
    async def demonstrate_trust_evolution(self):
        """Demonstrate trust score evolution"""
        print(f"\n🏆 Trust Score Evolution:")
        
        # Get initial trust scores
        initial_ranking = self.trust_calculator.get_trust_ranking()
        print("Initial trust ranking:")
        for i, (agent_id, score) in enumerate(initial_ranking, 1):
            print(f"  {i}. {agent_id}: {score:.3f}")
        
        # Process a few more documents to show trust evolution
        print(f"\n📈 Processing additional documents to show trust evolution...")
        
        # Create additional sample documents
        additional_docs = []
        for i in range(3):
            doc_content = f"""
            Additional Test Document {i+1}
            
            This is an additional test document to demonstrate trust score evolution.
            Document ID: {i+1}
            Purpose: Trust evolution demonstration
            Content: Sample content for processing
            """
            
            doc_file = f"additional_doc_{i+1}.txt"
            with open(doc_file, 'w', encoding='utf-8') as f:
                f.write(doc_content)
            additional_docs.append(doc_file)
        
        # Process additional documents
        for doc in additional_docs:
            try:
                await self.mas.process_document(doc)
                print(f"  Processed: {doc}")
            except Exception as e:
                print(f"  Error processing {doc}: {e}")
        
        # Get final trust scores
        final_ranking = self.trust_calculator.get_trust_ranking()
        print(f"\nFinal trust ranking:")
        for i, (agent_id, score) in enumerate(final_ranking, 1):
            print(f"  {i}. {agent_id}: {score:.3f}")
        
        # Show trust changes
        print(f"\n📊 Trust Score Changes:")
        for agent_id, final_score in final_ranking:
            initial_score = next((score for aid, score in initial_ranking if aid == agent_id), 0.5)
            change = final_score - initial_score
            print(f"  {agent_id}: {initial_score:.3f} → {final_score:.3f} ({change:+.3f})")
    
    async def show_security_monitoring(self):
        """Show security monitoring and audit logs"""
        print(f"\n🔒 Security Monitoring:")
        
        # Get audit log
        audit_log = self.mcp_gateway.get_audit_log()
        print(f"  Total audit entries: {len(audit_log)}")
        
        # Show recent audit entries
        recent_entries = audit_log[-10:] if audit_log else []
        print(f"  Recent audit entries:")
        for entry in recent_entries:
            print(f"    {entry['action']}: {entry.get('agent_id', 'N/A')} at {entry['timestamp']}")
        
        # Show sybil detection
        sybil_agents = self.trust_calculator.detect_sybil_agents()
        print(f"  Sybil agents detected: {len(sybil_agents)}")
        if sybil_agents:
            print(f"    Sybil agents: {sybil_agents}")
        
        # Show collusion detection
        print(f"  Collusion detection:")
        for agent in self.mas.agents:
            colluding_agents = self.trust_calculator.detect_collusion(agent.agent_id)
            if colluding_agents:
                print(f"    {agent.agent_id} potentially colluding with: {colluding_agents}")
    
    async def show_system_statistics(self):
        """Show comprehensive system statistics"""
        print(f"\n📊 System Statistics:")
        
        stats = self.mas.get_system_stats()
        
        print(f"  Agents: {stats['agents']}")
        print(f"  Completed tasks: {stats['completed_tasks']}")
        print(f"  Failed tasks: {stats['failed_tasks']}")
        print(f"  Audit log entries: {stats['audit_log_entries']}")
        
        print(f"\n  Agent Performance:")
        for agent_stat in stats['agent_stats']:
            print(f"    {agent_stat['agent_id']}:")
            print(f"      Trust Score: {agent_stat['trust_score']:.3f}")
            print(f"      Tasks Completed: {agent_stat['tasks_completed']}")
            print(f"      Tasks Failed: {agent_stat['tasks_failed']}")
            print(f"      Available Tools: {agent_stat['available_tools']}")
    
    async def cleanup(self):
        """Clean up resources"""
        print(f"\n🧹 Cleaning up...")
        
        # Clean up sample files
        sample_files = [
            "sample_document.txt",
            "sample_data.json",
            "additional_doc_1.txt",
            "additional_doc_2.txt",
            "additional_doc_3.txt"
        ]
        
        for file in sample_files:
            if os.path.exists(file):
                os.remove(file)
                print(f"  Removed: {file}")
        
        # Clean up MCP gateway
        if self.mcp_gateway:
            await self.mcp_gateway.__aexit__(None, None, None)
        
        print("✅ Cleanup complete!")
    
    async def run_demo(self):
        """Run the complete demo"""
        print("🎯 LangGraph Document Processing MAS Demo")
        print("=" * 60)
        
        try:
            # Start MCP server
            server_task = await self.start_mcp_server()
            
            # Initialize system
            await self.initialize_system()
            
            # Create sample documents
            sample_docs = self.create_sample_documents()
            
            # Process documents
            results = await self.process_documents(sample_docs)
            
            # Demonstrate trust evolution
            await self.demonstrate_trust_evolution()
            
            # Show security monitoring
            await self.show_security_monitoring()
            
            # Show system statistics
            await self.show_system_statistics()
            
            # Summary
            print(f"\n🎉 Demo Summary:")
            print(f"  Documents processed: {len(results)}")
            successful = len([r for r in results if r.get('success', False)])
            print(f"  Successful: {successful}")
            print(f"  Failed: {len(results) - successful}")
            print(f"  Success rate: {successful/len(results):.1%}" if results else "  Success rate: N/A")
            
        except KeyboardInterrupt:
            print(f"\n🛑 Demo interrupted by user")
        except Exception as e:
            print(f"\n❌ Demo error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Clean up
            await self.cleanup()
            
            # Stop MCP server
            if 'server_task' in locals():
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    pass
            
            print(f"\n✅ Demo completed!")


async def main():
    """Main function"""
    demo = LangGraphDocumentProcessingDemo()
    await demo.run_demo()


if __name__ == "__main__":
    print("🚀 Starting LangGraph Document Processing MAS Demo")
    print("This demo will:")
    print("1. Start a real MCP server with 8 tools")
    print("2. Initialize 4 LangGraph agents with Gemini API")
    print("3. Process real documents using the MAS")
    print("4. Demonstrate trust-aware task allocation")
    print("5. Show security monitoring and audit logs")
    print("6. Display trust score evolution")
    print("\nPress Ctrl+C to stop at any time\n")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"\n💥 Demo failed: {e}")
        import traceback
        traceback.print_exc()
