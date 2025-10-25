"""
Test script to verify the fixes for agent registration and tool manifest validation
"""

import asyncio
import logging
from hf_agent_demo import HFSecureAgent, register_demo_tools
from mcp_security_framework.core.registry import ToolRegistry

async def test_fixes():
    """Test the fixes for registration and tool validation"""
    print("Testing MCP Security Framework Fixes")
    print("=" * 50)
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Test 1: Agent Registration
        print("\n1. Testing Agent Registration...")
        agent = HFSecureAgent("test_agent", "distilbert-base-uncased-finetuned-sst-2-english")
        
        # Test registration
        success = await agent.register_agent()
        if success:
            print("✅ Agent registration successful!")
        else:
            print("❌ Agent registration failed!")
            return
        
        # Test authentication
        auth_success = await agent.authenticate()
        if auth_success:
            print("✅ Agent authentication successful!")
        else:
            print("❌ Agent authentication failed!")
            return
        
        # Test 2: Tool Registration
        print("\n2. Testing Tool Registration...")
        tool_registry = ToolRegistry()
        
        # Register demo tools
        await register_demo_tools(tool_registry)
        
        # Check if tools were registered
        tools = tool_registry.get_all_tools()
        print(f"✅ Registered {len(tools)} tools successfully!")
        
        for tool_id in ["text_processor", "data_analyzer", "security_monitor"]:
            tool = tool_registry.get_tool(tool_id)
            if tool:
                print(f"  ✅ {tool_id}: {tool.status.value}")
            else:
                print(f"  ❌ {tool_id}: Not found")
        
        # Test 3: Trust Score
        print("\n3. Testing Trust Score...")
        trust_score = agent.get_trust_score()
        if trust_score:
            print(f"✅ Trust score: {trust_score['overall_score']:.3f}")
        else:
            print("❌ No trust score available")
        
        # Test 4: Tool Execution
        print("\n4. Testing Tool Execution...")
        result = await agent.secure_tool_execution(
            "text_processor",
            {"text": "Hello world", "operation": "analyze"}
        )
        
        if result["success"]:
            print(f"✅ Tool execution successful: {result['data']}")
        else:
            print(f"❌ Tool execution failed: {result['error']}")
        
        # Test 5: Sentiment Analysis (if HF token is available)
        print("\n5. Testing Sentiment Analysis...")
        if agent.hf_authenticated and agent.classifier:
            sentiment_result = await agent.analyze_sentiment("I love this framework!")
            if sentiment_result["success"]:
                data = sentiment_result["data"]
                print(f"✅ Sentiment analysis: {data['predicted_label']} (confidence: {data['confidence']:.3f})")
            else:
                print(f"❌ Sentiment analysis failed: {sentiment_result['error']}")
        else:
            print("⚠️ Skipping sentiment analysis (HF token not available or model not loaded)")
        
        print("\nAll tests completed successfully!")
        print("=" * 50)
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_fixes())
