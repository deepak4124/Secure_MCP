#!/usr/bin/env python3
"""
Setup script for MCP Security Framework with real models
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def main():
    """Main setup function"""
    print("🚀 Setting up MCP Security Framework with Real Models")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    print(f"✅ Python version: {sys.version}")
    
    # Create virtual environment
    if not os.path.exists("mcp_security_env"):
        if not run_command("python -m venv mcp_security_env", "Creating virtual environment"):
            sys.exit(1)
    else:
        print("✅ Virtual environment already exists")
    
    # Activate virtual environment and install dependencies
    if sys.platform == "win32":
        activate_cmd = "mcp_security_env\\Scripts\\activate"
        pip_cmd = "mcp_security_env\\Scripts\\pip"
    else:
        activate_cmd = "source mcp_security_env/bin/activate"
        pip_cmd = "mcp_security_env/bin/pip"
    
    # Install requirements
    if not run_command(f"{pip_cmd} install --upgrade pip", "Upgrading pip"):
        sys.exit(1)
    
    if not run_command(f"{pip_cmd} install -r requirements_real.txt", "Installing dependencies"):
        sys.exit(1)
    
    # Setup Hugging Face authentication
    print("🔄 Setting up Hugging Face authentication...")
    hf_token = "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"
    
    # Set environment variable
    import os
    os.environ["HUGGINGFACE_HUB_TOKEN"] = hf_token
    
    # Download Hugging Face models
    print("🔄 Downloading Hugging Face models...")
    models_to_download = [
        "microsoft/DialoGPT-medium",
        "distilbert-base-uncased", 
        "roberta-base"
    ]
    
    for model in models_to_download:
        print(f"🔄 Downloading {model}...")
        # Use Python to download models with authentication
        download_cmd = f'{pip_cmd} run python -c "from transformers import AutoTokenizer, AutoModel; AutoTokenizer.from_pretrained(\'{model}\'); AutoModel.from_pretrained(\'{model}\')"'
        if not run_command(download_cmd, f"Downloading {model}"):
            print(f"⚠️  Warning: Could not download {model}")
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Activate the virtual environment:")
    if sys.platform == "win32":
        print("   mcp_security_env\\Scripts\\activate")
    else:
        print("   source mcp_security_env/bin/activate")
    print("2. Run the main application:")
    print("   python main.py")
    print("3. Monitor the framework:")
    print("   python monitor.py")

if __name__ == "__main__":
    main()
