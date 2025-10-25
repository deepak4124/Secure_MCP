"""
Hugging Face Configuration
"""

import os
from huggingface_hub import login

# Your Hugging Face access token
HF_ACCESS_TOKEN = "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"

def setup_huggingface():
    """Setup Hugging Face authentication"""
    try:
        # Set environment variable
        os.environ["HUGGINGFACE_HUB_TOKEN"] = HF_ACCESS_TOKEN
        
        # Login to Hugging Face
        login(token=HF_ACCESS_TOKEN)
        
        print("✅ Hugging Face authentication successful!")
        return True
        
    except Exception as e:
        print(f"❌ Hugging Face authentication failed: {e}")
        return False

if __name__ == "__main__":
    setup_huggingface()
