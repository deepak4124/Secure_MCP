#!/usr/bin/env python3
"""
Download Hugging Face models with authentication
"""

import os
import sys
from transformers import AutoTokenizer, AutoModel, AutoModelForSequenceClassification

# Setup Hugging Face authentication
HF_TOKEN = "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"
os.environ["HUGGINGFACE_HUB_TOKEN"] = HF_TOKEN

try:
    from huggingface_hub import login
    login(token=HF_TOKEN)
    print("✅ Hugging Face authentication successful!")
except Exception as e:
    print(f"⚠️  Hugging Face authentication warning: {e}")

def download_model(model_name, model_type="tokenizer_and_model"):
    """Download a specific model"""
    try:
        print(f"🔄 Downloading {model_name}...")
        
        if model_type == "tokenizer_and_model":
            # Download tokenizer and model
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModel.from_pretrained(model_name)
            print(f"✅ {model_name} downloaded successfully!")
            
        elif model_type == "classification":
            # Download for classification
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForSequenceClassification.from_pretrained(
                model_name, num_labels=3
            )
            print(f"✅ {model_name} (classification) downloaded successfully!")
            
        return True
        
    except Exception as e:
        print(f"❌ Failed to download {model_name}: {e}")
        return False

def main():
    """Download all required models"""
    print("🚀 Downloading Hugging Face Models for MCP Security Framework")
    print("=" * 60)
    
    models_to_download = [
        ("microsoft/DialoGPT-medium", "tokenizer_and_model"),
        ("distilbert-base-uncased", "classification"),
        ("roberta-base", "classification")
    ]
    
    success_count = 0
    total_count = len(models_to_download)
    
    for model_name, model_type in models_to_download:
        if download_model(model_name, model_type):
            success_count += 1
    
    print(f"\n📊 Download Summary:")
    print(f"   - Successfully downloaded: {success_count}/{total_count}")
    print(f"   - Failed downloads: {total_count - success_count}")
    
    if success_count == total_count:
        print("🎉 All models downloaded successfully!")
        return True
    else:
        print("⚠️  Some models failed to download. Check your internet connection and token.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
