"""
Unit tests for Real Models
"""

import pytest
import torch
from unittest.mock import Mock, patch, MagicMock
from mcp_security_framework.models.real_models import RealTrustModel, RealSecurityModel


class TestRealTrustModel:
    """Test cases for RealTrustModel"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Mock the model loading to avoid downloading during tests
        with patch('mcp_security_framework.models.real_models.AutoTokenizer') as mock_tokenizer, \
             patch('mcp_security_framework.models.real_models.AutoModel') as mock_model, \
             patch('mcp_security_framework.models.real_models.AutoModelForSequenceClassification') as mock_classifier, \
             patch('mcp_security_framework.models.real_models.pipeline') as mock_pipeline:
            
            # Setup mocks
            mock_tokenizer.from_pretrained.return_value = Mock()
            mock_model.from_pretrained.return_value = Mock()
            mock_classifier.from_pretrained.return_value = Mock()
            mock_pipeline.return_value = Mock()
            
            self.trust_model = RealTrustModel()
    
    def test_trust_model_initialization(self):
        """Test RealTrustModel initialization"""
        assert self.trust_model is not None
        assert hasattr(self.trust_model, 'device')
        assert hasattr(self.trust_model, 'trust_tokenizer')
        assert hasattr(self.trust_model, 'trust_model')
        assert hasattr(self.trust_model, 'behavior_tokenizer')
        assert hasattr(self.trust_model, 'behavior_model')
        assert hasattr(self.trust_model, 'trust_pipeline')
    
    def test_calculate_trust_score_success(self):
        """Test successful trust score calculation"""
        agent_id = "test_agent"
        interactions = [
            "This is a helpful response",
            "I can assist with that task",
            "Let me provide you with the information"
        ]
        
        # Mock the model outputs
        with patch.object(self.trust_model.trust_model, 'to') as mock_to, \
             patch.object(self.trust_model.trust_tokenizer, '__call__') as mock_tokenizer_call, \
             patch.object(self.trust_model.trust_model, '__call__') as mock_model_call:
            
            # Setup mock returns
            mock_to.return_value = self.trust_model.trust_model
            mock_tokenizer_call.return_value = {
                'input_ids': torch.tensor([[1, 2, 3, 4, 5]]),
                'attention_mask': torch.tensor([[1, 1, 1, 1, 1]])
            }
            
            # Mock model output
            mock_output = Mock()
            mock_output.last_hidden_state = torch.tensor([[[0.1, 0.2, 0.3, 0.4, 0.5]]])
            mock_model_call.return_value = mock_output
            
            # Mock torch operations
            with patch('torch.sigmoid') as mock_sigmoid, \
                 patch('torch.no_grad'):
                mock_sigmoid.return_value = torch.tensor(0.75)
                
                trust_score = self.trust_model.calculate_trust_score(agent_id, interactions)
                
                assert isinstance(trust_score, float)
                assert 0.0 <= trust_score <= 1.0
                assert trust_score == 0.75
    
    def test_calculate_trust_score_empty_interactions(self):
        """Test trust score calculation with empty interactions"""
        agent_id = "test_agent"
        interactions = []
        
        # Mock the model outputs
        with patch.object(self.trust_model.trust_tokenizer, '__call__') as mock_tokenizer_call:
            mock_tokenizer_call.return_value = {
                'input_ids': torch.tensor([[1, 2, 3]]),
                'attention_mask': torch.tensor([[1, 1, 1]])
            }
            
            with patch.object(self.trust_model.trust_model, '__call__') as mock_model_call:
                mock_output = Mock()
                mock_output.last_hidden_state = torch.tensor([[[0.1, 0.2, 0.3]]])
                mock_model_call.return_value = mock_output
                
                with patch('torch.sigmoid') as mock_sigmoid, \
                     patch('torch.no_grad'):
                    mock_sigmoid.return_value = torch.tensor(0.5)
                    
                    trust_score = self.trust_model.calculate_trust_score(agent_id, interactions)
                    
                    assert isinstance(trust_score, float)
                    assert 0.0 <= trust_score <= 1.0
    
    def test_calculate_trust_score_exception(self):
        """Test trust score calculation with exception"""
        agent_id = "test_agent"
        interactions = ["test interaction"]
        
        # Mock an exception
        with patch.object(self.trust_model.trust_tokenizer, '__call__', side_effect=Exception("Test error")):
            trust_score = self.trust_model.calculate_trust_score(agent_id, interactions)
            
            # Should return default score on error
            assert trust_score == 0.5
    
    def test_detect_anomaly_success(self):
        """Test successful anomaly detection"""
        behavior_text = "This is suspicious behavior"
        
        # Mock the pipeline
        with patch.object(self.trust_model.trust_pipeline, '__call__') as mock_pipeline_call:
            mock_pipeline_call.return_value = [{'label': 'LABEL_1', 'score': 0.8}]
            
            anomaly_score = self.trust_model.detect_anomaly(behavior_text)
            
            assert isinstance(anomaly_score, float)
            assert 0.0 <= anomaly_score <= 1.0
            assert anomaly_score == 0.8
    
    def test_detect_anomaly_no_anomaly(self):
        """Test anomaly detection with no anomaly"""
        behavior_text = "This is normal behavior"
        
        # Mock the pipeline
        with patch.object(self.trust_model.trust_pipeline, '__call__') as mock_pipeline_call:
            mock_pipeline_call.return_value = [{'label': 'LABEL_0', 'score': 0.8}]
            
            anomaly_score = self.trust_model.detect_anomaly(behavior_text)
            
            assert isinstance(anomaly_score, float)
            assert 0.0 <= anomaly_score <= 1.0
            assert anomaly_score == 0.2  # 1 - 0.8
    
    def test_detect_anomaly_exception(self):
        """Test anomaly detection with exception"""
        behavior_text = "test behavior"
        
        # Mock an exception
        with patch.object(self.trust_model.trust_pipeline, '__call__', side_effect=Exception("Test error")):
            anomaly_score = self.trust_model.detect_anomaly(behavior_text)
            
            # Should return default score on error
            assert anomaly_score == 0.0


class TestRealSecurityModel:
    """Test cases for RealSecurityModel"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Mock the model loading to avoid downloading during tests
        with patch('mcp_security_framework.models.real_models.AutoTokenizer') as mock_tokenizer, \
             patch('mcp_security_framework.models.real_models.AutoModelForSequenceClassification') as mock_classifier, \
             patch('mcp_security_framework.models.real_models.pipeline') as mock_pipeline:
            
            # Setup mocks
            mock_tokenizer.from_pretrained.return_value = Mock()
            mock_classifier.from_pretrained.return_value = Mock()
            mock_pipeline.return_value = Mock()
            
            self.security_model = RealSecurityModel()
    
    def test_security_model_initialization(self):
        """Test RealSecurityModel initialization"""
        assert self.security_model is not None
        assert hasattr(self.security_model, 'device')
        assert hasattr(self.security_model, 'security_tokenizer')
        assert hasattr(self.security_model, 'security_model')
        assert hasattr(self.security_model, 'security_pipeline')
    
    def test_detect_threat_safe(self):
        """Test threat detection with safe text"""
        text = "This is a normal request"
        
        # Mock the pipeline
        with patch.object(self.security_model.security_pipeline, '__call__') as mock_pipeline_call:
            mock_pipeline_call.return_value = [{'label': 'LABEL_0', 'score': 0.9}]
            
            result = self.security_model.detect_threat(text)
            
            assert isinstance(result, dict)
            assert result['threat_level'] == 'safe'
            assert result['confidence'] == 0.9
            assert result['is_threat'] is False
    
    def test_detect_threat_suspicious(self):
        """Test threat detection with suspicious text"""
        text = "This looks suspicious"
        
        # Mock the pipeline
        with patch.object(self.security_model.security_pipeline, '__call__') as mock_pipeline_call:
            mock_pipeline_call.return_value = [{'label': 'LABEL_1', 'score': 0.8}]
            
            result = self.security_model.detect_threat(text)
            
            assert isinstance(result, dict)
            assert result['threat_level'] == 'suspicious'
            assert result['confidence'] == 0.8
            assert result['is_threat'] is True
    
    def test_detect_threat_malicious(self):
        """Test threat detection with malicious text"""
        text = "This is clearly malicious"
        
        # Mock the pipeline
        with patch.object(self.security_model.security_pipeline, '__call__') as mock_pipeline_call:
            mock_pipeline_call.return_value = [{'label': 'LABEL_2', 'score': 0.95}]
            
            result = self.security_model.detect_threat(text)
            
            assert isinstance(result, dict)
            assert result['threat_level'] == 'malicious'
            assert result['confidence'] == 0.95
            assert result['is_threat'] is True
    
    def test_detect_threat_exception(self):
        """Test threat detection with exception"""
        text = "test text"
        
        # Mock an exception
        with patch.object(self.security_model.security_pipeline, '__call__', side_effect=Exception("Test error")):
            result = self.security_model.detect_threat(text)
            
            # Should return safe default on error
            assert isinstance(result, dict)
            assert result['threat_level'] == 'safe'
            assert result['confidence'] == 0.0
            assert result['is_threat'] is False
    
    def test_detect_threat_various_inputs(self):
        """Test threat detection with various input types"""
        test_cases = [
            ("normal text", 'LABEL_0', 'safe', False),
            ("suspicious activity", 'LABEL_1', 'suspicious', True),
            ("malicious code", 'LABEL_2', 'malicious', True),
            ("", 'LABEL_0', 'safe', False),  # Empty string
            ("a" * 1000, 'LABEL_0', 'safe', False),  # Long string
        ]
        
        for text, label, expected_level, expected_threat in test_cases:
            with patch.object(self.security_model.security_pipeline, '__call__') as mock_pipeline_call:
                mock_pipeline_call.return_value = [{'label': label, 'score': 0.8}]
                
                result = self.security_model.detect_threat(text)
                
                assert result['threat_level'] == expected_level
                assert result['is_threat'] == expected_threat
    
    def test_detect_threat_confidence_levels(self):
        """Test threat detection with different confidence levels"""
        confidence_tests = [
            (0.5, 0.5),
            (0.8, 0.8),
            (0.95, 0.95),
            (1.0, 1.0)
        ]
        
        for input_confidence, expected_confidence in confidence_tests:
            with patch.object(self.security_model.security_pipeline, '__call__') as mock_pipeline_call:
                mock_pipeline_call.return_value = [{'label': 'LABEL_0', 'score': input_confidence}]
                
                result = self.security_model.detect_threat("test text")
                
                assert result['confidence'] == expected_confidence


class TestRealModelsIntegration:
    """Integration tests for real models"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Mock both models
        with patch('mcp_security_framework.models.real_models.AutoTokenizer'), \
             patch('mcp_security_framework.models.real_models.AutoModel'), \
             patch('mcp_security_framework.models.real_models.AutoModelForSequenceClassification'), \
             patch('mcp_security_framework.models.real_models.pipeline'):
            
            self.trust_model = RealTrustModel()
            self.security_model = RealSecurityModel()
    
    def test_models_work_together(self):
        """Test that both models can work together"""
        # Test trust calculation
        with patch.object(self.trust_model.trust_tokenizer, '__call__') as mock_tokenizer, \
             patch.object(self.trust_model.trust_model, '__call__') as mock_model, \
             patch('torch.sigmoid') as mock_sigmoid, \
             patch('torch.no_grad'):
            
            mock_tokenizer.return_value = {
                'input_ids': torch.tensor([[1, 2, 3]]),
                'attention_mask': torch.tensor([[1, 1, 1]])
            }
            mock_output = Mock()
            mock_output.last_hidden_state = torch.tensor([[[0.1, 0.2, 0.3]]])
            mock_model.return_value = mock_output
            mock_sigmoid.return_value = torch.tensor(0.7)
            
            trust_score = self.trust_model.calculate_trust_score("agent_1", ["helpful interaction"])
            assert trust_score == 0.7
        
        # Test security detection
        with patch.object(self.security_model.security_pipeline, '__call__') as mock_pipeline:
            mock_pipeline.return_value = [{'label': 'LABEL_1', 'score': 0.8}]
            
            threat_result = self.security_model.detect_threat("suspicious text")
            assert threat_result['threat_level'] == 'suspicious'
            assert threat_result['is_threat'] is True
    
    def test_models_error_handling(self):
        """Test error handling in both models"""
        # Test trust model error handling
        with patch.object(self.trust_model.trust_tokenizer, '__call__', side_effect=Exception("Trust error")):
            trust_score = self.trust_model.calculate_trust_score("agent_1", ["test"])
            assert trust_score == 0.5  # Default fallback
        
        # Test security model error handling
        with patch.object(self.security_model.security_pipeline, '__call__', side_effect=Exception("Security error")):
            threat_result = self.security_model.detect_threat("test")
            assert threat_result['threat_level'] == 'safe'  # Default fallback
            assert threat_result['is_threat'] is False


