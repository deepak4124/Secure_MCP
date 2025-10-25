"""
Privacy Preservation System for MCP Security Framework

This module provides comprehensive privacy protection mechanisms including:
- Data anonymization and pseudonymization
- Differential privacy implementation
- Privacy-preserving computation
- Data minimization and purpose limitation
- Consent management
- Privacy impact assessment
- Data retention and deletion
"""

import time
import hashlib
import secrets
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from pydantic import BaseModel, Field


class PrivacyLevel(Enum):
    """Privacy level enumeration"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class DataCategory(Enum):
    """Data category enumeration"""
    IDENTIFIER = "identifier"
    QUASI_IDENTIFIER = "quasi_identifier"
    SENSITIVE_ATTRIBUTE = "sensitive_attribute"
    NON_SENSITIVE = "non_sensitive"
    METADATA = "metadata"


class AnonymizationMethod(Enum):
    """Anonymization method enumeration"""
    GENERALIZATION = "generalization"
    SUPPRESSION = "suppression"
    PERTURBATION = "perturbation"
    SWAPPING = "swapping"
    MICROAGGREGATION = "microaggregation"
    DIFFERENTIAL_PRIVACY = "differential_privacy"


class ConsentStatus(Enum):
    """Consent status enumeration"""
    GRANTED = "granted"
    DENIED = "denied"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    PENDING = "pending"


@dataclass
class PrivacyPolicy:
    """Privacy policy definition"""
    policy_id: str
    name: str
    description: str
    data_categories: List[DataCategory]
    privacy_level: PrivacyLevel
    retention_period: int  # days
    anonymization_required: bool
    consent_required: bool
    purpose_limitation: List[str]
    data_minimization: bool
    cross_border_transfer: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataSubject:
    """Data subject representation"""
    subject_id: str
    consent_records: Dict[str, ConsentStatus]
    data_categories: Set[DataCategory]
    privacy_preferences: Dict[str, Any]
    last_updated: float


@dataclass
class AnonymizedData:
    """Anonymized data structure"""
    original_data: Any
    anonymized_data: Any
    method: AnonymizationMethod
    privacy_level: PrivacyLevel
    k_anonymity: Optional[int] = None
    l_diversity: Optional[int] = None
    t_closeness: Optional[float] = None
    epsilon: Optional[float] = None  # For differential privacy
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PrivacyImpact:
    """Privacy impact assessment result"""
    assessment_id: str
    data_categories: List[DataCategory]
    privacy_risks: List[str]
    risk_level: str
    mitigation_measures: List[str]
    residual_risk: float
    compliance_status: bool
    recommendations: List[str]


class PrivacyPreservationSystem:
    """
    Comprehensive privacy preservation system
    
    Features:
    - Data anonymization and pseudonymization
    - Differential privacy implementation
    - Privacy-preserving computation
    - Data minimization and purpose limitation
    - Consent management
    - Privacy impact assessment
    - Data retention and deletion
    - Cross-border data transfer controls
    """
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        """Initialize privacy preservation system"""
        self.privacy_policies: Dict[str, PrivacyPolicy] = {}
        self.data_subjects: Dict[str, DataSubject] = {}
        self.anonymization_cache: Dict[str, AnonymizedData] = {}
        self.consent_records: Dict[str, Dict[str, Any]] = {}
        self.data_retention_schedule: Dict[str, float] = {}
        
        # Encryption setup
        if encryption_key:
            self.encryption_key = encryption_key
        else:
            self.encryption_key = Fernet.generate_key()
        
        self.cipher = Fernet(self.encryption_key)
        
        # Privacy parameters
        self.default_k_anonymity = 3
        self.default_l_diversity = 2
        self.default_epsilon = 1.0  # Differential privacy parameter
        self.max_retention_days = 2555  # 7 years default
        
        # Initialize default policies
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default privacy policies"""
        # Personal data policy
        personal_policy = PrivacyPolicy(
            policy_id="personal_data",
            name="Personal Data Protection",
            description="Policy for handling personal data",
            data_categories=[DataCategory.IDENTIFIER, DataCategory.SENSITIVE_ATTRIBUTE],
            privacy_level=PrivacyLevel.PERSONAL,
            retention_period=365,  # 1 year
            anonymization_required=True,
            consent_required=True,
            purpose_limitation=["research", "analysis"],
            data_minimization=True,
            cross_border_transfer=False
        )
        
        # Internal data policy
        internal_policy = PrivacyPolicy(
            policy_id="internal_data",
            name="Internal Data Protection",
            description="Policy for handling internal data",
            data_categories=[DataCategory.QUASI_IDENTIFIER, DataCategory.NON_SENSITIVE],
            privacy_level=PrivacyLevel.INTERNAL,
            retention_period=1095,  # 3 years
            anonymization_required=False,
            consent_required=False,
            purpose_limitation=["operations", "monitoring"],
            data_minimization=True,
            cross_border_transfer=True
        )
        
        self.privacy_policies["personal_data"] = personal_policy
        self.privacy_policies["internal_data"] = internal_policy
    
    def add_privacy_policy(self, policy: PrivacyPolicy) -> bool:
        """Add a privacy policy"""
        if policy.policy_id in self.privacy_policies:
            return False
        
        self.privacy_policies[policy.policy_id] = policy
        return True
    
    def anonymize_data(
        self,
        data: Any,
        method: AnonymizationMethod,
        privacy_level: PrivacyLevel,
        k: int = None,
        l: int = None,
        epsilon: float = None
    ) -> AnonymizedData:
        """
        Anonymize data using specified method
        
        Args:
            data: Data to anonymize
            method: Anonymization method
            privacy_level: Required privacy level
            k: k-anonymity parameter
            l: l-diversity parameter
            epsilon: Differential privacy parameter
            
        Returns:
            Anonymized data object
        """
        if k is None:
            k = self.default_k_anonymity
        if l is None:
            l = self.default_l_diversity
        if epsilon is None:
            epsilon = self.default_epsilon
        
        # Check cache first
        data_hash = hashlib.sha256(str(data).encode()).hexdigest()
        cache_key = f"{data_hash}_{method.value}_{privacy_level.value}_{k}_{l}_{epsilon}"
        
        if cache_key in self.anonymization_cache:
            return self.anonymization_cache[cache_key]
        
        # Apply anonymization method
        if method == AnonymizationMethod.GENERALIZATION:
            anonymized_data = self._generalize_data(data, privacy_level)
        elif method == AnonymizationMethod.SUPPRESSION:
            anonymized_data = self._suppress_data(data, privacy_level)
        elif method == AnonymizationMethod.PERTURBATION:
            anonymized_data = self._perturb_data(data, epsilon)
        elif method == AnonymizationMethod.SWAPPING:
            anonymized_data = self._swap_data(data)
        elif method == AnonymizationMethod.MICROAGGREGATION:
            anonymized_data = self._microaggregate_data(data, k)
        elif method == AnonymizationMethod.DIFFERENTIAL_PRIVACY:
            anonymized_data = self._apply_differential_privacy(data, epsilon)
        else:
            anonymized_data = data
        
        # Create anonymized data object
        result = AnonymizedData(
            original_data=data,
            anonymized_data=anonymized_data,
            method=method,
            privacy_level=privacy_level,
            k_anonymity=k if method in [AnonymizationMethod.GENERALIZATION, AnonymizationMethod.MICROAGGREGATION] else None,
            l_diversity=l if method == AnonymizationMethod.GENERALIZATION else None,
            epsilon=epsilon if method == AnonymizationMethod.DIFFERENTIAL_PRIVACY else None,
            metadata={
                "anonymization_time": time.time(),
                "method_parameters": {"k": k, "l": l, "epsilon": epsilon}
            }
        )
        
        # Cache result
        self.anonymization_cache[cache_key] = result
        
        return result
    
    def _generalize_data(self, data: Any, privacy_level: PrivacyLevel) -> Any:
        """Apply generalization anonymization"""
        if isinstance(data, dict):
            generalized = {}
            for key, value in data.items():
                if self._is_quasi_identifier(key):
                    generalized[key] = self._generalize_value(value, privacy_level)
                else:
                    generalized[key] = value
            return generalized
        elif isinstance(data, list):
            return [self._generalize_data(item, privacy_level) for item in data]
        else:
            return self._generalize_value(data, privacy_level)
    
    def _generalize_value(self, value: Any, privacy_level: PrivacyLevel) -> Any:
        """Generalize a single value"""
        if isinstance(value, str):
            # Generalize strings by truncating or masking
            if privacy_level == PrivacyLevel.PERSONAL:
                return value[:2] + "*" * (len(value) - 2) if len(value) > 2 else "*"
            elif privacy_level == PrivacyLevel.CONFIDENTIAL:
                return value[:4] + "*" * (len(value) - 4) if len(value) > 4 else "*"
            else:
                return value
        elif isinstance(value, int):
            # Generalize integers by rounding
            if privacy_level == PrivacyLevel.PERSONAL:
                return (value // 10) * 10  # Round to nearest 10
            elif privacy_level == PrivacyLevel.CONFIDENTIAL:
                return (value // 5) * 5   # Round to nearest 5
            else:
                return value
        elif isinstance(value, float):
            # Generalize floats by rounding
            if privacy_level == PrivacyLevel.PERSONAL:
                return round(value, 0)  # Round to integer
            elif privacy_level == PrivacyLevel.CONFIDENTIAL:
                return round(value, 1)  # Round to 1 decimal
            else:
                return value
        else:
            return value
    
    def _suppress_data(self, data: Any, privacy_level: PrivacyLevel) -> Any:
        """Apply suppression anonymization"""
        if isinstance(data, dict):
            suppressed = {}
            for key, value in data.items():
                if self._is_sensitive_attribute(key):
                    suppressed[key] = None  # Suppress sensitive attributes
                else:
                    suppressed[key] = value
            return suppressed
        elif isinstance(data, list):
            # Suppress entire records if they contain sensitive data
            suppressed = []
            for item in data:
                if self._contains_sensitive_data(item):
                    suppressed.append(None)  # Suppress entire record
                else:
                    suppressed.append(item)
            return suppressed
        else:
            return None if self._is_sensitive_data(data) else data
    
    def _perturb_data(self, data: Any, epsilon: float) -> Any:
        """Apply perturbation anonymization"""
        if isinstance(data, (int, float)):
            # Add Laplace noise for numerical data
            noise = np.random.laplace(0, 1.0 / epsilon)
            return data + noise
        elif isinstance(data, list) and all(isinstance(x, (int, float)) for x in data):
            # Add noise to numerical lists
            noise = np.random.laplace(0, 1.0 / epsilon, len(data))
            return [x + n for x, n in zip(data, noise)]
        else:
            return data
    
    def _swap_data(self, data: Any) -> Any:
        """Apply swapping anonymization"""
        if isinstance(data, list) and len(data) > 1:
            # Swap elements in the list
            swapped = data.copy()
            for i in range(0, len(swapped) - 1, 2):
                swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            return swapped
        else:
            return data
    
    def _microaggregate_data(self, data: Any, k: int) -> Any:
        """Apply microaggregation anonymization"""
        if isinstance(data, list) and len(data) >= k:
            # Group data into clusters of size k and replace with cluster mean
            aggregated = []
            for i in range(0, len(data), k):
                cluster = data[i:i + k]
                if all(isinstance(x, (int, float)) for x in cluster):
                    # Numerical cluster - use mean
                    mean_value = sum(cluster) / len(cluster)
                    aggregated.extend([mean_value] * len(cluster))
                else:
                    # Non-numerical cluster - use most common value
                    from collections import Counter
                    most_common = Counter(cluster).most_common(1)[0][0]
                    aggregated.extend([most_common] * len(cluster))
            return aggregated
        else:
            return data
    
    def _apply_differential_privacy(self, data: Any, epsilon: float) -> Any:
        """Apply differential privacy"""
        if isinstance(data, (int, float)):
            # Add Laplace noise
            noise = np.random.laplace(0, 1.0 / epsilon)
            return data + noise
        elif isinstance(data, list):
            # Apply to each element
            return [self._apply_differential_privacy(item, epsilon) for item in data]
        else:
            return data
    
    def _is_quasi_identifier(self, key: str) -> bool:
        """Check if a key is a quasi-identifier"""
        quasi_identifiers = ["age", "zip", "gender", "occupation", "education", "income"]
        return any(qi in key.lower() for qi in quasi_identifiers)
    
    def _is_sensitive_attribute(self, key: str) -> bool:
        """Check if a key is a sensitive attribute"""
        sensitive_attributes = ["disease", "salary", "religion", "political", "sexual", "criminal"]
        return any(sa in key.lower() for sa in sensitive_attributes)
    
    def _is_sensitive_data(self, data: Any) -> bool:
        """Check if data is sensitive"""
        if isinstance(data, str):
            sensitive_keywords = ["password", "ssn", "credit", "medical", "bank"]
            return any(keyword in data.lower() for keyword in sensitive_keywords)
        return False
    
    def _contains_sensitive_data(self, data: Any) -> bool:
        """Check if data contains sensitive information"""
        if isinstance(data, dict):
            return any(self._is_sensitive_attribute(key) or self._is_sensitive_data(value) 
                      for key, value in data.items())
        else:
            return self._is_sensitive_data(data)
    
    def pseudonymize_data(self, data: Any, salt: Optional[str] = None) -> Any:
        """
        Pseudonymize data using cryptographic hashing
        
        Args:
            data: Data to pseudonymize
            salt: Optional salt for hashing
            
        Returns:
            Pseudonymized data
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        if isinstance(data, dict):
            pseudonymized = {}
            for key, value in data.items():
                if self._is_identifier(key):
                    pseudonymized[key] = self._hash_value(value, salt)
                else:
                    pseudonymized[key] = value
            return pseudonymized
        elif isinstance(data, list):
            return [self.pseudonymize_data(item, salt) for item in data]
        else:
            return self._hash_value(data, salt) if self._is_identifier(str(data)) else data
    
    def _is_identifier(self, value: str) -> bool:
        """Check if a value is an identifier"""
        identifier_patterns = ["id", "name", "email", "phone", "address", "ssn"]
        return any(pattern in value.lower() for pattern in identifier_patterns)
    
    def _hash_value(self, value: Any, salt: str) -> str:
        """Hash a value with salt"""
        value_str = str(value)
        salted_value = value_str + salt
        return hashlib.sha256(salted_value.encode()).hexdigest()[:16]  # Truncate to 16 chars
    
    def encrypt_sensitive_data(self, data: Any) -> bytes:
        """Encrypt sensitive data"""
        data_str = json.dumps(data)
        return self.cipher.encrypt(data_str.encode())
    
    def decrypt_sensitive_data(self, encrypted_data: bytes) -> Any:
        """Decrypt sensitive data"""
        decrypted_bytes = self.cipher.decrypt(encrypted_data)
        return json.loads(decrypted_bytes.decode())
    
    def manage_consent(self, subject_id: str, purpose: str, status: ConsentStatus, 
                      expires_at: Optional[float] = None) -> bool:
        """
        Manage consent for data processing
        
        Args:
            subject_id: Data subject identifier
            purpose: Purpose of data processing
            status: Consent status
            expires_at: Optional expiration timestamp
            
        Returns:
            True if consent managed successfully
        """
        if subject_id not in self.data_subjects:
            self.data_subjects[subject_id] = DataSubject(
                subject_id=subject_id,
                consent_records={},
                data_categories=set(),
                privacy_preferences={},
                last_updated=time.time()
            )
        
        subject = self.data_subjects[subject_id]
        subject.consent_records[purpose] = status
        subject.last_updated = time.time()
        
        # Record consent in consent records
        consent_id = str(uuid.uuid4())
        self.consent_records[consent_id] = {
            "subject_id": subject_id,
            "purpose": purpose,
            "status": status.value,
            "timestamp": time.time(),
            "expires_at": expires_at
        }
        
        return True
    
    def check_consent(self, subject_id: str, purpose: str) -> ConsentStatus:
        """Check consent status for data processing"""
        if subject_id not in self.data_subjects:
            return ConsentStatus.DENIED
        
        subject = self.data_subjects[subject_id]
        consent_status = subject.consent_records.get(purpose, ConsentStatus.DENIED)
        
        # Check if consent has expired
        for consent_id, record in self.consent_records.items():
            if (record["subject_id"] == subject_id and 
                record["purpose"] == purpose and 
                record["expires_at"] and 
                time.time() > record["expires_at"]):
                return ConsentStatus.EXPIRED
        
        return consent_status
    
    def assess_privacy_impact(self, data_categories: List[DataCategory], 
                            processing_purposes: List[str]) -> PrivacyImpact:
        """
        Assess privacy impact of data processing
        
        Args:
            data_categories: Categories of data being processed
            processing_purposes: Purposes of data processing
            
        Returns:
            Privacy impact assessment
        """
        assessment_id = str(uuid.uuid4())
        privacy_risks = []
        risk_level = "low"
        mitigation_measures = []
        residual_risk = 0.0
        compliance_status = True
        recommendations = []
        
        # Assess risks based on data categories
        if DataCategory.IDENTIFIER in data_categories:
            privacy_risks.append("Direct identification risk")
            risk_level = "high"
            mitigation_measures.append("Implement strong anonymization")
            residual_risk += 0.3
        
        if DataCategory.SENSITIVE_ATTRIBUTE in data_categories:
            privacy_risks.append("Sensitive attribute disclosure risk")
            risk_level = "high"
            mitigation_measures.append("Apply differential privacy")
            residual_risk += 0.4
        
        if DataCategory.QUASI_IDENTIFIER in data_categories:
            privacy_risks.append("Re-identification risk")
            risk_level = "medium"
            mitigation_measures.append("Implement k-anonymity")
            residual_risk += 0.2
        
        # Assess risks based on processing purposes
        if "marketing" in processing_purposes:
            privacy_risks.append("Commercial use risk")
            mitigation_measures.append("Obtain explicit consent")
            residual_risk += 0.2
        
        if "research" in processing_purposes:
            mitigation_measures.append("Use anonymized data")
            recommendations.append("Consider data minimization")
        
        # Determine overall risk level
        if residual_risk > 0.6:
            risk_level = "high"
        elif residual_risk > 0.3:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Check compliance
        if risk_level == "high" and not mitigation_measures:
            compliance_status = False
            recommendations.append("Implement additional privacy controls")
        
        return PrivacyImpact(
            assessment_id=assessment_id,
            data_categories=data_categories,
            privacy_risks=privacy_risks,
            risk_level=risk_level,
            mitigation_measures=mitigation_measures,
            residual_risk=residual_risk,
            compliance_status=compliance_status,
            recommendations=recommendations
        )
    
    def schedule_data_deletion(self, data_id: str, retention_days: int) -> bool:
        """
        Schedule data for deletion after retention period
        
        Args:
            data_id: Data identifier
            retention_days: Retention period in days
            
        Returns:
            True if deletion scheduled successfully
        """
        deletion_time = time.time() + (retention_days * 24 * 60 * 60)
        self.data_retention_schedule[data_id] = deletion_time
        return True
    
    def process_data_deletions(self) -> List[str]:
        """
        Process scheduled data deletions
        
        Returns:
            List of data IDs that were deleted
        """
        current_time = time.time()
        deleted_data = []
        
        for data_id, deletion_time in list(self.data_retention_schedule.items()):
            if current_time >= deletion_time:
                # Delete data (in real implementation, this would delete actual data)
                del self.data_retention_schedule[data_id]
                deleted_data.append(data_id)
        
        return deleted_data
    
    def apply_data_minimization(self, data: Any, purpose: str) -> Any:
        """
        Apply data minimization based on processing purpose
        
        Args:
            data: Data to minimize
            purpose: Processing purpose
            
        Returns:
            Minimized data
        """
        if isinstance(data, dict):
            minimized = {}
            for key, value in data.items():
                if self._is_relevant_for_purpose(key, purpose):
                    minimized[key] = value
            return minimized
        elif isinstance(data, list):
            return [self.apply_data_minimization(item, purpose) for item in data]
        else:
            return data
    
    def _is_relevant_for_purpose(self, key: str, purpose: str) -> bool:
        """Check if a data field is relevant for the processing purpose"""
        purpose_mappings = {
            "research": ["age", "gender", "education", "income"],
            "marketing": ["age", "gender", "preferences", "location"],
            "analytics": ["usage", "performance", "metrics"],
            "security": ["access", "authentication", "logs"]
        }
        
        relevant_fields = purpose_mappings.get(purpose, [])
        return any(field in key.lower() for field in relevant_fields)
    
    def check_cross_border_transfer(self, data_categories: List[DataCategory], 
                                  destination_country: str) -> bool:
        """
        Check if cross-border data transfer is allowed
        
        Args:
            data_categories: Categories of data being transferred
            destination_country: Destination country code
            
        Returns:
            True if transfer is allowed
        """
        # Check if any data category requires special handling
        restricted_categories = [DataCategory.IDENTIFIER, DataCategory.SENSITIVE_ATTRIBUTE]
        
        if any(cat in data_categories for cat in restricted_categories):
            # Check if destination country has adequate protection
            adequate_countries = ["US", "CA", "AU", "NZ", "CH", "IS", "NO", "LI"]
            return destination_country.upper() in adequate_countries
        
        return True
    
    def get_privacy_metrics(self) -> Dict[str, Any]:
        """Get privacy preservation metrics"""
        total_subjects = len(self.data_subjects)
        active_consents = sum(1 for subject in self.data_subjects.values() 
                            for status in subject.consent_records.values() 
                            if status == ConsentStatus.GRANTED)
        
        scheduled_deletions = len(self.data_retention_schedule)
        anonymization_operations = len(self.anonymization_cache)
        
        return {
            "total_data_subjects": total_subjects,
            "active_consents": active_consents,
            "scheduled_deletions": scheduled_deletions,
            "anonymization_operations": anonymization_operations,
            "privacy_policies": len(self.privacy_policies),
            "consent_records": len(self.consent_records)
        }
    
    def export_privacy_data(self, file_path: str) -> bool:
        """Export privacy data to file"""
        try:
            export_data = {
                "privacy_policies": {
                    policy_id: {
                        "policy_id": policy.policy_id,
                        "name": policy.name,
                        "description": policy.description,
                        "data_categories": [cat.value for cat in policy.data_categories],
                        "privacy_level": policy.privacy_level.value,
                        "retention_period": policy.retention_period,
                        "anonymization_required": policy.anonymization_required,
                        "consent_required": policy.consent_required,
                        "purpose_limitation": policy.purpose_limitation,
                        "data_minimization": policy.data_minimization,
                        "cross_border_transfer": policy.cross_border_transfer,
                        "metadata": policy.metadata
                    }
                    for policy_id, policy in self.privacy_policies.items()
                },
                "data_subjects": {
                    subject_id: {
                        "subject_id": subject.subject_id,
                        "consent_records": {purpose: status.value for purpose, status in subject.consent_records.items()},
                        "data_categories": [cat.value for cat in subject.data_categories],
                        "privacy_preferences": subject.privacy_preferences,
                        "last_updated": subject.last_updated
                    }
                    for subject_id, subject in self.data_subjects.items()
                },
                "consent_records": self.consent_records,
                "data_retention_schedule": self.data_retention_schedule,
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting privacy data: {e}")
            return False
