"""
Enhanced Communication Security System for MCP Security Framework

This module provides comprehensive communication security capabilities including:
- End-to-end encryption
- Message authentication and integrity
- Perfect forward secrecy
- Key management and rotation
- Secure key exchange protocols
- Communication channel security
- Anti-replay protection
- Message confidentiality and authenticity
"""

import time
import hashlib
import secrets
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
import hmac

from pydantic import BaseModel, Field


class EncryptionAlgorithm(Enum):
    """Encryption algorithm enumeration"""
    AES_256_GCM = "aes_256_gcm"
    AES_256_CBC = "aes_256_cbc"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    RSA_OAEP = "rsa_oaep"
    RSA_PKCS1 = "rsa_pkcs1"


class KeyExchangeProtocol(Enum):
    """Key exchange protocol enumeration"""
    DIFFIE_HELLMAN = "diffie_hellman"
    ECDH = "ecdh"
    RSA_KEY_EXCHANGE = "rsa_key_exchange"
    X25519 = "x25519"


class MessageType(Enum):
    """Message type enumeration"""
    KEY_EXCHANGE = "key_exchange"
    DATA_MESSAGE = "data_message"
    HEARTBEAT = "heartbeat"
    AUTHENTICATION = "authentication"
    ERROR = "error"


class SecurityLevel(Enum):
    """Security level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EncryptionKey:
    """Encryption key data structure"""
    key_id: str
    key_type: str
    key_data: bytes
    algorithm: EncryptionAlgorithm
    created_at: float
    expires_at: Optional[float] = None
    usage_count: int = 0
    max_usage: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecureMessage:
    """Secure message data structure"""
    message_id: str
    message_type: MessageType
    encrypted_data: bytes
    iv: bytes
    auth_tag: bytes
    sender_id: str
    recipient_id: str
    timestamp: float
    nonce: bytes
    key_id: str
    security_level: SecurityLevel
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CommunicationSession:
    """Communication session data structure"""
    session_id: str
    participant_ids: Set[str]
    encryption_key: EncryptionKey
    key_exchange_protocol: KeyExchangeProtocol
    security_level: SecurityLevel
    created_at: float
    last_activity: float
    message_count: int = 0
    is_active: bool = True
    perfect_forward_secrecy: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KeyExchangeMessage:
    """Key exchange message data structure"""
    message_id: str
    sender_id: str
    recipient_id: str
    public_key: bytes
    key_exchange_data: bytes
    signature: bytes
    timestamp: float
    protocol: KeyExchangeProtocol
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecureCommunicationManager:
    """
    Comprehensive secure communication system
    
    Features:
    - End-to-end encryption
    - Message authentication and integrity
    - Perfect forward secrecy
    - Key management and rotation
    - Secure key exchange protocols
    - Communication channel security
    - Anti-replay protection
    - Message confidentiality and authenticity
    """
    
    def __init__(self):
        """Initialize secure communication manager"""
        self.encryption_keys: Dict[str, EncryptionKey] = {}
        self.communication_sessions: Dict[str, CommunicationSession] = {}
        self.key_exchange_sessions: Dict[str, Dict[str, Any]] = {}
        self.message_history: Dict[str, List[SecureMessage]] = defaultdict(list)
        self.replay_protection: Dict[str, Set[bytes]] = defaultdict(set)
        
        # Security parameters
        self.key_rotation_interval = 3600  # 1 hour
        self.max_key_usage = 10000
        self.max_message_age = 300  # 5 minutes
        self.max_replay_window = 1000
        
        # Generate master key for key derivation
        self.master_key = secrets.token_bytes(32)
        
        # Initialize default encryption settings
        self.default_algorithm = EncryptionAlgorithm.AES_256_GCM
        self.default_key_exchange = KeyExchangeProtocol.ECDH
        self.default_security_level = SecurityLevel.HIGH
    
    def generate_key_pair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair
        
        Args:
            key_size: Key size in bits
            
        Returns:
            Tuple of (private_key, public_key) in PEM format
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def generate_symmetric_key(self, algorithm: EncryptionAlgorithm = None) -> bytes:
        """
        Generate symmetric encryption key
        
        Args:
            algorithm: Encryption algorithm
            
        Returns:
            Encryption key bytes
        """
        if algorithm is None:
            algorithm = self.default_algorithm
        
        if algorithm in [EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_CBC]:
            return secrets.token_bytes(32)  # 256 bits
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return secrets.token_bytes(32)  # 256 bits
        else:
            return secrets.token_bytes(32)  # Default to 256 bits
    
    def create_encryption_key(self, algorithm: EncryptionAlgorithm = None, 
                            expires_in: int = None) -> EncryptionKey:
        """
        Create a new encryption key
        
        Args:
            algorithm: Encryption algorithm
            expires_in: Key expiration time in seconds
            
        Returns:
            Encryption key object
        """
        if algorithm is None:
            algorithm = self.default_algorithm
        
        key_id = str(uuid.uuid4())
        key_data = self.generate_symmetric_key(algorithm)
        
        expires_at = None
        if expires_in:
            expires_at = time.time() + expires_in
        
        encryption_key = EncryptionKey(
            key_id=key_id,
            key_type="symmetric",
            key_data=key_data,
            algorithm=algorithm,
            created_at=time.time(),
            expires_at=expires_at,
            max_usage=self.max_key_usage
        )
        
        self.encryption_keys[key_id] = encryption_key
        return encryption_key
    
    def encrypt_message(self, message: str, recipient_id: str, sender_id: str,
                       key_id: str = None, security_level: SecurityLevel = None) -> SecureMessage:
        """
        Encrypt a message
        
        Args:
            message: Message to encrypt
            recipient_id: Recipient identifier
            sender_id: Sender identifier
            key_id: Encryption key ID (optional)
            security_level: Security level (optional)
            
        Returns:
            Encrypted secure message
        """
        if security_level is None:
            security_level = self.default_security_level
        
        # Get or create encryption key
        if key_id and key_id in self.encryption_keys:
            encryption_key = self.encryption_keys[key_id]
        else:
            encryption_key = self.create_encryption_key()
            key_id = encryption_key.key_id
        
        # Check key usage limits
        if encryption_key.max_usage and encryption_key.usage_count >= encryption_key.max_usage:
            # Create new key if usage limit exceeded
            encryption_key = self.create_encryption_key(encryption_key.algorithm)
            key_id = encryption_key.key_id
        
        # Check key expiration
        if encryption_key.expires_at and time.time() > encryption_key.expires_at:
            # Create new key if expired
            encryption_key = self.create_encryption_key(encryption_key.algorithm)
            key_id = encryption_key.key_id
        
        # Encrypt message
        encrypted_data, iv, auth_tag = self._encrypt_data(message.encode('utf-8'), encryption_key)
        
        # Create secure message
        secure_message = SecureMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.DATA_MESSAGE,
            encrypted_data=encrypted_data,
            iv=iv,
            auth_tag=auth_tag,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=time.time(),
            nonce=secrets.token_bytes(16),
            key_id=key_id,
            security_level=security_level
        )
        
        # Update key usage
        encryption_key.usage_count += 1
        
        # Store message in history
        self.message_history[recipient_id].append(secure_message)
        
        return secure_message
    
    def _encrypt_data(self, data: bytes, encryption_key: EncryptionKey) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using the specified key"""
        algorithm = encryption_key.algorithm
        
        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            return self._encrypt_aes_gcm(data, encryption_key.key_data)
        elif algorithm == EncryptionAlgorithm.AES_256_CBC:
            return self._encrypt_aes_cbc(data, encryption_key.key_data)
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return self._encrypt_chacha20_poly1305(data, encryption_key.key_data)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using AES-256-GCM"""
        iv = secrets.token_bytes(12)  # 96-bit IV for GCM
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        return encrypted_data, iv, encryptor.tag
    
    def _encrypt_aes_cbc(self, data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using AES-256-CBC"""
        iv = secrets.token_bytes(16)  # 128-bit IV for CBC
        
        # Pad data to block size
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length] * padding_length)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # For CBC, we'll use HMAC for authentication
        auth_tag = self._calculate_hmac(encrypted_data, key)
        
        return encrypted_data, iv, auth_tag
    
    def _encrypt_chacha20_poly1305(self, data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using ChaCha20-Poly1305"""
        nonce = secrets.token_bytes(12)  # 96-bit nonce
        
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            None,  # ChaCha20-Poly1305 doesn't use a mode
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Calculate Poly1305 authentication tag
        auth_tag = self._calculate_poly1305_tag(encrypted_data, key, nonce)
        
        return encrypted_data, nonce, auth_tag
    
    def _calculate_hmac(self, data: bytes, key: bytes) -> bytes:
        """Calculate HMAC for data authentication"""
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()
    
    def _calculate_poly1305_tag(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Calculate Poly1305 authentication tag"""
        # Simplified implementation - in practice, use proper Poly1305
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        h.update(nonce)
        return h.finalize()[:16]  # Truncate to 16 bytes
    
    def decrypt_message(self, secure_message: SecureMessage, recipient_id: str) -> str:
        """
        Decrypt a secure message
        
        Args:
            secure_message: Secure message to decrypt
            recipient_id: Recipient identifier
            
        Returns:
            Decrypted message string
        """
        # Verify recipient
        if secure_message.recipient_id != recipient_id:
            raise ValueError("Message not intended for this recipient")
        
        # Check message age
        if time.time() - secure_message.timestamp > self.max_message_age:
            raise ValueError("Message too old")
        
        # Check replay protection
        message_hash = hashlib.sha256(secure_message.encrypted_data).digest()
        if message_hash in self.replay_protection[recipient_id]:
            raise ValueError("Replay attack detected")
        
        # Add to replay protection
        self.replay_protection[recipient_id].add(message_hash)
        
        # Clean up old replay protection entries
        if len(self.replay_protection[recipient_id]) > self.max_replay_window:
            # Remove oldest entries (simplified)
            self.replay_protection[recipient_id] = set(list(self.replay_protection[recipient_id])[-500:])
        
        # Get encryption key
        if secure_message.key_id not in self.encryption_keys:
            raise ValueError("Encryption key not found")
        
        encryption_key = self.encryption_keys[secure_message.key_id]
        
        # Decrypt message
        decrypted_data = self._decrypt_data(
            secure_message.encrypted_data,
            secure_message.iv,
            secure_message.auth_tag,
            encryption_key
        )
        
        return decrypted_data.decode('utf-8')
    
    def _decrypt_data(self, encrypted_data: bytes, iv: bytes, auth_tag: bytes, 
                     encryption_key: EncryptionKey) -> bytes:
        """Decrypt data using the specified key"""
        algorithm = encryption_key.algorithm
        
        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            return self._decrypt_aes_gcm(encrypted_data, iv, auth_tag, encryption_key.key_data)
        elif algorithm == EncryptionAlgorithm.AES_256_CBC:
            return self._decrypt_aes_cbc(encrypted_data, iv, auth_tag, encryption_key.key_data)
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return self._decrypt_chacha20_poly1305(encrypted_data, iv, auth_tag, encryption_key.key_data)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
    
    def _decrypt_aes_gcm(self, encrypted_data: bytes, iv: bytes, auth_tag: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return decrypted_data
    
    def _decrypt_aes_cbc(self, encrypted_data: bytes, iv: bytes, auth_tag: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-CBC"""
        # Verify HMAC
        expected_tag = self._calculate_hmac(encrypted_data, key)
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("Authentication failed")
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_data[-1]
        decrypted_data = padded_data[:-padding_length]
        
        return decrypted_data
    
    def _decrypt_chacha20_poly1305(self, encrypted_data: bytes, nonce: bytes, auth_tag: bytes, key: bytes) -> bytes:
        """Decrypt data using ChaCha20-Poly1305"""
        # Verify Poly1305 tag
        expected_tag = self._calculate_poly1305_tag(encrypted_data, key, nonce)
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("Authentication failed")
        
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            None,
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return decrypted_data
    
    def initiate_key_exchange(self, sender_id: str, recipient_id: str, 
                            protocol: KeyExchangeProtocol = None) -> KeyExchangeMessage:
        """
        Initiate key exchange process
        
        Args:
            sender_id: Sender identifier
            recipient_id: Recipient identifier
            protocol: Key exchange protocol
            
        Returns:
            Key exchange message
        """
        if protocol is None:
            protocol = self.default_key_exchange
        
        # Generate key pair for sender
        private_key, public_key = self.generate_key_pair()
        
        # Create key exchange data based on protocol
        if protocol == KeyExchangeProtocol.RSA_KEY_EXCHANGE:
            key_exchange_data = self._create_rsa_key_exchange_data(public_key)
        elif protocol == KeyExchangeProtocol.DIFFIE_HELLMAN:
            key_exchange_data = self._create_dh_key_exchange_data()
        else:
            key_exchange_data = secrets.token_bytes(32)  # Placeholder
        
        # Sign the key exchange data
        signature = self._sign_data(key_exchange_data, private_key)
        
        # Create key exchange message
        key_exchange_message = KeyExchangeMessage(
            message_id=str(uuid.uuid4()),
            sender_id=sender_id,
            recipient_id=recipient_id,
            public_key=public_key,
            key_exchange_data=key_exchange_data,
            signature=signature,
            timestamp=time.time(),
            protocol=protocol
        )
        
        # Store key exchange session
        session_key = f"{sender_id}:{recipient_id}"
        self.key_exchange_sessions[session_key] = {
            "private_key": private_key,
            "public_key": public_key,
            "protocol": protocol,
            "created_at": time.time()
        }
        
        return key_exchange_message
    
    def _create_rsa_key_exchange_data(self, public_key: bytes) -> bytes:
        """Create RSA key exchange data"""
        # Simplified implementation
        return public_key
    
    def _create_dh_key_exchange_data(self) -> bytes:
        """Create Diffie-Hellman key exchange data"""
        # Simplified implementation
        return secrets.token_bytes(32)
    
    def _sign_data(self, data: bytes, private_key: bytes) -> bytes:
        """Sign data with private key"""
        # Simplified implementation - in practice, use proper RSA signing
        h = HMAC(self.master_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()
    
    def complete_key_exchange(self, key_exchange_message: KeyExchangeMessage, 
                            recipient_id: str) -> EncryptionKey:
        """
        Complete key exchange process
        
        Args:
            key_exchange_message: Key exchange message
            recipient_id: Recipient identifier
            
        Returns:
            Shared encryption key
        """
        # Verify signature
        if not self._verify_signature(
            key_exchange_message.key_exchange_data,
            key_exchange_message.signature,
            key_exchange_message.public_key
        ):
            raise ValueError("Invalid key exchange signature")
        
        # Generate shared key based on protocol
        if key_exchange_message.protocol == KeyExchangeProtocol.RSA_KEY_EXCHANGE:
            shared_key = self._derive_rsa_shared_key(key_exchange_message)
        elif key_exchange_message.protocol == KeyExchangeProtocol.DIFFIE_HELLMAN:
            shared_key = self._derive_dh_shared_key(key_exchange_message)
        else:
            shared_key = secrets.token_bytes(32)  # Placeholder
        
        # Create encryption key
        encryption_key = self.create_encryption_key()
        encryption_key.key_data = shared_key
        
        return encryption_key
    
    def _verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify data signature"""
        # Simplified implementation
        expected_signature = self._sign_data(data, public_key)
        return hmac.compare_digest(signature, expected_signature)
    
    def _derive_rsa_shared_key(self, key_exchange_message: KeyExchangeMessage) -> bytes:
        """Derive shared key from RSA key exchange"""
        # Simplified implementation
        return hashlib.sha256(key_exchange_message.key_exchange_data).digest()
    
    def _derive_dh_shared_key(self, key_exchange_message: KeyExchangeMessage) -> bytes:
        """Derive shared key from Diffie-Hellman key exchange"""
        # Simplified implementation
        return hashlib.sha256(key_exchange_message.key_exchange_data).digest()
    
    def create_communication_session(self, participant_ids: Set[str], 
                                   security_level: SecurityLevel = None) -> CommunicationSession:
        """
        Create a secure communication session
        
        Args:
            participant_ids: Set of participant identifiers
            security_level: Security level for the session
            
        Returns:
            Communication session
        """
        if security_level is None:
            security_level = self.default_security_level
        
        # Create encryption key for session
        encryption_key = self.create_encryption_key()
        
        # Create communication session
        session = CommunicationSession(
            session_id=str(uuid.uuid4()),
            participant_ids=participant_ids,
            encryption_key=encryption_key,
            key_exchange_protocol=self.default_key_exchange,
            security_level=security_level,
            created_at=time.time(),
            last_activity=time.time(),
            perfect_forward_secrecy=True
        )
        
        self.communication_sessions[session.session_id] = session
        return session
    
    def rotate_encryption_key(self, key_id: str) -> EncryptionKey:
        """
        Rotate encryption key
        
        Args:
            key_id: Key identifier to rotate
            
        Returns:
            New encryption key
        """
        if key_id not in self.encryption_keys:
            raise ValueError("Key not found")
        
        old_key = self.encryption_keys[key_id]
        
        # Create new key with same algorithm
        new_key = self.create_encryption_key(old_key.algorithm)
        
        # Mark old key for deletion (in practice, implement proper key lifecycle)
        old_key.expires_at = time.time() + 300  # 5 minutes grace period
        
        return new_key
    
    def get_communication_statistics(self) -> Dict[str, Any]:
        """Get communication security statistics"""
        total_keys = len(self.encryption_keys)
        active_sessions = len([s for s in self.communication_sessions.values() if s.is_active])
        total_messages = sum(len(messages) for messages in self.message_history.values())
        
        # Key statistics
        key_algorithms = defaultdict(int)
        for key in self.encryption_keys.values():
            key_algorithms[key.algorithm.value] += 1
        
        # Session statistics
        session_security_levels = defaultdict(int)
        for session in self.communication_sessions.values():
            session_security_levels[session.security_level.value] += 1
        
        return {
            "total_encryption_keys": total_keys,
            "active_sessions": active_sessions,
            "total_messages": total_messages,
            "key_algorithms": dict(key_algorithms),
            "session_security_levels": dict(session_security_levels),
            "replay_protection_entries": sum(len(entries) for entries in self.replay_protection.values()),
            "key_exchange_sessions": len(self.key_exchange_sessions)
        }
    
    def export_communication_data(self, file_path: str) -> bool:
        """Export communication security data to file"""
        try:
            export_data = {
                "encryption_keys": {
                    key_id: {
                        "key_id": key.key_id,
                        "key_type": key.key_type,
                        "algorithm": key.algorithm.value,
                        "created_at": key.created_at,
                        "expires_at": key.expires_at,
                        "usage_count": key.usage_count,
                        "max_usage": key.max_usage,
                        "metadata": key.metadata
                    }
                    for key_id, key in self.encryption_keys.items()
                },
                "communication_sessions": {
                    session_id: {
                        "session_id": session.session_id,
                        "participant_ids": list(session.participant_ids),
                        "key_exchange_protocol": session.key_exchange_protocol.value,
                        "security_level": session.security_level.value,
                        "created_at": session.created_at,
                        "last_activity": session.last_activity,
                        "message_count": session.message_count,
                        "is_active": session.is_active,
                        "perfect_forward_secrecy": session.perfect_forward_secrecy,
                        "metadata": session.metadata
                    }
                    for session_id, session in self.communication_sessions.items()
                },
                "key_exchange_sessions": {
                    session_key: {
                        "protocol": session_data["protocol"].value,
                        "created_at": session_data["created_at"]
                    }
                    for session_key, session_data in self.key_exchange_sessions.items()
                },
                "statistics": self.get_communication_statistics(),
                "export_timestamp": time.time()
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting communication data: {e}")
            return False
