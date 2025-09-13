"""
Cryptographic utilities for MCP Security Framework

This module provides cryptographic functions for key generation, signing,
verification, and encryption for the MCP Security Framework.
"""

import hashlib
import secrets
import base64
from typing import Tuple, Optional, Union, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Generate RSA key pair
    
    Args:
        key_size: Key size in bits (1024, 2048, 3072, or 4096)
        
    Returns:
        Tuple of (private_key, public_key) in PEM format
    """
    if key_size not in [1024, 2048, 3072, 4096]:
        raise ValueError("Key size must be 1024, 2048, 3072, or 4096")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Get public key
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


def sign_data(data: Union[str, bytes], private_key: bytes) -> bytes:
    """
    Sign data with private key
    
    Args:
        data: Data to sign (string or bytes)
        private_key: Private key in PEM format
        
    Returns:
        Digital signature
    """
    # Convert data to bytes if string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Load private key
    key = serialization.load_pem_private_key(
        private_key, password=None, backend=default_backend()
    )
    
    # Sign data
    signature = key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(
    data: Union[str, bytes], 
    signature: bytes, 
    public_key: bytes
) -> bool:
    """
    Verify digital signature
    
    Args:
        data: Original data (string or bytes)
        signature: Digital signature
        public_key: Public key in PEM format
        
    Returns:
        True if signature is valid
    """
    try:
        # Convert data to bytes if string
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Load public key
        key = serialization.load_pem_public_key(
            public_key, backend=default_backend()
        )
        
        # Verify signature
        key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
        
    except Exception:
        return False


def generate_hash(data: Union[str, bytes], algorithm: str = "SHA256") -> str:
    """
    Generate hash of data
    
    Args:
        data: Data to hash (string or bytes)
        algorithm: Hash algorithm (SHA256, SHA512, etc.)
        
    Returns:
        Hexadecimal hash string
    """
    # Convert data to bytes if string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Get hash function
    hash_func = getattr(hashes, algorithm.upper(), hashes.SHA256)
    
    # Generate hash
    digest = hashlib.new(algorithm.lower(), data)
    
    return digest.hexdigest()


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def generate_random_string(length: int) -> str:
    """
    Generate cryptographically secure random string
    
    Args:
        length: Length of string to generate
        
    Returns:
        Random string
    """
    return secrets.token_urlsafe(length)


def encrypt_data(
    data: Union[str, bytes], 
    password: str, 
    salt: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data with password
    
    Args:
        data: Data to encrypt (string or bytes)
        password: Encryption password
        salt: Optional salt (generated if None)
        
    Returns:
        Tuple of (encrypted_data, salt, iv)
    """
    # Convert data to bytes if string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate salt if not provided
    if salt is None:
        salt = generate_random_bytes(16)
    
    # Generate IV
    iv = generate_random_bytes(16)
    
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # Encrypt data
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return ciphertext, salt, iv


def decrypt_data(
    encrypted_data: bytes,
    password: str,
    salt: bytes,
    iv: bytes
) -> bytes:
    """
    Decrypt data with password
    
    Args:
        encrypted_data: Encrypted data
        password: Decryption password
        salt: Salt used for encryption
        iv: Initialization vector
        
    Returns:
        Decrypted data
    """
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # Decrypt data
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    
    return plaintext


def create_digital_certificate(
    subject: str,
    issuer: str,
    public_key: bytes,
    private_key: bytes,
    validity_days: int = 365
) -> bytes:
    """
    Create a simple digital certificate
    
    Args:
        subject: Certificate subject
        issuer: Certificate issuer
        public_key: Subject's public key
        private_key: Issuer's private key
        validity_days: Certificate validity in days
        
    Returns:
        Certificate in PEM format
    """
    import time
    
    # Create certificate data
    cert_data = {
        "version": "1.0",
        "serial_number": secrets.randbits(64),
        "issuer": issuer,
        "subject": subject,
        "valid_from": int(time.time()),
        "valid_to": int(time.time()) + (validity_days * 24 * 60 * 60),
        "public_key": base64.b64encode(public_key).decode(),
        "signature_algorithm": "RSA-PSS-SHA256"
    }
    
    # Create certificate string
    cert_string = f"{cert_data['version']}\n{cert_data['serial_number']}\n{cert_data['issuer']}\n{cert_data['subject']}\n{cert_data['valid_from']}\n{cert_data['valid_to']}\n{cert_data['public_key']}\n{cert_data['signature_algorithm']}"
    
    # Sign certificate
    signature = sign_data(cert_string, private_key)
    
    # Create final certificate
    certificate = {
        "certificate_data": cert_data,
        "signature": base64.b64encode(signature).decode()
    }
    
    # Convert to PEM format
    cert_pem = f"-----BEGIN CERTIFICATE-----\n{base64.b64encode(str(certificate).encode()).decode()}\n-----END CERTIFICATE-----"
    
    return cert_pem.encode()


def verify_certificate(certificate: bytes, issuer_public_key: bytes) -> bool:
    """
    Verify digital certificate
    
    Args:
        certificate: Certificate in PEM format
        issuer_public_key: Issuer's public key
        
    Returns:
        True if certificate is valid
    """
    try:
        # Parse certificate
        cert_str = certificate.decode()
        if not cert_str.startswith("-----BEGIN CERTIFICATE-----"):
            return False
        
        # Extract certificate data
        cert_data_b64 = cert_str.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
        cert_data_str = base64.b64decode(cert_data_b64).decode()
        
        # Parse certificate dictionary
        import ast
        certificate_dict = ast.literal_eval(cert_data_str)
        cert_data = certificate_dict["certificate_data"]
        signature = base64.b64decode(certificate_dict["signature"])
        
        # Recreate certificate string
        cert_string = f"{cert_data['version']}\n{cert_data['serial_number']}\n{cert_data['issuer']}\n{cert_data['subject']}\n{cert_data['valid_from']}\n{cert_data['valid_to']}\n{cert_data['public_key']}\n{cert_data['signature_algorithm']}"
        
        # Verify signature
        if not verify_signature(cert_string, signature, issuer_public_key):
            return False
        
        # Check validity period
        current_time = int(time.time())
        if current_time < cert_data['valid_from'] or current_time > cert_data['valid_to']:
            return False
        
        return True
        
    except Exception:
        return False


def create_secure_token(
    data: Dict[str, any],
    secret_key: str,
    expiration_seconds: int = 3600
) -> str:
    """
    Create a secure token with expiration
    
    Args:
        data: Data to include in token
        secret_key: Secret key for signing
        expiration_seconds: Token expiration in seconds
        
    Returns:
        Secure token string
    """
    import time
    import json
    
    # Add expiration time
    token_data = {
        **data,
        "exp": int(time.time()) + expiration_seconds,
        "iat": int(time.time())
    }
    
    # Create token string
    token_string = json.dumps(token_data, sort_keys=True)
    
    # Sign token
    signature = sign_data(token_string, secret_key.encode())
    
    # Encode token
    token_encoded = base64.b64encode(f"{token_string}.{base64.b64encode(signature).decode()}".encode()).decode()
    
    return token_encoded


def verify_secure_token(token: str, secret_key: str) -> Optional[Dict[str, any]]:
    """
    Verify and decode secure token
    
    Args:
        token: Secure token string
        secret_key: Secret key for verification
        
    Returns:
        Token data if valid, None if invalid
    """
    try:
        import time
        import json
        
        # Decode token
        token_decoded = base64.b64decode(token).decode()
        
        # Split token and signature
        token_string, signature_b64 = token_decoded.split('.', 1)
        signature = base64.b64decode(signature_b64)
        
        # Verify signature
        if not verify_signature(token_string, signature, secret_key.encode()):
            return None
        
        # Parse token data
        token_data = json.loads(token_string)
        
        # Check expiration
        if time.time() > token_data.get('exp', 0):
            return None
        
        return token_data
        
    except Exception:
        return None
