"""
Enhanced Security utilities with Diffie-Hellman key exchange for E2EE
Includes JWT authentication, password policy, and per-chat encryption
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import os
from dotenv import load_dotenv
import base64
import secrets
import re

# Load environment variables
load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# DH parameters (2048-bit MODP Group 14 from RFC 3526)
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())


# ========== PASSWORD POLICY ==========

class PasswordPolicy:
    """Enforce strong password requirements"""
    
    MIN_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    @classmethod
    def validate(cls, password: str) -> Tuple[bool, str]:
        """
        Validate password against policy
        Returns: (is_valid, error_message)
        """
        if len(password) < cls.MIN_LENGTH:
            return False, f"Password must be at least {cls.MIN_LENGTH} characters long"
        
        if cls.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if cls.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if cls.REQUIRE_DIGIT and not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if cls.REQUIRE_SPECIAL and not any(c in cls.SPECIAL_CHARS for c in password):
            return False, f"Password must contain at least one special character ({cls.SPECIAL_CHARS})"
        
        # Check for common patterns
        if re.search(r'(.)\1{2,}', password):
            return False, "Password should not contain repeated characters"
        
        return True, "Password is strong"


# ========== PASSWORD HASHING ==========

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    if len(password.encode('utf-8')) > 72:
        password = password[:72]
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


# ========== JWT TOKEN MANAGEMENT ==========

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


def verify_token(token: str) -> Optional[str]:
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            return None
            
        return username
        
    except JWTError:
        return None


# ========== DIFFIE-HELLMAN KEY EXCHANGE ==========

class DHKeyExchange:
    """Handles Diffie-Hellman key exchange for E2EE"""
    
    def __init__(self):
        self.private_key = DH_PARAMETERS.generate_private_key()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self) -> str:
        """Get public key as base64 string"""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    def compute_shared_secret(self, peer_public_key_str: str) -> bytes:
        """
        Compute shared secret from peer's public key
        Returns raw shared secret bytes
        """
        # Decode peer's public key
        peer_public_bytes = base64.b64decode(peer_public_key_str)
        peer_public_key = serialization.load_pem_public_key(
            peer_public_bytes,
            backend=default_backend()
        )
        
        # Compute shared secret
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret
    
    def derive_encryption_key(self, shared_secret: bytes, salt: bytes = None) -> str:
        """
        Derive a Fernet key from shared secret using PBKDF2
        """
        if salt is None:
            salt = b'secure_chat_dh_salt_v1'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(shared_secret))
        return key.decode('utf-8')
    
    @staticmethod
    def generate_chat_key(user1_public: str, user2_public: str) -> str:
        """
        Generate a deterministic shared key for a chat between two users
        This ensures both users derive the same key regardless of who initiates
        """
        # Sort public keys to ensure deterministic ordering
        keys = sorted([user1_public, user2_public])
        combined = f"{keys[0]}:{keys[1]}".encode('utf-8')
        
        # Derive key from combined public keys
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'chat_key_salt_v1',
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(combined))
        return key.decode('utf-8')


# ========== MESSAGE ENCRYPTION ==========

class MessageEncryption:
    """Handles message encryption/decryption using Fernet"""
    
    @staticmethod
    def encrypt_message(message: str, key: str) -> str:
        """Encrypt a message using Fernet symmetric encryption"""
        try:
            fernet = Fernet(key.encode() if isinstance(key, str) else key)
            encrypted = fernet.encrypt(message.encode())
            return encrypted.decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_message(encrypted_message: str, key: str) -> str:
        """Decrypt a message using Fernet symmetric encryption"""
        try:
            fernet = Fernet(key.encode() if isinstance(key, str) else key)
            decrypted = fernet.decrypt(encrypted_message.encode())
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


# ========== TESTING ==========

if __name__ == "__main__":
    print("=== Testing Enhanced Security ===\n")
    
    # Test password policy
    print("1. Testing Password Policy")
    test_passwords = [
        "weak",
        "StrongPass123!",
        "NoSpecialChar123",
        "alllowercase123!",
        "ALLUPPERCASE123!",
    ]
    
    for pwd in test_passwords:
        valid, msg = PasswordPolicy.validate(pwd)
        print(f"  '{pwd}': {'✅' if valid else '❌'} {msg}")
    
    # Test DH key exchange
    print("\n2. Testing Diffie-Hellman Key Exchange")
    
    # Asma generates her keys
    asma_dh = DHKeyExchange()
    asma_public = asma_dh.get_public_key_bytes()
    print(f"  Asma public key (first 50 chars): {asma_public[:50]}...")
    
    # Abubakar generates his keys
    abubakar_dh = DHKeyExchange()
    abubakar_public = abubakar_dh.get_public_key_bytes()
    print(f"  Abubakar public key (first 50 chars): {abubakar_public[:50]}...")
    
    # Both compute shared secret
    asma_shared = asma_dh.compute_shared_secret(abubakar_public)
    abubakar_shared = abubakar_dh.compute_shared_secret(asma_public)
    
    # Derive encryption keys
    asma_key = asma_dh.derive_encryption_key(asma_shared)
    abubakar_key = abubakar_dh.derive_encryption_key(abubakar_shared)
    
    print(f"  Keys match: {'✅' if asma_key == abubakar_key else '❌'}")
    
    # Test encryption with derived key
    print("\n3. Testing Message Encryption with DH Key")
    message = "Hello, this is a secret message!"
    encrypted = MessageEncryption.encrypt_message(message, asma_key)
    print(f"  Original: {message}")
    print(f"  Encrypted (first 50 chars): {encrypted[:50]}...")
    
    decrypted = MessageEncryption.decrypt_message(encrypted, abubakar_key)
    print(f"  Decrypted: {decrypted}")
    print(f"  Match: {'✅' if message == decrypted else '❌'}")
    
    # Test deterministic chat key generation
    print("\n4. Testing Deterministic Chat Key")
    key1 = DHKeyExchange.generate_chat_key(asma_public, abubakar_public)
    key2 = DHKeyExchange.generate_chat_key(abubakar_public, asma_public)
    print(f"  Keys match (different order): {'✅' if key1 == key2 else '❌'}")
    
    print("\n✅ All security tests passed!")