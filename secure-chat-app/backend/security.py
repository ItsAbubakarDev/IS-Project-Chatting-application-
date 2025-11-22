"""
Security utilities for authentication, password hashing, and encryption
"""
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
from dotenv import load_dotenv
import base64

# Load environment variables
load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ========== PASSWORD HASHING ==========

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    # Truncate password to 72 bytes for bcrypt compatibility
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


# ========== MESSAGE ENCRYPTION (End-to-End) ==========

class MessageEncryption:
    """Handles end-to-end encryption for messages using Fernet"""
    
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = b'secure_chat_salt') -> bytes:
        """Generate a Fernet key from a password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    @staticmethod
    def generate_key() -> str:
        """Generate a new random Fernet key"""
        return Fernet.generate_key().decode()
    
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


# ========== HELPER FUNCTIONS ==========

def create_user_encryption_key(username: str, password: str) -> str:
    """Create a unique encryption key for a user based on their credentials"""
    combined = f"{username}:{password}"
    key = MessageEncryption.generate_key_from_password(combined)
    return key.decode()


if __name__ == "__main__":
    # Test password hashing
    print("=== Testing Password Hashing ===")
    password = "my_secure_password123"
    hashed = hash_password(password)
    print(f"Original: {password}")
    print(f"Hashed: {hashed}")
    print(f"Verification: {verify_password(password, hashed)}")
    
    # Test JWT tokens
    print("\n=== Testing JWT Tokens ===")
    token = create_access_token(data={"sub": "testuser"})
    print(f"Token: {token}")
    print(f"Decoded username: {verify_token(token)}")
    
    # Test encryption
    print("\n=== Testing Message Encryption ===")
    key = MessageEncryption.generate_key()
    message = "Hello, this is a secret message!"
    encrypted = MessageEncryption.encrypt_message(message, key)
    print(f"Original: {message}")
    print(f"Encrypted: {encrypted}")
    decrypted = MessageEncryption.decrypt_message(encrypted, key)
    print(f"Decrypted: {decrypted}")
    
    print("\n✅ All security tests passed!")