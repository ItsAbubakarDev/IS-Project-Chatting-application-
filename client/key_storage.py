# client/key_storage.py

import os
import json
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class KeyStorage:
    """
    Securely store private keys locally, encrypted with user's password
    Keys are stored in: ~/.secure_chat/keys/
    """
    
    def __init__(self):
        self.keys_dir = Path.home() / ".secure_chat" / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_encryption_key(self, username: str, password: str) -> bytes:
        """Derive encryption key from username + password"""
        salt = f"secure_chat_{username}".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def save_private_key(self, username: str, password: str, private_key_pem: bytes):
        """Save private key encrypted with user's password"""
        try:
            # Encrypt private key with password-derived key
            encryption_key = self._get_encryption_key(username, password)
            fernet = Fernet(encryption_key)
            encrypted_key = fernet.encrypt(private_key_pem)
            
            # Save to file
            key_file = self.keys_dir / f"{username}.key"
            with open(key_file, 'wb') as f:
                f.write(encrypted_key)
            
            # Secure file permissions (owner read/write only)
            os.chmod(key_file, 0o600)
            
            print(f"✅ Private key saved securely for {username}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to save private key: {e}")
            return False
    
    def load_private_key(self, username: str, password: str) -> bytes:
        """Load and decrypt private key"""
        try:
            key_file = self.keys_dir / f"{username}.key"
            
            if not key_file.exists():
                return None
            
            # Read encrypted key
            with open(key_file, 'rb') as f:
                encrypted_key = f.read()
            
            # Decrypt with password-derived key
            encryption_key = self._get_encryption_key(username, password)
            fernet = Fernet(encryption_key)
            private_key_pem = fernet.decrypt(encrypted_key)
            
            print(f"✅ Private key loaded for {username}")
            return private_key_pem
            
        except Exception as e:
            print(f"⚠️  Failed to load private key: {e}")
            return None
    
    def delete_private_key(self, username: str):
        """Delete stored private key (for logout/key rotation)"""
        try:
            key_file = self.keys_dir / f"{username}.key"
            if key_file.exists():
                key_file.unlink()
                print(f"🗑️  Private key deleted for {username}")
                return True
        except Exception as e:
            print(f"⚠️  Failed to delete private key: {e}")
        return False
    
    def has_stored_key(self, username: str) -> bool:
        """Check if user has a stored private key"""
        key_file = self.keys_dir / f"{username}.key"
        return key_file.exists()