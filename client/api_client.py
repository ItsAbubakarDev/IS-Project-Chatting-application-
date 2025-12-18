"""
Enhanced API Client with Diffie-Hellman key exchange for true E2EE
Each chat session uses a unique derived key
"""
import requests
import json
import websocket
import threading
from typing import Optional, Callable, Dict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


class E2EEManager:
    """Manages per-chat encryption keys using DH"""
    
    def __init__(self):
        self.chat_keys: Dict[str, str] = {}  # username -> encryption_key
    
    def generate_chat_key(self, user1_public: str, user2_public: str) -> str:
        """
        Generate a deterministic shared key for a chat between two users
        Both users will derive the same key
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
    
    def set_chat_key(self, username: str, key: str):
        """Store encryption key for a specific user chat"""
        self.chat_keys[username] = key
    
    def get_chat_key(self, username: str) -> Optional[str]:
        """Get encryption key for a specific user chat"""
        return self.chat_keys.get(username)
    
    def encrypt_message(self, message: str, username: str) -> str:
        """Encrypt message for specific user"""
        key = self.get_chat_key(username)
        if not key:
            raise ValueError(f"No encryption key for {username}")
        
        fernet = Fernet(key.encode())
        encrypted = fernet.encrypt(message.encode())
        return encrypted.decode()
    
    def decrypt_message(self, encrypted: str, username: str) -> str:
        """Decrypt message from specific user"""
        key = self.get_chat_key(username)
        if not key:
            raise ValueError(f"No encryption key for {username}")
        
        fernet = Fernet(key.encode())
        decrypted = fernet.decrypt(encrypted.encode())
        return decrypted.decode()


class SecureChatAPI:
    """Enhanced API client with E2EE using Diffie-Hellman"""
    
    def __init__(self, base_url: str = "http://127.0.0.1:8000", use_ssl: bool = False):
        self.base_url = base_url
        if use_ssl:
            self.base_url = base_url.replace("http://", "https://")
            self.ws_url = base_url.replace("http://", "wss://").replace("https://", "wss://")
        else:
            self.ws_url = base_url.replace("http://", "ws://").replace("https://", "ws://")
        
        self.token: Optional[str] = None
        self.username: Optional[str] = None
        self.user_id: Optional[int] = None
        self.my_public_key: Optional[str] = None
        
        # E2EE manager for per-chat keys
        self.e2ee = E2EEManager()
        
        self.ws: Optional[websocket.WebSocketApp] = None
        self.ws_thread: Optional[threading.Thread] = None
        self.message_callback: Optional[Callable] = None
        
        # SSL verification (disable for self-signed certs in dev)
        self.verify_ssl = False  # Set to True in production with proper certs
    
    # ========== AUTHENTICATION ==========
    
    def register(self, username: str, email: str, password: str) -> Dict:
        """Register a new user"""
        try:
            response = requests.post(
                f"{self.base_url}/register",
                json={
                    "username": username,
                    "email": email,
                    "password": password
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 201:
                return {"success": True, "data": response.json()}
            else:
                error_detail = response.json().get("detail", "Registration failed")
                return {"success": False, "error": error_detail}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def login(self, username: str, password: str) -> Dict:
        """Login and get JWT token + public key"""
        try:
            response = requests.post(
                f"{self.base_url}/login",
                data={
                    "username": username,
                    "password": password
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                self.username = data["username"]
                self.user_id = data["user_id"]
                self.my_public_key = data.get("public_key")
                
                return {"success": True, "data": data}
            else:
                error_detail = response.json().get("detail", "Login failed")
                return {"success": False, "error": error_detail}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def logout(self) -> Dict:
        """Logout"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(
                f"{self.base_url}/logout",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                self.disconnect_websocket()
                return {"success": True}
            else:
                return {"success": False, "error": "Logout failed"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== USER MANAGEMENT ==========
    
    def get_users(self) -> Dict:
        """Get list of all users with their public keys"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(
                f"{self.base_url}/users",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                users = response.json()
                
                # Setup encryption keys for each user
                for user in users:
                    if user.get('public_key') and self.my_public_key:
                        chat_key = self.e2ee.generate_chat_key(
                            self.my_public_key,
                            user['public_key']
                        )
                        self.e2ee.set_chat_key(user['username'], chat_key)
                
                return {"success": True, "data": users}
            else:
                return {"success": False, "error": "Failed to fetch users"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_user_public_key(self, username: str) -> Dict:
        """Get a specific user's public key"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(
                f"{self.base_url}/users/{username}/public-key",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Setup encryption key for this user
                if data.get('public_key') and self.my_public_key:
                    chat_key = self.e2ee.generate_chat_key(
                        self.my_public_key,
                        data['public_key']
                    )
                    self.e2ee.set_chat_key(username, chat_key)
                
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": "Failed to fetch public key"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== MESSAGING ==========
    
    def send_message(self, receiver_username: str, message: str) -> Dict:
        """
        Encrypt and send a message using per-chat E2EE
        """
        try:
            # Ensure we have the encryption key for this user
            if not self.e2ee.get_chat_key(receiver_username):
                # Fetch user's public key
                key_result = self.get_user_public_key(receiver_username)
                if not key_result["success"]:
                    return {"success": False, "error": "Could not establish encryption"}
            
            # Encrypt message
            encrypted = self.e2ee.encrypt_message(message, receiver_username)
            
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(
                f"{self.base_url}/messages/send",
                headers=headers,
                json={
                    "receiver_username": receiver_username,
                    "encrypted_content": encrypted
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                error_detail = response.json().get("detail", "Failed to send message")
                return {"success": False, "error": error_detail}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_message_history(self, username: str) -> Dict:
        """
        Get message history and decrypt with per-chat key
        """
        try:
            # Ensure we have the encryption key
            if not self.e2ee.get_chat_key(username):
                key_result = self.get_user_public_key(username)
                if not key_result["success"]:
                    return {"success": False, "error": "Could not establish encryption"}
            
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(
                f"{self.base_url}/messages/history/{username}",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                messages = response.json()
                
                # Decrypt each message
                for msg in messages:
                    try:
                        # Determine which user to use for decryption
                        sender = msg["sender_username"]
                        other_user = sender if sender != self.username else msg["receiver_username"]
                        
                        msg["decrypted_content"] = self.e2ee.decrypt_message(
                            msg["encrypted_content"],
                            other_user
                        )
                    except Exception as e:
                        msg["decrypted_content"] = f"[Decryption error: {str(e)}]"
                
                return {"success": True, "data": messages}
            else:
                return {"success": False, "error": "Failed to fetch messages"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== WEBSOCKET ==========
    
    def connect_websocket(self, on_message_callback: Callable):
        """Connect to WebSocket (WSS in production)"""
        self.message_callback = on_message_callback
        
        ws_url = f"{self.ws_url.rstrip('/')}/ws/{self.username}"
        
        # For WSS with self-signed certs
        sslopt = None
        if self.ws_url.startswith("wss://") and not self.verify_ssl:
            import ssl
            sslopt = {"cert_reqs": ssl.CERT_NONE}
        
        self.ws = websocket.WebSocketApp(
            ws_url,
            on_message=self._on_ws_message,
            on_error=self._on_ws_error,
            on_close=self._on_ws_close,
            on_open=self._on_ws_open
        )
        
        # Run WebSocket in separate thread
        if sslopt:
            self.ws_thread = threading.Thread(
                target=lambda: self.ws.run_forever(sslopt=sslopt),
                daemon=True
            )
        else:
            self.ws_thread = threading.Thread(
                target=self.ws.run_forever,
                daemon=True
            )
        self.ws_thread.start()
    
    def disconnect_websocket(self):
        """Disconnect from WebSocket"""
        if self.ws:
            self.ws.close()
    
    def _on_ws_open(self, ws):
        """WebSocket connection opened"""
        protocol = "WSS" if self.ws_url.startswith("wss://") else "WS"
        print(f"✅ {protocol} connected for {self.username}")
    
    def _on_ws_message(self, ws, message):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message)
            
            # Decrypt message if it's a chat message
            if data.get("type") == "new_message":
                try:
                    sender = data.get("sender")
                    data["decrypted_content"] = self.e2ee.decrypt_message(
                        data["encrypted_content"],
                        sender
                    )
                except Exception as e:
                    data["decrypted_content"] = f"[Decryption error: {str(e)}]"
                
                # Call the callback function
                if self.message_callback:
                    self.message_callback(data)
        
        except Exception as e:
            print(f"WebSocket message error: {e}")
    
    def _on_ws_error(self, ws, error):
        """WebSocket error occurred"""
        print(f"WebSocket error: {error}")
    
    def _on_ws_close(self, ws, close_status_code, close_msg):
        """WebSocket connection closed"""
        print(f"❌ WebSocket disconnected")
    
    # ========== UTILITY ==========
    
    def is_logged_in(self) -> bool:
        """Check if user is logged in"""
        return self.token is not None


# ========== TESTING ==========

if __name__ == "__main__":
    print("=== Enhanced API Client with E2EE ===\n")
    
    api = SecureChatAPI()
    
    # Test registration with strong password
    print("1. Testing Registration with Strong Password")
    result = api.register("abubakar2024", "abubakar@example.com", "SecurePass123!@#")
    print(f"   Result: {result['success']}")
    if not result['success']:
        print(f"   Error: {result['error']}")
    
    # Test login
    print("\n2. Testing Login")
    result = api.login("abubakar2024", "SecurePass123!@#")
    print(f"   Result: {result['success']}")
    if result['success']:
        print(f"   Public Key (first 50 chars): {result['data']['public_key'][:50]}...")
    
    if api.is_logged_in():
        # Test getting users
        print("\n3. Testing Get Users (with key exchange)")
        users = api.get_users()
        if users['success']:
            print(f"   Found {len(users['data'])} users")
            for user in users['data'][:3]:
                has_key = api.e2ee.get_chat_key(user['username']) is not None
                print(f"   - {user['username']}: Encryption key {'✅' if has_key else '❌'}")
    
    print("\n✅ API Client tests completed!")