"""
Fixed API Client with TRUE Diffie-Hellman key exchange
Private keys NEVER leave the client device
"""
import requests
import json
import websocket
import threading
from typing import Optional, Callable, Dict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import base64


class DHKeyExchange:
    """
    CLIENT-SIDE DH key exchange
    Private key NEVER leaves this class
    """
    
    def __init__(self, dh_parameters):
        """Generate keypair using shared DH parameters"""
        self.private_key = dh_parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self) -> str:
        """Get public key as base64 string for server"""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    def compute_shared_secret(self, peer_public_key_str: str) -> bytes:
        """
        Compute shared secret using OUR private key and THEIR public key
        This is the core of TRUE DH - happens CLIENT-SIDE ONLY
        """
        peer_public_bytes = base64.b64decode(peer_public_key_str)
        peer_public_key = serialization.load_pem_public_key(
            peer_public_bytes,
            backend=default_backend()
        )
        
        # THE MAGIC: Use our private key with their public key
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret
    
    def derive_encryption_key(self, shared_secret: bytes, salt: bytes) -> str:
        """Derive Fernet key from shared secret"""
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
    def create_chat_salt(user1: str, user2: str) -> bytes:
        """Create deterministic salt for a chat"""
        users = sorted([user1, user2])
        chat_id = f"{users[0]}:{users[1]}"
        return chat_id.encode('utf-8')


class E2EEManager:
    """
    Manages per-chat encryption using TRUE DH
    Stores derived keys (not private keys!)
    """
    
    def __init__(self, my_dh: DHKeyExchange, my_username: str):
        self.my_dh = my_dh  # Our DH instance (contains private key)
        self.my_username = my_username
        self.chat_keys: Dict[str, str] = {}  # username -> derived_fernet_key
        self.peer_public_keys: Dict[str, str] = {}  # username -> their_public_key
    
    def setup_chat_key(self, peer_username: str, peer_public_key: str):
        """
        Setup encryption key for a chat using TRUE DH
        Computes: shared_secret = my_private.exchange(their_public)
        """
        # Store peer's public key
        self.peer_public_keys[peer_username] = peer_public_key
        
        # Compute shared secret using OUR private key
        shared_secret = self.my_dh.compute_shared_secret(peer_public_key)
        
        # Derive encryption key with chat-specific salt
        chat_salt = DHKeyExchange.create_chat_salt(self.my_username, peer_username)
        encryption_key = self.my_dh.derive_encryption_key(shared_secret, chat_salt)
        
        # Store the derived key
        self.chat_keys[peer_username] = encryption_key
    
    def get_chat_key(self, username: str) -> Optional[str]:
        """Get encryption key for a specific chat"""
        return self.chat_keys.get(username)
    
    def encrypt_message(self, message: str, username: str) -> str:
        """Encrypt message for specific user"""
        key = self.get_chat_key(username)
        if not key:
            raise ValueError(f"No encryption key for {username}. Call setup_chat_key first.")
        
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
    """Enhanced API client with TRUE E2EE using Diffie-Hellman"""
    
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
        
        # DH components (private key stays here!)
        self.dh_parameters = None  # Shared parameters from server
        self.my_dh: Optional[DHKeyExchange] = None  # Our keypair
        self.my_public_key: Optional[str] = None  # Our public key
        
        # E2EE manager
        self.e2ee: Optional[E2EEManager] = None
        
        self.ws: Optional[websocket.WebSocketApp] = None
        self.ws_thread: Optional[threading.Thread] = None
        self.message_callback: Optional[Callable] = None
        
        self.verify_ssl = False
        
        # Get DH parameters from server
        self._fetch_dh_parameters()
    
    def _fetch_dh_parameters(self):
        """
        Fetch shared DH parameters from server
        These are public and shared by all users
        """
        try:
            response = requests.get(f"{self.base_url}/dh-parameters", verify=self.verify_ssl)
            if response.status_code == 200:
                params_b64 = response.json()["parameters"]
                params_bytes = base64.b64decode(params_b64)
                self.dh_parameters = serialization.load_pem_parameters(
                    params_bytes,
                    backend=default_backend()
                )
                print("✅ DH parameters received from server")
        except Exception as e:
            print(f"⚠️  Could not fetch DH parameters: {e}")
            # Fallback: generate local parameters (not ideal for production)
            self.dh_parameters = dh.generate_parameters(
                generator=2, key_size=2048, backend=default_backend()
            )
    
    def _generate_keypair(self):
        """
        Generate client-side DH keypair
        PRIVATE KEY STAYS ON CLIENT - NEVER SENT TO SERVER
        """
        if not self.dh_parameters:
            raise ValueError("DH parameters not available")
        
        self.my_dh = DHKeyExchange(self.dh_parameters)
        self.my_public_key = self.my_dh.get_public_key_bytes()
        print("✅ Client keypair generated (private key stays local)")
    
    # ========== AUTHENTICATION ==========
    
    def register(self, username: str, email: str, password: str) -> Dict:
        """
        Register a new user
        Client generates keypair and sends ONLY public key
        """
        # Generate client-side keypair
        self._generate_keypair()
        
        try:
            response = requests.post(
                f"{self.base_url}/register",
                json={
                    "username": username,
                    "email": email,
                    "password": password,
                    "public_key": self.my_public_key  # Only public key sent!
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
        """
        Login and initialize E2EE manager
        If user doesn't have a keypair, generate one
        """
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
                
                # Get user's stored public key or generate new one
                stored_public_key = data.get("public_key")
                
                if not stored_public_key:
                    # User registered before DH - generate keypair now
                    self._generate_keypair()
                    # Update server with new public key
                    self._update_public_key()
                else:
                    # User has public key but we need to generate local keypair
                    # (we don't have their private key - it was never stored!)
                    self._generate_keypair()
                    # Update server with our new public key
                    self._update_public_key()
                
                # Initialize E2EE manager
                self.e2ee = E2EEManager(self.my_dh, self.username)
                
                return {"success": True, "data": data}
            else:
                error_detail = response.json().get("detail", "Login failed")
                return {"success": False, "error": error_detail}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _update_public_key(self):
        """Update our public key on server"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            requests.put(
                f"{self.base_url}/users/me/public-key",
                headers=headers,
                json={"public_key": self.my_public_key},
                verify=self.verify_ssl
            )
        except Exception as e:
            print(f"⚠️  Could not update public key: {e}")
    
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
        """
        Get list of all users with their public keys
        Setup encryption keys using TRUE DH
        """
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(
                f"{self.base_url}/users",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                users = response.json()
                
                # Setup encryption keys using TRUE DH
                for user in users:
                    peer_public_key = user.get('public_key')
                    if peer_public_key:
                        # TRUE DH: compute shared secret with our private key
                        self.e2ee.setup_chat_key(user['username'], peer_public_key)
                        print(f"🔑 DH key exchange completed with {user['username']}")
                
                return {"success": True, "data": users}
            else:
                return {"success": False, "error": "Failed to fetch users"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_user_public_key(self, username: str) -> Dict:
        """Get a specific user's public key and setup DH"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(
                f"{self.base_url}/users/{username}/public-key",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                peer_public_key = data.get('public_key')
                
                if peer_public_key:
                    # TRUE DH key exchange
                    self.e2ee.setup_chat_key(username, peer_public_key)
                    print(f"🔑 DH key exchange completed with {username}")
                
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": "Failed to fetch public key"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== MESSAGING ==========
    
    def send_message(self, receiver_username: str, message: str) -> Dict:
        """
        Encrypt and send a message using TRUE DH-derived key
        """
        try:
            # Ensure we have encryption key
            if not self.e2ee.get_chat_key(receiver_username):
                key_result = self.get_user_public_key(receiver_username)
                if not key_result["success"]:
                    return {"success": False, "error": "Could not establish encryption"}
            
            # Encrypt with TRUE DH-derived key
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
        """Get and decrypt message history"""
        try:
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
        """Connect to WebSocket"""
        self.message_callback = on_message_callback
        
        ws_url = f"{self.ws_url.rstrip('/')}/ws/{self.username}"
        
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
        if self.ws:
            self.ws.close()
    
    def _on_ws_open(self, ws):
        protocol = "WSS" if self.ws_url.startswith("wss://") else "WS"
        print(f"✅ {protocol} connected for {self.username}")
    
    def _on_ws_message(self, ws, message):
        try:
            data = json.loads(message)
            
            if data.get("type") == "new_message":
                try:
                    sender = data.get("sender")
                    data["decrypted_content"] = self.e2ee.decrypt_message(
                        data["encrypted_content"],
                        sender
                    )
                except Exception as e:
                    data["decrypted_content"] = f"[Decryption error: {str(e)}]"
                
                if self.message_callback:
                    self.message_callback(data)
        
        except Exception as e:
            print(f"WebSocket message error: {e}")
    
    def _on_ws_error(self, ws, error):
        print(f"WebSocket error: {error}")
    
    def _on_ws_close(self, ws, close_status_code, close_msg):
        print(f"❌ WebSocket disconnected")
    
    def is_logged_in(self) -> bool:
        return self.token is not None


if __name__ == "__main__":
    print("=== TRUE E2EE API Client ===\n")
    print("🔐 Private keys stay on client device")
    print("📤 Only public keys are sent to server\n")