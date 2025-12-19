"""
Complete API Client with PERSISTENT DH keys
Private keys are stored securely and reused across sessions
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
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64

from key_storage import KeyStorage


class DHKeyExchange:
    """CLIENT-SIDE DH key exchange with persistence support"""
    
    def __init__(self, dh_parameters, private_key=None):
        if private_key:
            self.private_key = private_key
            self.public_key = private_key.public_key()
            print("🔑 Loaded existing keypair")
        else:
            self.private_key = dh_parameters.generate_private_key()
            self.public_key = self.private_key.public_key()
            print("🔑 Generated new keypair")
    
    def get_public_key_bytes(self) -> str:
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    def get_private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @staticmethod
    def load_private_key_from_pem(pem_data: bytes, dh_parameters):
        private_key = load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend()
        )
        return DHKeyExchange(dh_parameters, private_key=private_key)
    
    def compute_shared_secret(self, peer_public_key_str: str) -> bytes:
        peer_public_bytes = base64.b64decode(peer_public_key_str)
        peer_public_key = serialization.load_pem_public_key(
            peer_public_bytes,
            backend=default_backend()
        )
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret
    
    def derive_encryption_key(self, shared_secret: bytes, salt: bytes) -> str:
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
        users = sorted([user1, user2])
        chat_id = f"{users[0]}:{users[1]}"
        return chat_id.encode('utf-8')


class E2EEManager:
    """Manages per-chat encryption using TRUE DH"""
    
    def __init__(self, my_dh: DHKeyExchange, my_username: str):
        self.my_dh = my_dh
        self.my_username = my_username
        self.chat_keys: Dict[str, str] = {}
        self.peer_public_keys: Dict[str, str] = {}
    
    def setup_chat_key(self, peer_username: str, peer_public_key: str):
        self.peer_public_keys[peer_username] = peer_public_key
        shared_secret = self.my_dh.compute_shared_secret(peer_public_key)
        chat_salt = DHKeyExchange.create_chat_salt(self.my_username, peer_username)
        encryption_key = self.my_dh.derive_encryption_key(shared_secret, chat_salt)
        self.chat_keys[peer_username] = encryption_key
    
    def get_chat_key(self, username: str) -> Optional[str]:
        return self.chat_keys.get(username)
    
    def encrypt_message(self, message: str, username: str) -> str:
        key = self.get_chat_key(username)
        if not key:
            raise ValueError(f"No encryption key for {username}")
        fernet = Fernet(key.encode())
        encrypted = fernet.encrypt(message.encode())
        return encrypted.decode()
    
    def decrypt_message(self, encrypted: str, username: str) -> str:
        key = self.get_chat_key(username)
        if not key:
            raise ValueError(f"No encryption key for {username}")
        fernet = Fernet(key.encode())
        decrypted = fernet.decrypt(encrypted.encode())
        return decrypted.decode()


class SecureChatAPI:
    """API client with PERSISTENT E2EE"""
    
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
        
        self.dh_parameters = None
        self.my_dh: Optional[DHKeyExchange] = None
        self.my_public_key: Optional[str] = None
        self.e2ee: Optional[E2EEManager] = None
        self.key_storage = KeyStorage()
        
        self.ws: Optional[websocket.WebSocketApp] = None
        self.ws_thread: Optional[threading.Thread] = None
        self.message_callback: Optional[Callable] = None
        self.verify_ssl = False
        
        self._fetch_dh_parameters()
    
    def _fetch_dh_parameters(self):
        try:
            print("🔍 Fetching DH parameters from server...")
            response = requests.get(f"{self.base_url}/dh-parameters", verify=self.verify_ssl)
            if response.status_code == 200:
                params_b64 = response.json()["parameters"]
                params_bytes = base64.b64decode(params_b64)
                self.dh_parameters = serialization.load_pem_parameters(
                    params_bytes,
                    backend=default_backend()
                )
                print("✅ DH parameters received from server")
            else:
                print(f"⚠️  Server returned {response.status_code}")
        except Exception as e:
            print(f"⚠️  Could not fetch DH parameters: {e}")
            print("📝 Generating local DH parameters as fallback...")
            self.dh_parameters = dh.generate_parameters(
                generator=2, key_size=2048, backend=default_backend()
            )
    
    def _generate_keypair(self):
        if not self.dh_parameters:
            raise ValueError("DH parameters not available")
        print("🔑 Generating NEW client-side keypair...")
        self.my_dh = DHKeyExchange(self.dh_parameters)
        self.my_public_key = self.my_dh.get_public_key_bytes()
        print(f"✅ New keypair generated")
    
    def register(self, username: str, email: str, password: str) -> Dict:
        """Register with persistent key storage"""
        print(f"\n📝 Registering user: {username}")
        
        self._generate_keypair()
        
        private_key_pem = self.my_dh.get_private_key_pem()
        if not self.key_storage.save_private_key(username, password, private_key_pem):
            print("⚠️  Warning: Could not save private key locally")
        else:
            print("✅ Private key saved securely")
        
        try:
            response = requests.post(
                f"{self.base_url}/register",
                json={
                    "username": username,
                    "email": email,
                    "password": password,
                    "public_key": self.my_public_key
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 201:
                print(f"✅ Registration successful for {username}")
                return {"success": True, "data": response.json()}
            else:
                error_detail = response.json().get("detail", "Registration failed")
                print(f"❌ Registration failed: {error_detail}")
                return {"success": False, "error": error_detail}
        except Exception as e:
            print(f"❌ Registration error: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def login(self, username: str, password: str) -> Dict:
        """Login with persistent key loading"""
        print(f"\n🔐 Logging in as: {username}")
        
        try:
            response = requests.post(
                f"{self.base_url}/login",
                data={"username": username, "password": password},
                verify=self.verify_ssl
            )
            
            print(f"🔍 Login response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                self.username = data["username"]
                self.user_id = data["user_id"]
                
                print(f"✅ Login successful for {self.username}")
                
                # Try to load existing private key
                if self.key_storage.has_stored_key(username):
                    print(f"🔑 Found stored private key, loading...")
                    private_key_pem = self.key_storage.load_private_key(username, password)
                    
                    if private_key_pem:
                        self.my_dh = DHKeyExchange.load_private_key_from_pem(
                            private_key_pem,
                            self.dh_parameters
                        )
                        self.my_public_key = self.my_dh.get_public_key_bytes()
                        print(f"✅ Loaded persistent keypair - old messages readable!")
                    else:
                        print(f"⚠️  Failed to decrypt stored key")
                        print(f"   Generating new keypair...")
                        self._generate_keypair()
                        private_key_pem = self.my_dh.get_private_key_pem()
                        self.key_storage.save_private_key(username, password, private_key_pem)
                else:
                    print(f"🔑 No stored key found, generating new keypair...")
                    self._generate_keypair()
                    private_key_pem = self.my_dh.get_private_key_pem()
                    if self.key_storage.save_private_key(username, password, private_key_pem):
                        print("✅ New keypair saved for future sessions")
                
                self._update_public_key()
                self.e2ee = E2EEManager(self.my_dh, self.username)
                print(f"✅ E2EE manager initialized")
                
                return {"success": True, "data": data}
            else:
                error_detail = response.json().get("detail", "Login failed")
                print(f"❌ Login failed: {error_detail}")
                return {"success": False, "error": error_detail}
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def _update_public_key(self) -> bool:
        try:
            print("🔄 Updating public key on server...")
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.put(
                f"{self.base_url}/users/me/public-key",
                headers=headers,
                json={"public_key": self.my_public_key},
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                print(f"✅ Public key updated on server")
                return True
            else:
                print(f"⚠️  Public key update failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"⚠️  Could not update public key: {e}")
            return False
    
    def logout(self) -> Dict:
        print(f"\n👋 Logging out: {self.username}")
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(
                f"{self.base_url}/logout",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                self.disconnect_websocket()
                print("✅ Logout successful")
                return {"success": True}
            else:
                print(f"⚠️  Logout failed: {response.status_code}")
                return {"success": False, "error": "Logout failed"}
        except Exception as e:
            print(f"❌ Logout error: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def get_users(self) -> Dict:
        try:
            print(f"\n📋 Fetching users list...")
            
            if not self.token:
                return {"success": False, "error": "Not authenticated"}
            
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(
                f"{self.base_url}/users",
                headers=headers,
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                users = response.json()
                print(f"✅ Received {len(users)} users")
                
                for user in users:
                    peer_public_key = user.get('public_key')
                    if peer_public_key:
                        try:
                            self.e2ee.setup_chat_key(user['username'], peer_public_key)
                            print(f"   🔑 Key exchange with {user['username']}")
                        except Exception as e:
                            print(f"   ⚠️  Key exchange failed: {e}")
                
                return {"success": True, "data": users}
            else:
                error_msg = f"Server returned {response.status_code}"
                return {"success": False, "error": error_msg}
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def get_user_public_key(self, username: str) -> Dict:
        print(f"\n🔑 Fetching public key for: {username}")
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
                    self.e2ee.setup_chat_key(username, peer_public_key)
                    print(f"✅ Key exchange completed")
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": "Failed to fetch public key"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def send_message(self, receiver_username: str, message: str) -> Dict:
        print(f"\n📤 Sending message to: {receiver_username}")
        try:
            if not self.e2ee.get_chat_key(receiver_username):
                key_result = self.get_user_public_key(receiver_username)
                if not key_result["success"]:
                    return {"success": False, "error": "Could not establish encryption"}
            
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
                print(f"   ✅ Message sent")
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to send"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_message_history(self, username: str) -> Dict:
        print(f"\n📜 Fetching message history with: {username}")
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
                print(f"   ✅ Received {len(messages)} messages")
                
                decrypted_count = 0
                failed_count = 0
                
                for msg in messages:
                    try:
                        sender = msg["sender_username"]
                        other_user = sender if sender != self.username else msg["receiver_username"]
                        msg["decrypted_content"] = self.e2ee.decrypt_message(
                            msg["encrypted_content"],
                            other_user
                        )
                        decrypted_count += 1
                    except Exception as e:
                        failed_count += 1
                        error_type = type(e).__name__
                        if "InvalidToken" in error_type or "InvalidSignature" in error_type:
                            msg["decrypted_content"] = "🔒 [Old message - key changed]"
                        else:
                            msg["decrypted_content"] = f"❌ [Decryption failed]"
                
                print(f"   📊 {decrypted_count} success, {failed_count} failed")
                return {"success": True, "data": messages}
            else:
                return {"success": False, "error": "Failed to fetch messages"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def connect_websocket(self, on_message_callback: Callable):
        print(f"\n🔌 Connecting to WebSocket...")
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
        print(f"✅ WebSocket connected")
    
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
                    data["decrypted_content"] = f"[Decryption error]"
                
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
    print("=== E2EE API Client with Persistent Keys ===")