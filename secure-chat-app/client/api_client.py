"""
API Client for Secure Chat Application
Handles HTTP requests and WebSocket connections to the backend
FIXED VERSION: Uses shared encryption key so users can decrypt each other's messages
"""
import requests
import json
import websocket
import threading
from typing import Optional, Callable, Dict, List
from cryptography.fernet import Fernet


class SecureChatAPI:
    """Handles all API communication with the backend"""
    
    # Shared encryption key for all users (in production, use proper key exchange)
    SHARED_ENCRYPTION_KEY = "xQd8F4-qJ_mYHNZ9R3vW8uT5pK2nL7bA6cE1zX0wI9M="  # Fixed key for demo
    
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.token: Optional[str] = None
        self.username: Optional[str] = None
        self.user_id: Optional[int] = None
        self.encryption_key: str = self.SHARED_ENCRYPTION_KEY  # Use shared key
        self.ws: Optional[websocket.WebSocketApp] = None
        self.ws_thread: Optional[threading.Thread] = None
        self.message_callback: Optional[Callable] = None
        
    # ========== AUTHENTICATION ==========
    
    def register(self, username: str, email: str, password: str) -> Dict:
        """
        Register a new user
        
        Args:
            username: Username for new account
            email: Email address
            password: Password (will be hashed on server)
            
        Returns:
            Dict with user info or error
        """
        try:
            response = requests.post(
                f"{self.base_url}/register",
                json={
                    "username": username,
                    "email": email,
                    "password": password
                }
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
        Login and get JWT token
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Dict with token and user info or error
        """
        try:
            response = requests.post(
                f"{self.base_url}/login",
                data={
                    "username": username,
                    "password": password
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                self.username = data["username"]
                self.user_id = data["user_id"]
                
                # Use shared encryption key (all users can decrypt each other's messages)
                self.encryption_key = self.SHARED_ENCRYPTION_KEY
                
                return {"success": True, "data": data}
            else:
                error_detail = response.json().get("detail", "Login failed")
                return {"success": False, "error": error_detail}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== USER MANAGEMENT ==========
    
    def get_users(self) -> Dict:
        """Get list of all users (except current user)"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{self.base_url}/users", headers=headers)
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to fetch users"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== MESSAGING ==========
    
    def send_message(self, receiver_username: str, message: str) -> Dict:
        """
        Encrypt and send a message
        
        Args:
            receiver_username: Username of recipient
            message: Plain text message
            
        Returns:
            Dict with status
        """
        try:
            # Encrypt message
            encrypted = self._encrypt_message(message)
            
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(
                f"{self.base_url}/messages/send",
                headers=headers,
                json={
                    "receiver_username": receiver_username,
                    "encrypted_content": encrypted
                }
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
        Get message history with a user and decrypt messages
        
        Args:
            username: Other user's username
            
        Returns:
            Dict with decrypted messages
        """
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(
                f"{self.base_url}/messages/history/{username}",
                headers=headers
            )
            
            if response.status_code == 200:
                messages = response.json()
                
                # Decrypt each message
                for msg in messages:
                    try:
                        msg["decrypted_content"] = self._decrypt_message(
                            msg["encrypted_content"]
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
        """
        Connect to WebSocket for real-time messages
        
        Args:
            on_message_callback: Function to call when message received
        """
        self.message_callback = on_message_callback
        
        ws_url = f"ws://127.0.0.1:8000/ws/{self.username}"
        
        self.ws = websocket.WebSocketApp(
            ws_url,
            on_message=self._on_ws_message,
            on_error=self._on_ws_error,
            on_close=self._on_ws_close,
            on_open=self._on_ws_open
        )
        
        # Run WebSocket in separate thread
        self.ws_thread = threading.Thread(target=self.ws.run_forever, daemon=True)
        self.ws_thread.start()
    
    def disconnect_websocket(self):
        """Disconnect from WebSocket"""
        if self.ws:
            self.ws.close()
    
    def _on_ws_open(self, ws):
        """WebSocket connection opened"""
        print(f"✅ WebSocket connected for {self.username}")
    
    def _on_ws_message(self, ws, message):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message)
            
            # Decrypt message if it's a chat message
            if data.get("type") == "new_message":
                try:
                    data["decrypted_content"] = self._decrypt_message(
                        data["encrypted_content"]
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
    
    # ========== ENCRYPTION HELPERS ==========
    
    def _encrypt_message(self, message: str) -> str:
        """Encrypt a message using Fernet"""
        if not self.encryption_key:
            raise ValueError("No encryption key available")
        
        fernet = Fernet(self.encryption_key.encode())
        encrypted = fernet.encrypt(message.encode())
        return encrypted.decode()
    
    def _decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt a message using Fernet"""
        if not self.encryption_key:
            raise ValueError("No encryption key available")
        
        fernet = Fernet(self.encryption_key.encode())
        decrypted = fernet.decrypt(encrypted_message.encode())
        return decrypted.decode()
    
    # ========== UTILITY ==========
    
    def is_logged_in(self) -> bool:
        """Check if user is logged in"""
        return self.token is not None


# ========== TESTING ==========

if __name__ == "__main__":
    # Test the API client
    api = SecureChatAPI()
    
    print("=== Testing API Client ===")
    
    # Test registration
    print("\n1. Testing Registration...")
    result = api.register("testuser", "test@example.com", "password123")
    print(f"Result: {result}")
    
    # Test login
    print("\n2. Testing Login...")
    result = api.login("testuser", "password123")
    print(f"Result: {result}")
    
    if result["success"]:
        # Test getting users
        print("\n3. Testing Get Users...")
        users = api.get_users()
        print(f"Users: {users}")
        
        # Test encryption
        print("\n4. Testing Encryption...")
        message = "Hello, this is a test message!"
        encrypted = api._encrypt_message(message)
        print(f"Original: {message}")
        print(f"Encrypted: {encrypted}")
        decrypted = api._decrypt_message(encrypted)
        print(f"Decrypted: {decrypted}")
    
    print("\n✅ API Client tests completed!")