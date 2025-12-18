"""
Fixed FastAPI application for TRUE Diffie-Hellman E2EE
Server only stores/exchanges public keys - NEVER private keys
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict
from pydantic import BaseModel, EmailStr
from datetime import datetime
import json
import os

from database import get_db, User, Message, init_db
from security import (
    hash_password, 
    verify_password, 
    create_access_token, 
    verify_token,
    PasswordPolicy,
    serialize_dh_parameters
)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    print("🚀 Server started successfully!")
    print("🔐 TRUE E2EE with Diffie-Hellman key exchange")
    print("⚠️  Server NEVER stores private keys")
    yield
    # Shutdown
    print("👋 Server shutting down...")

# Initialize FastAPI app
app = FastAPI(
    title="Secure Chat API with TRUE E2EE",
    description="End-to-end encrypted chat with proper DH key exchange",
    version="3.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ========== PYDANTIC MODELS ==========

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    public_key: str  # Client sends their public key

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    public_key: str | None
    is_online: bool
    created_at: datetime
    
    model_config = {"from_attributes": True}

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    user_id: int
    public_key: str | None

class MessageSend(BaseModel):
    receiver_username: str
    encrypted_content: str

class PublicKeyUpdate(BaseModel):
    public_key: str


# ========== AUTHENTICATION ==========

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Get current authenticated user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    username = verify_token(token)
    if username is None:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    
    return user


# ========== REST API ENDPOINTS ==========

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Secure Chat API with TRUE E2EE is running!",
        "version": "3.0.0",
        "security": {
            "dh_key_exchange": "TRUE - Client generates private keys",
            "private_keys": "NEVER stored on server",
            "public_keys": "Stored and exchanged via server",
            "encryption": "Client-side only"
        },
        "status": "healthy"
    }


@app.get("/dh-parameters")
async def get_dh_parameters():
    """
    Provide shared DH parameters to clients
    These are public and the same for all users
    """
    return {
        "parameters": serialize_dh_parameters(),
        "description": "2048-bit MODP Group 14 (RFC 3526)"
    }


@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user
    Client sends their PUBLIC key (generated client-side)
    Server NEVER receives or stores private keys
    """
    # Check if username exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Validate password strength
    is_valid, message = PasswordPolicy.validate(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    # Validate public key format
    if not user_data.public_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Public key is required"
        )
    
    # Create new user with client-provided public key
    hashed_pwd = hash_password(user_data.password)
    
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd,
        public_key=user_data.public_key  # Store ONLY public key
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    print(f"✅ Registered {user_data.username} with public key (private key never received)")
    
    return new_user


@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Login endpoint
    Returns user's stored public key (NOT private key - we don't have it!)
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update online status
    user.is_online = True
    user.last_active = datetime.utcnow()
    db.commit()
    
    # Create access token
    access_token = create_access_token(data={"sub": user.username})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "user_id": user.id,
        "public_key": user.public_key  # Return their stored public key
    }


@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Logout and update online status"""
    current_user.is_online = False
    db.commit()
    return {"message": "Logged out successfully"}


@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current authenticated user's information"""
    return current_user


@app.get("/users", response_model=List[UserResponse])
async def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all users with their PUBLIC keys
    Clients will use these public keys for DH key exchange
    """
    users = db.query(User).filter(User.id != current_user.id).all()
    return users


@app.get("/users/{username}/public-key")
async def get_user_public_key(
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific user's PUBLIC key for DH key exchange
    This is safe to share - only the user has their private key
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {
        "username": user.username,
        "public_key": user.public_key,
        "note": "This is a PUBLIC key - safe to share. Private key stays on user's device."
    }


@app.put("/users/me/public-key")
async def update_public_key(
    key_data: PublicKeyUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update user's public key (for key rotation)
    Client generates new keypair and sends new public key
    """
    current_user.public_key = key_data.public_key
    db.commit()
    
    print(f"🔑 {current_user.username} rotated their public key")
    
    return {
        "message": "Public key updated successfully",
        "note": "Your private key should never leave your device"
    }


@app.post("/messages/send")
async def send_message(
    message_data: MessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Receive and store encrypted message
    Server CANNOT decrypt - only clients with private keys can
    """
    # Find receiver
    receiver = db.query(User).filter(User.username == message_data.receiver_username).first()
    if not receiver:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Receiver not found"
        )
    
    # Store encrypted message (server cannot decrypt it!)
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        encrypted_content=message_data.encrypted_content
    )
    
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    
    # Notify via WebSocket if receiver is connected
    await connection_manager.send_personal_message(
        json.dumps({
            "type": "new_message",
            "message_id": new_message.id,
            "sender": current_user.username,
            "encrypted_content": message_data.encrypted_content,
            "timestamp": new_message.timestamp.isoformat(),
            "note": "Server cannot read this - E2EE protected"
        }),
        receiver.username
    )
    
    return {
        "status": "sent",
        "message_id": new_message.id,
        "note": "Message is E2EE - server cannot decrypt"
    }


@app.get("/messages/history/{username}")
async def get_message_history(
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get encrypted message history
    Server returns encrypted messages - client must decrypt
    """
    other_user = db.query(User).filter(User.username == username).first()
    if not other_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get all encrypted messages
    messages = db.query(Message).filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user.id)) |
        ((Message.sender_id == other_user.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Return encrypted messages (client will decrypt)
    result = []
    for msg in messages:
        result.append({
            "id": msg.id,
            "sender_username": msg.sender.username,
            "receiver_username": msg.receiver.username,
            "encrypted_content": msg.encrypted_content,  # Still encrypted!
            "timestamp": msg.timestamp.isoformat(),
            "is_read": msg.is_read,
            "note": "Client-side decryption required"
        })
    
    return result


# ========== WEBSOCKET CONNECTION MANAGER ==========

class ConnectionManager:
    """Manages WebSocket connections for real-time messaging"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket
        print(f"✅ {username} connected via WebSocket. Total: {len(self.active_connections)}")
    
    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
            print(f"❌ {username} disconnected. Total: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, username: str):
        if username in self.active_connections:
            await self.active_connections[username].send_text(message)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)


connection_manager = ConnectionManager()


@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """
    WebSocket endpoint for real-time encrypted messaging
    Server forwards encrypted messages - cannot decrypt them
    """
    await connection_manager.connect(websocket, username)
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            if message_data.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            
            elif message_data.get("type") == "message":
                recipient = message_data.get("recipient")
                if recipient:
                    # Forward encrypted message (server cannot read it)
                    await connection_manager.send_personal_message(data, recipient)
    
    except WebSocketDisconnect:
        connection_manager.disconnect(username)
    except Exception as e:
        print(f"WebSocket error: {e}")
        connection_manager.disconnect(username)


# ========== ADMIN/DEBUG ENDPOINT ==========

@app.get("/admin/security-status")
async def security_status(current_user: User = Depends(get_current_user)):
    """
    Debug endpoint to verify TRUE E2EE implementation
    Shows that server cannot decrypt messages
    """
    return {
        "implementation": "TRUE Diffie-Hellman E2EE",
        "private_keys_on_server": "NONE - Generated client-side only",
        "public_keys_on_server": "YES - Used for key exchange",
        "server_can_decrypt": "NO - Requires private key which server doesn't have",
        "key_exchange": "Client-side DH: shared_secret = my_private.exchange(their_public)",
        "your_username": current_user.username,
        "your_public_key_stored": bool(current_user.public_key),
        "security_guarantee": "Even if server is compromised, past messages remain encrypted"
    }


# ========== RUN SERVER ==========

if __name__ == "__main__":
    import uvicorn
    
    USE_SSL = os.getenv("USE_SSL", "false").lower() == "true"
    
    if USE_SSL:
        ssl_keyfile = os.getenv("SSL_KEYFILE", "./key.pem")
        ssl_certfile = os.getenv("SSL_CERTFILE", "./cert.pem")
        
        print("🔒 Running with SSL/TLS (WSS)")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile
        )
    else:
        print("⚠️  Running without SSL (development only)")
        print("🔐 TRUE E2EE still active - encryption happens client-side")
        uvicorn.run(
            "main:app",
            host="127.0.0.1",
            port=8000,
            reload=True
        )