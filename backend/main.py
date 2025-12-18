"""
Enhanced FastAPI application with WSS support and public key exchange
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict
from pydantic import BaseModel, EmailStr
from datetime import datetime
import json
import ssl
import os

from database import get_db, User, Message, init_db
from security import (
    hash_password, 
    verify_password, 
    create_access_token, 
    verify_token,
    MessageEncryption,
    DHKeyExchange,
    PasswordPolicy
)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    print("🚀 Server started successfully!")
    print("🔐 E2EE enabled with Diffie-Hellman key exchange")
    yield
    # Shutdown
    print("👋 Server shutting down...")

# Initialize FastAPI app
app = FastAPI(
    title="Secure Chat API with E2EE",
    description="End-to-end encrypted chat with DH key exchange and WSS",
    version="2.0.0",
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
        "message": "Secure Chat API with E2EE is running!",
        "version": "2.0.0",
        "features": [
            "Diffie-Hellman key exchange",
            "Per-chat encryption",
            "Strong password policy",
            "WSS support"
        ],
        "status": "healthy"
    }


@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user with password policy enforcement"""
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
    
    # Create new user
    hashed_pwd = hash_password(user_data.password)
    
    # Generate DH key pair for user
    dh = DHKeyExchange()
    public_key = dh.get_public_key_bytes()
    
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd,
        public_key=public_key
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login endpoint - returns JWT access token"""
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
        "public_key": user.public_key
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
    """List all users except current user with their public keys"""
    users = db.query(User).filter(User.id != current_user.id).all()
    return users


@app.get("/users/{username}/public-key")
async def get_user_public_key(
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a specific user's public key for E2EE"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {
        "username": user.username,
        "public_key": user.public_key
    }


@app.put("/users/me/public-key")
async def update_public_key(
    key_data: PublicKeyUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user's public key (for key rotation)"""
    current_user.public_key = key_data.public_key
    db.commit()
    
    return {"message": "Public key updated successfully"}


@app.post("/messages/send")
async def send_message(
    message_data: MessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send an encrypted message"""
    # Find receiver
    receiver = db.query(User).filter(User.username == message_data.receiver_username).first()
    if not receiver:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Receiver not found"
        )
    
    # Create message
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
            "timestamp": new_message.timestamp.isoformat()
        }),
        receiver.username
    )
    
    return {"status": "sent", "message_id": new_message.id}


@app.get("/messages/history/{username}")
async def get_message_history(
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get message history with a specific user"""
    other_user = db.query(User).filter(User.username == username).first()
    if not other_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get all messages between users
    messages = db.query(Message).filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user.id)) |
        ((Message.sender_id == other_user.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Format response
    result = []
    for msg in messages:
        result.append({
            "id": msg.id,
            "sender_username": msg.sender.username,
            "receiver_username": msg.receiver.username,
            "encrypted_content": msg.encrypted_content,
            "timestamp": msg.timestamp.isoformat(),
            "is_read": msg.is_read
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
        """Broadcast message to all connected users"""
        for connection in self.active_connections.values():
            await connection.send_text(message)


connection_manager = ConnectionManager()


@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """
    WebSocket endpoint for real-time messaging
    In production, use WSS with SSL certificates
    """
    await connection_manager.connect(websocket, username)
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Handle ping
            if message_data.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            
            # Forward message to recipient
            elif message_data.get("type") == "message":
                recipient = message_data.get("recipient")
                if recipient:
                    await connection_manager.send_personal_message(data, recipient)
    
    except WebSocketDisconnect:
        connection_manager.disconnect(username)
    except Exception as e:
        print(f"WebSocket error: {e}")
        connection_manager.disconnect(username)


# ========== RUN SERVER ==========

if __name__ == "__main__":
    import uvicorn
    
    # For WSS in production, configure SSL
    # ssl_keyfile and ssl_certfile should point to your certificates
    # Generate self-signed for testing:
    # openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
    
    USE_SSL = os.getenv("USE_SSL", "false").lower() == "true"
    
    if USE_SSL:
        ssl_keyfile = os.getenv("SSL_KEYFILE", "./key.pem")
        ssl_certfile = os.getenv("SSL_CERTFILE", "./cert.pem")
        
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile
        )
    else:
        print("⚠️  Running without SSL (not recommended for production)")
        print("💡 Enable SSL by setting USE_SSL=true and providing certificates")
        uvicorn.run(
            "main:app",
            host="127.0.0.1",
            port=8000,
            reload=True
        )