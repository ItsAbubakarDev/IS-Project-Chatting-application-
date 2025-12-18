"""
Enhanced Database models with public key storage for E2EE
"""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./chat.db")

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


class User(Base):
    """User table with public key for E2EE"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    public_key = Column(Text, nullable=True)  # DH public key for E2EE
    created_at = Column(DateTime, default=datetime.utcnow)
    last_active = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_online = Column(Boolean, default=False)
    
    # Relationships
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"


class Message(Base):
    """Message table for encrypted chat messages"""
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_read = Column(Boolean, default=False)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")
    
    def __repr__(self):
        return f"<Message(from={self.sender_id}, to={self.receiver_id}, time={self.timestamp})>"


def get_db():
    """
    Dependency function to get database session
    Usage: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables in the database"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")


def drop_db():
    """Drop all tables - USE CAREFULLY!"""
    Base.metadata.drop_all(bind=engine)
    print("⚠️  All database tables dropped!")


if __name__ == "__main__":
    init_db()