"""
Secure Chat Client Application
PyQt5 GUI with Login and Chat windows
"""
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget,
    QMessageBox, QSplitter, QFrame, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon
from datetime import datetime
from api_client import SecureChatAPI


# ========== LOGIN WINDOW ==========

class LoginWindow(QMainWindow):
    """Login and Registration Window"""
    
    def __init__(self):
        super().__init__()
        self.api = SecureChatAPI()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle("Secure Chat - Login")
        self.setGeometry(100, 100, 400, 500)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2c3e50;
            }
            QLabel {
                color: #ecf0f1;
                font-size: 14px;
            }
            QLineEdit {
                padding: 10px;
                border: 2px solid #34495e;
                border-radius: 5px;
                background-color: #ecf0f1;
                font-size: 13px;
            }
            QPushButton {
                padding: 10px;
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Title
        title = QLabel("🔒 Secure Chat")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel("End-to-End Encrypted Messaging")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #95a5a6; font-size: 12px;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(20)
        
        # Username
        layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        layout.addWidget(self.username_input)
        
        # Email (for registration)
        layout.addWidget(QLabel("Email:"))
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email (for registration)")
        layout.addWidget(self.email_input)
        
        # Password
        layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        
        # Login button
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)
        
        # Register button
        self.register_btn = QPushButton("Register")
        self.register_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        self.register_btn.clicked.connect(self.handle_register)
        layout.addWidget(self.register_btn)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        central_widget.setLayout(layout)
        
        # Connect Enter key to login
        self.password_input.returnPressed.connect(self.handle_login)
    
    def handle_login(self):
        """Handle login button click"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            self.status_label.setText("❌ Please enter username and password")
            return
        
        self.status_label.setText("🔄 Logging in...")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        
        # Attempt login
        result = self.api.login(username, password)
        
        if result["success"]:
            self.status_label.setText("✅ Login successful!")
            # Open chat window
            self.open_chat_window()
        else:
            self.status_label.setText(f"❌ {result['error']}")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
    
    def handle_register(self):
        """Handle register button click"""
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not email or not password:
            self.status_label.setText("❌ Please fill all fields")
            return
        
        self.status_label.setText("🔄 Registering...")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        
        # Attempt registration
        result = self.api.register(username, email, password)
        
        if result["success"]:
            self.status_label.setText("✅ Registration successful! Please login.")
            self.email_input.clear()
            self.password_input.clear()
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
        else:
            self.status_label.setText(f"❌ {result['error']}")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
    
    def open_chat_window(self):
        """Open the chat window and close login window"""
        self.chat_window = ChatWindow(self.api)
        self.chat_window.show()
        self.close()


# ========== CHAT WINDOW ==========

class ChatWindow(QMainWindow):
    """Main chat window"""
    
    # Signal for receiving messages
    new_message_signal = pyqtSignal(dict)
    
    def __init__(self, api: SecureChatAPI):
        super().__init__()
        self.api = api
        self.current_chat_user = None
        self.users = []
        self.init_ui()
        self.load_users()
        self.connect_websocket()
        
        # Connect signal
        self.new_message_signal.connect(self.handle_incoming_message)
    
    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle(f"Secure Chat - {self.api.username}")
        self.setGeometry(100, 100, 1000, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ecf0f1;
            }
            QListWidget {
                background-color: #34495e;
                color: #ecf0f1;
                border: none;
                font-size: 14px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 10px;
                border-radius: 5px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background-color: #3498db;
            }
            QListWidget::item:hover {
                background-color: #2c3e50;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                padding: 10px;
                font-size: 13px;
            }
            QLineEdit {
                padding: 10px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 13px;
            }
            QPushButton {
                padding: 10px 20px;
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout()
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Left sidebar (users list)
        sidebar = QFrame()
        sidebar.setMaximumWidth(250)
        sidebar.setStyleSheet("background-color: #34495e;")
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        
        # User info
        user_label = QLabel(f"👤 {self.api.username}")
        user_label.setStyleSheet("color: #ecf0f1; font-size: 16px; font-weight: bold; padding: 10px;")
        sidebar_layout.addWidget(user_label)
        
        # Users list
        users_title = QLabel("Users")
        users_title.setStyleSheet("color: #95a5a6; font-size: 12px; padding: 5px;")
        sidebar_layout.addWidget(users_title)
        
        self.users_list = QListWidget()
        self.users_list.itemClicked.connect(self.select_user)
        sidebar_layout.addWidget(self.users_list)
        
        sidebar.setLayout(sidebar_layout)
        main_layout.addWidget(sidebar)
        
        # Right side (chat area)
        chat_container = QWidget()
        chat_layout = QVBoxLayout()
        chat_layout.setContentsMargins(20, 20, 20, 20)
        
        # Chat header
        self.chat_header = QLabel("Select a user to start chatting")
        self.chat_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50; padding: 10px;")
        chat_layout.addWidget(self.chat_header)
        
        # Messages display
        self.messages_display = QTextEdit()
        self.messages_display.setReadOnly(True)
        chat_layout.addWidget(self.messages_display)
        
        # Message input area
        input_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)
        
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)
        
        chat_layout.addLayout(input_layout)
        
        chat_container.setLayout(chat_layout)
        main_layout.addWidget(chat_container)
        
        central_widget.setLayout(main_layout)
    
    def load_users(self):
        """Load users from server"""
        result = self.api.get_users()
        
        if result["success"]:
            self.users = result["data"]
            self.users_list.clear()
            
            for user in self.users:
                self.users_list.addItem(f"👤 {user['username']}")
    
    def select_user(self, item):
        """Handle user selection"""
        username = item.text().replace("👤 ", "")
        self.current_chat_user = username
        self.chat_header.setText(f"💬 Chat with {username}")
        
        # Load message history
        self.load_message_history(username)
    
    def load_message_history(self, username: str):
        """Load chat history with a user"""
        result = self.api.get_message_history(username)
        
        if result["success"]:
            messages = result["data"]
            self.messages_display.clear()
            
            for msg in messages:
                self.display_message(
                    msg["sender_username"],
                    msg["decrypted_content"],
                    msg["timestamp"]
                )
    
    def send_message(self):
        """Send a message"""
        if not self.current_chat_user:
            QMessageBox.warning(self, "Warning", "Please select a user first!")
            return
        
        message_text = self.message_input.text().strip()
        if not message_text:
            return
        
        # Send message via API
        result = self.api.send_message(self.current_chat_user, message_text)
        
        if result["success"]:
            # Display sent message
            self.display_message(
                self.api.username,
                message_text,
                datetime.now().isoformat()
            )
            self.message_input.clear()
        else:
            QMessageBox.critical(self, "Error", f"Failed to send: {result['error']}")
    
    def display_message(self, sender: str, content: str, timestamp: str):
        """Display a message in the chat"""
        try:
            time_str = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime("%H:%M")
        except:
            time_str = datetime.now().strftime("%H:%M")
        
        is_me = (sender == self.api.username)
        
        if is_me:
            style = "color: #2980b9; font-weight: bold;"
            sender_display = "You"
        else:
            style = "color: #27ae60; font-weight: bold;"
            sender_display = sender
        
        html = f"""
        <div style="margin: 5px 0;">
            <span style="{style}">{sender_display}</span>
            <span style="color: #95a5a6; font-size: 11px;"> {time_str}</span><br>
            <span style="color: #2c3e50;">{content}</span>
        </div>
        """
        
        self.messages_display.append(html)
    
    def connect_websocket(self):
        """Connect to WebSocket for real-time messages"""
        self.api.connect_websocket(self.on_websocket_message)
    
    def on_websocket_message(self, data: dict):
        """Handle incoming WebSocket message"""
        # Emit signal to update GUI (thread-safe)
        self.new_message_signal.emit(data)
    
    def handle_incoming_message(self, data: dict):
        """Handle incoming message (runs in main thread)"""
        if data.get("type") == "new_message":
            sender = data.get("sender")
            content = data.get("decrypted_content", "[Failed to decrypt]")
            timestamp = data.get("timestamp")
            
            # If chatting with sender, display message
            if sender == self.current_chat_user:
                self.display_message(sender, content, timestamp)
            
            # Show notification
            QMessageBox.information(
                self,
                "New Message",
                f"New message from {sender}:\n{content[:50]}..."
            )
    
    def closeEvent(self, event):
        """Handle window close"""
        self.api.disconnect_websocket()
        event.accept()


# ========== MAIN APPLICATION ==========

def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show login window
    login_window = LoginWindow()
    login_window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()