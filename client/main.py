"""
Enhanced Secure Chat Client with E2EE - FIXED VERSION
Features: Per-chat encryption, strong password policy, online status
INCLUDES: Comprehensive debugging and UI fixes for user list display
"""
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget,
    QMessageBox, QFrame, QToolTip, QListWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor
from datetime import datetime
from api_client import SecureChatAPI
import requests


# ========== LOGIN WINDOW ==========

class LoginWindow(QMainWindow):
    """Enhanced Login window with password requirements"""
    
    def __init__(self, use_ssl: bool = False):
        super().__init__()
        self.api = SecureChatAPI(use_ssl=use_ssl)
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle("Secure Chat - Login")
        self.setGeometry(100, 100, 450, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QLabel {
                color: #eee;
                font-size: 14px;
            }
            QLineEdit {
                padding: 12px;
                border: 2px solid #16213e;
                border-radius: 8px;
                background-color: #0f3460;
                color: #eee;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 2px solid #e94560;
            }
            QPushButton {
                padding: 12px;
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c23b54;
            }
            QPushButton:pressed {
                background-color: #9e2f43;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Title
        title = QLabel("🔐 Secure Chat")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #e94560;")
        layout.addWidget(title)
        
        subtitle = QLabel("End-to-End Encrypted • Diffie-Hellman Key Exchange")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #a8a8a8; font-size: 11px;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(20)
        
        # Username
        layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        layout.addWidget(self.username_input)
        
        # Email
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
        
        # Password requirements
        req_text = QLabel(
            "Password requirements:\n"
            "• At least 12 characters\n"
            "• Uppercase and lowercase letters\n"
            "• At least one digit\n"
            "• At least one special character (!@#$%^&*...)"
        )
        req_text.setStyleSheet("""
            color: #7f8c8d;
            font-size: 11px;
            padding: 10px;
            background-color: #16213e;
            border-radius: 5px;
        """)
        layout.addWidget(req_text)
        
        # Show password checkbox
        self.show_password_cb = QPushButton("👁 Show Password")
        self.show_password_cb.setCheckable(True)
        self.show_password_cb.clicked.connect(self.toggle_password_visibility)
        self.show_password_cb.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                font-size: 12px;
            }
            QPushButton:checked {
                background-color: #0f3460;
            }
        """)
        layout.addWidget(self.show_password_cb)
        
        # Login button
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)
        
        # Register button
        self.register_btn = QPushButton("Register New Account")
        self.register_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        self.register_btn.clicked.connect(self.handle_register)
        layout.addWidget(self.register_btn)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        central_widget.setLayout(layout)
        
        # Connect Enter key
        self.password_input.returnPressed.connect(self.handle_login)
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_cb.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
    
    def handle_login(self):
        """Handle login with server connection test"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            self.status_label.setText("❌ Please enter username and password")
            return
        
        self.status_label.setText("🔄 Testing server connection...")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        
        QApplication.processEvents()
        
        # Test server connection first
        try:
            test_response = requests.get(f"{self.api.base_url}/", timeout=5)
            if test_response.status_code != 200:
                self.status_label.setText("❌ Server not responding")
                self.login_btn.setEnabled(True)
                self.register_btn.setEnabled(True)
                return
        except Exception as e:
            self.status_label.setText(f"❌ Cannot connect to server: {str(e)}")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
            return
        
        self.status_label.setText("🔄 Logging in...")
        QApplication.processEvents()
        
        print(f"\n{'='*60}")
        print(f"LOGIN ATTEMPT: {username}")
        print(f"{'='*60}")
        
        result = self.api.login(username, password)
        
        if result["success"]:
            print(f"✅ Login successful for {username}")
            self.status_label.setText("✅ Login successful!")
            QTimer.singleShot(500, self.open_chat_window)
        else:
            error_msg = result['error']
            print(f"❌ Login failed: {error_msg}")
            self.status_label.setText(f"❌ {error_msg}")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
    
    def handle_register(self):
        """Handle registration"""
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not email or not password:
            self.status_label.setText("❌ Please fill all fields")
            return
        
        self.status_label.setText("🔄 Registering...")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        
        QApplication.processEvents()
        
        print(f"\n{'='*60}")
        print(f"REGISTRATION ATTEMPT: {username}")
        print(f"{'='*60}")
        
        result = self.api.register(username, email, password)
        
        if result["success"]:
            print(f"✅ Registration successful for {username}")
            self.status_label.setText("✅ Registration successful! Please login.")
            self.email_input.clear()
            self.password_input.clear()
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
        else:
            error_msg = result['error']
            print(f"❌ Registration failed: {error_msg}")
            self.status_label.setText(f"❌ {error_msg}")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
    
    def open_chat_window(self):
        """Open chat window"""
        print(f"\n{'='*60}")
        print(f"OPENING CHAT WINDOW FOR: {self.api.username}")
        print(f"{'='*60}\n")
        
        self.chat_window = ChatWindow(self.api)
        self.chat_window.show()
        self.close()


# ========== CHAT WINDOW ==========

class ChatWindow(QMainWindow):
    """Enhanced chat window with E2EE indicators - FIXED VERSION"""
    
    new_message_signal = pyqtSignal(dict)
    
    def __init__(self, api: SecureChatAPI):
        super().__init__()
        self.api = api
        self.current_chat_user = None
        self.users = []
        
        print(f"\n{'='*60}")
        print(f"INITIALIZING CHAT WINDOW FOR: {api.username}")
        print(f"{'='*60}\n")
        
        self.init_ui()
        
        print("🔄 Loading initial user list...")
        self.load_users()
        
        print("🔄 Connecting WebSocket...")
        self.connect_websocket()
        
        self.new_message_signal.connect(self.handle_incoming_message)
        
        # Auto-refresh user list every 30 seconds
        print("🔄 Starting auto-refresh timer (30 seconds)...")
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_users)
        self.refresh_timer.start(30000)
        
        print(f"\n{'='*60}")
        print(f"CHAT WINDOW INITIALIZED SUCCESSFULLY")
        print(f"{'='*60}\n")
    
    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle(f"Secure Chat - {self.api.username} 🔐")
        self.setGeometry(100, 100, 1100, 650)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QListWidget {
                background-color: #16213e;
                color: #eee;
                border: none;
                font-size: 14px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 12px;
                border-radius: 8px;
                margin: 3px;
            }
            QListWidget::item:selected {
                background-color: #e94560;
            }
            QListWidget::item:hover {
                background-color: #0f3460;
            }
            QTextEdit {
                background-color: #0f3460;
                color: #eee;
                border: 1px solid #16213e;
                border-radius: 8px;
                padding: 10px;
                font-size: 13px;
            }
            QLineEdit {
                padding: 12px;
                border: 2px solid #16213e;
                border-radius: 8px;
                background-color: #0f3460;
                color: #eee;
                font-size: 13px;
            }
            QPushButton {
                padding: 12px 20px;
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c23b54;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout()
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Sidebar
        sidebar = QFrame()
        sidebar.setMaximumWidth(280)
        sidebar.setStyleSheet("background-color: #16213e;")
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(15, 15, 15, 15)
        
        # User info
        user_label = QLabel(f"👤 {self.api.username}")
        user_label.setStyleSheet(
            "color: #eee; font-size: 18px; font-weight: bold; padding: 10px;"
        )
        sidebar_layout.addWidget(user_label)
        
        # E2EE indicator
        e2ee_label = QLabel("🔒 End-to-End Encrypted")
        e2ee_label.setStyleSheet(
            "color: #2ecc71; font-size: 11px; padding: 5px;"
        )
        sidebar_layout.addWidget(e2ee_label)
        
        # Users list
        users_title = QLabel("Users")
        users_title.setStyleSheet("color: #a8a8a8; font-size: 12px; padding: 8px 5px;")
        sidebar_layout.addWidget(users_title)
        
        self.users_list = QListWidget()
        self.users_list.itemClicked.connect(self.select_user)
        sidebar_layout.addWidget(self.users_list)
        
        print(f"✅ Users list widget created: {self.users_list}")
        
        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #c0392b;
                font-size: 12px;
                padding: 8px;
            }
        """)
        logout_btn.clicked.connect(self.handle_logout)
        sidebar_layout.addWidget(logout_btn)
        
        sidebar.setLayout(sidebar_layout)
        main_layout.addWidget(sidebar)
        
        # Chat area
        chat_container = QWidget()
        chat_layout = QVBoxLayout()
        chat_layout.setContentsMargins(20, 20, 20, 20)
        
        # Chat header
        header_layout = QHBoxLayout()
        self.chat_header = QLabel("Select a user to start chatting")
        self.chat_header.setStyleSheet(
            "font-size: 20px; font-weight: bold; color: #eee; padding: 10px;"
        )
        header_layout.addWidget(self.chat_header)
        
        self.encryption_status = QLabel("")
        self.encryption_status.setStyleSheet(
            "font-size: 11px; color: #2ecc71; padding: 10px;"
        )
        header_layout.addWidget(self.encryption_status)
        header_layout.addStretch()
        
        chat_layout.addLayout(header_layout)
        
        # Messages display
        self.messages_display = QTextEdit()
        self.messages_display.setReadOnly(True)
        chat_layout.addWidget(self.messages_display)
        
        # Message input
        input_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)
        
        self.send_btn = QPushButton("Send 🔒")
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)
        
        chat_layout.addLayout(input_layout)
        
        chat_container.setLayout(chat_layout)
        main_layout.addWidget(chat_container)
        
        central_widget.setLayout(main_layout)
    
    def load_users(self):
        """Load users with encryption key exchange - FIXED VERSION with comprehensive debugging"""
        print("\n" + "=" * 60)
        print("LOADING USERS - DEBUG")
        print("=" * 60)
        print(f"Current user: {self.api.username}")
        print(f"Users list widget exists: {self.users_list is not None}")
        print(f"Users list widget count (before): {self.users_list.count()}")
        
        # Get users from API
        result = self.api.get_users()
        
        print(f"\nAPI call result:")
        print(f"  Success: {result.get('success')}")
        if not result.get('success'):
            print(f"  Error: {result.get('error')}")
        
        if not result["success"]:
            error_msg = result.get('error', 'Unknown error')
            print(f"❌ Failed to get users: {error_msg}")
            
            # Clear list and show error
            self.users_list.clear()
            error_item = QListWidgetItem(f"❌ Error: {error_msg}")
            error_item.setForeground(QColor("#e74c3c"))
            self.users_list.addItem(error_item)
            
            # Show message box
            QMessageBox.warning(
                self,
                "Error Loading Users",
                f"Could not load users:\n{error_msg}\n\nPlease check server connection."
            )
            print("=" * 60 + "\n")
            return
        
        # Success - we have users data
        self.users = result["data"]
        print(f"✅ Received {len(self.users)} users from API")
        
        # Clear the list widget
        self.users_list.clear()
        print(f"  Cleared users list widget")
        print(f"  Users list widget count (after clear): {self.users_list.count()}")
        
        # Check if there are any users
        if len(self.users) == 0:
            print("  ℹ️  No other users found")
            placeholder = QListWidgetItem("No other users available")
            placeholder.setForeground(QColor("#7f8c8d"))
            self.users_list.addItem(placeholder)
            print(f"  Added placeholder item")
            print(f"  Users list widget count (after placeholder): {self.users_list.count()}")
        else:
            # Add each user to the list
            print(f"\n  Adding {len(self.users)} users to list widget:")
            for i, user in enumerate(self.users):
                username = user.get('username', 'Unknown')
                is_online = user.get('is_online', False)
                has_public_key = bool(user.get('public_key'))
                
                # Check if we have encryption key
                has_chat_key = self.api.e2ee.get_chat_key(username) is not None
                
                # Create display text
                status_icon = "🟢" if is_online else "⚫"
                key_icon = "🔑" if has_chat_key else "❌"
                item_text = f"{status_icon} {username} {key_icon}"
                
                print(f"    [{i+1}] {username}:")
                print(f"        online={is_online}")
                print(f"        has_public_key={has_public_key}")
                print(f"        has_chat_key={has_chat_key}")
                print(f"        display_text='{item_text}'")
                
                # Create list item
                item = QListWidgetItem(item_text)
                
                # Color code based on key status
                if not has_chat_key:
                    item.setForeground(QColor("#7f8c8d"))  # Gray if no key
                    print(f"        color=gray (no key)")
                else:
                    item.setForeground(QColor("#ffffff"))  # White if has key
                    print(f"        color=white (has key)")
                
                # Add to list widget
                self.users_list.addItem(item)
                print(f"        ✅ Added to list widget")
                print(f"        Current widget count: {self.users_list.count()}")
        
        print(f"\n✅ User list updated!")
        print(f"  Final widget count: {self.users_list.count()}")
        print("=" * 60 + "\n")
        
        # Force UI update
        self.users_list.update()
        self.users_list.repaint()
        QApplication.processEvents()
        
        print(f"✅ UI update forced, final count: {self.users_list.count()}\n")
    
    def select_user(self, item):
        """Select user for chat"""
        item_text = item.text()
        print(f"\n📋 User selected: {item_text}")
        
        # Extract username (format: "🟢 username 🔑")
        parts = item_text.split()
        if len(parts) >= 2:
            username = parts[1]  # Get the username part
        else:
            print(f"⚠️  Could not parse username from: {item_text}")
            return
        
        print(f"   Parsed username: {username}")
        self.current_chat_user = username
        
        # Check if we have encryption key
        has_key = self.api.e2ee.get_chat_key(username) is not None
        
        self.chat_header.setText(f"💬 {username}")
        
        if has_key:
            self.encryption_status.setText("🔒 Encrypted with DH key")
            print(f"   ✅ Has encryption key")
        else:
            self.encryption_status.setText("⚠️ Setting up encryption...")
            print(f"   ⚠️  No encryption key, fetching...")
            # Try to get key
            result = self.api.get_user_public_key(username)
            if result["success"]:
                self.encryption_status.setText("🔒 Encrypted with DH key")
                print(f"   ✅ Encryption key obtained")
                self.load_users()  # Refresh to show key icon
            else:
                print(f"   ❌ Failed to get encryption key")
        
        self.load_message_history(username)
    
    def load_message_history(self, username: str):
        """Load and decrypt message history"""
        print(f"\n📜 Loading message history with: {username}")
        
        result = self.api.get_message_history(username)
        
        if result["success"]:
            messages = result["data"]
            print(f"   ✅ Loaded {len(messages)} messages")
            self.messages_display.clear()
            
            for msg in messages:
                self.display_message(
                    msg["sender_username"],
                    msg["decrypted_content"],
                    msg["timestamp"]
                )
        else:
            print(f"   ❌ Failed to load messages: {result.get('error')}")
    
    def send_message(self):
        """Send encrypted message"""
        if not self.current_chat_user:
            QMessageBox.warning(self, "Warning", "Please select a user first!")
            return
        
        message_text = self.message_input.text().strip()
        if not message_text:
            return
        
        print(f"\n📤 Sending message to {self.current_chat_user}: {message_text[:50]}...")
        
        result = self.api.send_message(self.current_chat_user, message_text)
        
        if result["success"]:
            print(f"   ✅ Message sent successfully")
            self.display_message(
                self.api.username,
                message_text,
                datetime.now().isoformat()
            )
            self.message_input.clear()
        else:
            error_msg = result['error']
            print(f"   ❌ Failed to send: {error_msg}")
            QMessageBox.critical(self, "Error", f"Failed to send: {error_msg}")
    
    def display_message(self, sender: str, content: str, timestamp: str):
        """Display message in chat"""
        try:
            time_str = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime("%H:%M")
        except:
            time_str = datetime.now().strftime("%H:%M")
        
        is_me = (sender == self.api.username)
        
        if is_me:
            color = "#e94560"
            align = "right"
            sender_display = "You"
        else:
            color = "#2ecc71"
            align = "left"
            sender_display = sender
        
        html = f"""
        <div style="margin: 8px 0; text-align: {align};">
            <span style="color: {color}; font-weight: bold;">{sender_display}</span>
            <span style="color: #7f8c8d; font-size: 10px;"> {time_str}</span><br>
            <span style="color: #eee; background-color: #0f3460; padding: 8px 12px; 
                         border-radius: 10px; display: inline-block; margin-top: 3px;">
                {content}
            </span>
        </div>
        """
        
        self.messages_display.append(html)
    
    def connect_websocket(self):
        """Connect to WebSocket"""
        self.api.connect_websocket(self.on_websocket_message)
    
    def on_websocket_message(self, data: dict):
        """Handle incoming WebSocket message"""
        self.new_message_signal.emit(data)
    
    def handle_incoming_message(self, data: dict):
        """Handle incoming message in main thread"""
        if data.get("type") == "new_message":
            sender = data.get("sender")
            content = data.get("decrypted_content", "[Failed to decrypt]")
            timestamp = data.get("timestamp")
            
            print(f"\n📨 New message from {sender}: {content[:50]}...")
            
            if sender == self.current_chat_user:
                self.display_message(sender, content, timestamp)
            
            # Show notification
            QMessageBox.information(
                self,
                f"New Message from {sender}",
                f"{content[:100]}..."
            )
    
    def handle_logout(self):
        """Handle logout"""
        print(f"\n👋 Logging out: {self.api.username}")
        self.api.logout()
        self.close()
        
        # Return to login window
        login_window = LoginWindow()
        login_window.show()
    
    def closeEvent(self, event):
        """Handle window close"""
        print(f"\n🔌 Closing chat window for: {self.api.username}")
        self.api.disconnect_websocket()
        self.refresh_timer.stop()
        event.accept()


# ========== MAIN ==========

def main():
    """Main entry point"""
    print("\n" + "=" * 60)
    print("SECURE CHAT CLIENT - STARTING")
    print("=" * 60 + "\n")
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Check if SSL should be enabled
    import os
    use_ssl = os.getenv("USE_SSL", "false").lower() == "true"
    
    print(f"SSL Enabled: {use_ssl}")
    
    login_window = LoginWindow(use_ssl=use_ssl)
    login_window.show()
    
    print("\n" + "=" * 60)
    print("LOGIN WINDOW DISPLAYED")
    print("=" * 60 + "\n")
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()