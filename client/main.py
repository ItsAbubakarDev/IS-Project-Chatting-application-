"""
Enhanced Secure Chat Client with E2EE
Features: Per-chat encryption, strong password policy, online status
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
        """Handle login"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            self.status_label.setText("❌ Please enter username and password")
            return
        
        self.status_label.setText("🔄 Logging in...")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        
        QApplication.processEvents()
        
        result = self.api.login(username, password)
        
        if result["success"]:
            self.status_label.setText("✅ Login successful!")
            QTimer.singleShot(500, self.open_chat_window)
        else:
            self.status_label.setText(f"❌ {result['error']}")
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
        """Open chat window"""
        self.chat_window = ChatWindow(self.api)
        self.chat_window.show()
        self.close()


# ========== CHAT WINDOW ==========

class ChatWindow(QMainWindow):
    """Enhanced chat window with E2EE indicators"""
    
    new_message_signal = pyqtSignal(dict)
    
    def __init__(self, api: SecureChatAPI):
        super().__init__()
        self.api = api
        self.current_chat_user = None
        self.users = []
        self.init_ui()
        self.load_users()
        self.connect_websocket()
        
        self.new_message_signal.connect(self.handle_incoming_message)
        
        # Auto-refresh user list every 30 seconds
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_users)
        self.refresh_timer.start(30000)
    
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
        """Load users with encryption key exchange"""
        result = self.api.get_users()
        
        if result["success"]:
            self.users = result["data"]
            self.users_list.clear()
            
            for user in self.users:
                has_key = self.api.e2ee.get_chat_key(user['username']) is not None
                status = "🟢" if user.get('is_online') else "⚫"
                key_icon = "🔑" if has_key else "❌"
                
                item_text = f"{status} {user['username']} {key_icon}"
                item = QListWidgetItem(item_text)
                
                if not has_key:
                    item.setForeground(QColor("#7f8c8d"))
                
                self.users_list.addItem(item)
    
    def select_user(self, item):
        """Select user for chat"""
        username = item.text().split()[1]  # Extract username
        self.current_chat_user = username
        
        # Check if we have encryption key
        has_key = self.api.e2ee.get_chat_key(username) is not None
        
        self.chat_header.setText(f"💬 {username}")
        
        if has_key:
            self.encryption_status.setText("🔒 Encrypted with DH key")
        else:
            self.encryption_status.setText("⚠️ Setting up encryption...")
            # Try to get key
            result = self.api.get_user_public_key(username)
            if result["success"]:
                self.encryption_status.setText("🔒 Encrypted with DH key")
                self.load_users()  # Refresh to show key icon
        
        self.load_message_history(username)
    
    def load_message_history(self, username: str):
        """Load and decrypt message history"""
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
        """Send encrypted message"""
        if not self.current_chat_user:
            QMessageBox.warning(self, "Warning", "Please select a user first!")
            return
        
        message_text = self.message_input.text().strip()
        if not message_text:
            return
        
        result = self.api.send_message(self.current_chat_user, message_text)
        
        if result["success"]:
            self.display_message(
                self.api.username,
                message_text,
                datetime.now().isoformat()
            )
            self.message_input.clear()
        else:
            QMessageBox.critical(self, "Error", f"Failed to send: {result['error']}")
    
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
        self.api.logout()
        self.close()
        login_window = LoginWindow()
        login_window.show()
    
    def closeEvent(self, event):
        """Handle window close"""
        self.api.disconnect_websocket()
        self.refresh_timer.stop()
        event.accept()


# ========== MAIN ==========

def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Check if SSL should be enabled
    import os
    use_ssl = os.getenv("USE_SSL", "false").lower() == "true"
    
    login_window = LoginWindow(use_ssl=use_ssl)
    login_window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()