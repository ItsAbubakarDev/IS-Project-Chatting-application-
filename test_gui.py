"""
Quick GUI Test - Add this to the END of your client/main.py temporarily
to test if the QListWidget is working
"""

if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication, QMainWindow, QListWidget, QVBoxLayout, QWidget, QListWidgetItem
    from PyQt5.QtGui import QColor
    
    print("\n" + "="*60)
    print("TESTING QLISTWIDGET")
    print("="*60)
    
    app = QApplication(sys.argv)
    
    window = QMainWindow()
    window.setWindowTitle("QListWidget Test")
    window.setGeometry(100, 100, 300, 400)
    
    central = QWidget()
    layout = QVBoxLayout()
    
    list_widget = QListWidget()
    list_widget.setStyleSheet("""
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
    """)
    
    # Add test items
    print("\nAdding test items:")
    for i in range(5):
        item_text = f"🟢 TestUser{i} 🔑"
        item = QListWidgetItem(item_text)
        list_widget.addItem(item)
        print(f"  Added: {item_text}")
    
    print(f"\nList widget count: {list_widget.count()}")
    print("="*60 + "\n")
    
    layout.addWidget(list_widget)
    central.setLayout(layout)
    window.setCentralWidget(central)
    
    window.show()
    
    print("If you see 5 test users in the window, QListWidget is working!")
    print("If the window is empty, there's a Qt/UI issue.")
    
    sys.exit(app.exec_())