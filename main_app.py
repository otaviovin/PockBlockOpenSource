from flask import Flask, render_template, request, redirect, url_for, session, send_file
import threading
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtGui import QIcon
import os
from dotenv import load_dotenv
from datetime import timedelta
import secrets

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL")  # Server URL

app = Flask(__name__)

# Generate a random secret key for Flask sessions.
# It is recommended that in production, this key is fixed and securely stored (e.g., environment variable).
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Define session expiration time (optional but recommended).
app.permanent_session_lifetime = timedelta(hours=1)

# Security settings for session cookies.
app.config.update(
    # SESSION_COOKIE_SECURE=True,      # (Production) Cookies are only sent over HTTPS.
    SESSION_COOKIE_SECURE=False,     # (Development) Cookies are only sent over HTTPS.
    SESSION_COOKIE_SAMESITE='Lax',   # Provides basic CSRF protection. Use 'None' for cross-domain.
    SESSION_COOKIE_HTTPONLY=True     # Prevents JavaScript access (protects against XSS).
)

def run_flask():
    """
    Function to run the Flask web server on a separate thread.

    This function starts the Flask application in debug mode, with the reloader disabled
    to prevent it from restarting the server while running in a separate thread.
    """
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)

class WebViewWindow(QMainWindow):
    """
    PyQt5 window class that renders the Flask web application in a QWebEngineView.

    This class creates a window using PyQt5 to display a web application served by Flask.
    The window title is set to 'Pocket Block', and a logo is displayed in the top bar.
    The window is resized dynamically based on the screen size, simulating a mobile device.
    """
    
    def __init__(self):
        """
        Initializes the WebViewWindow instance and sets up the window properties.

        This constructor sets the window title, adds an icon to the top bar, and configures
        the layout to display the Flask application via QWebEngineView. The window size is
        set to simulate a 5-inch Android device screen.
        """
        super().__init__()
        self.setWindowTitle("Pocket Block")

        # Add logo to the top bar
        self.setWindowIcon(QIcon("./static/pocketblock_logo_2.png"))  # Path to the logo image

        # Set up the layout and browser view
        self.browser = QWebEngineView()

        # Configure responsive window size for mobile simulation
        self.setGeometry(100, 100, 375, 667)  # Position (100, 100) and size (375x667)
        
        # Dynamically adjust the browser size based on the window
        self.browser.resize(self.width(), self.height())
        self.browser.page().setZoomFactor(1.0)  # Ensure correct zoom factor

        # Set the URL to the locally hosted Flask application
        self.browser.setUrl(QUrl("http://127.0.0.1:5000/app"))

        # Set the browser as the central widget of the window
        self.setCentralWidget(self.browser)

# Main function to run PyQt5 and Flask concurrently
if __name__ == "__main__":
    """
    Main function to run the Flask and PyQt5 applications simultaneously.

    This function starts the Flask web server on a separate thread and initializes
    the PyQt5 application to display the Flask app in a web view window.
    """
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True  # Daemonize the thread to exit with the main program
    flask_thread.start()

    # Initialize PyQt5 application
    app = QApplication([])

    # Create and show the WebViewWindow instance
    window = WebViewWindow()
    window.show()

    # Run the PyQt5 application event loop
    app.exec_()