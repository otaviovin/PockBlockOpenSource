# ========================
# Imports and Dependencies
# ========================

# Module for sending HTTP requests (e.g., calling APIs)
import requests

# Allows creation of in-memory byte streams (used for handling image and QR code data without saving to disk)
from io import BytesIO

# Flask function to send files (e.g., images, QR codes) as HTTP responses
from flask import send_file

# Stellar SDK components for account management, transactions, network selection, and asset operations
from stellar_sdk import Keypair, Server, TransactionBuilder, Network, Asset

# QR code generation library
import qrcode

# Redundant import (already imported above), but allows creation of in-memory streams
from io import BytesIO

# Pillow (PIL) library used for image manipulation (e.g., resizing or converting QR code images)
from PIL import Image

# Module for encoding and decoding Base64 (commonly used for embedding images in HTML)
import base64

# Module for interacting with the operating system (e.g., reading environment variables, working with paths)
import os

# Loads environment variables from a `.env` file into the runtime environment
from dotenv import load_dotenv

# Decimal module used for precise decimal arithmetic (e.g., rounding financial values)
from decimal import Decimal, ROUND_DOWN

# MongoDB client for connecting to and querying MongoDB databases
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

# MongoDB Configuration
mongo_client = MongoClient(os.getenv("MONGODB_URI"))
data_db_withdraw = mongo_client["withdrawpocketblock"]
settings_collection = data_db_withdraw["settings_value_fiat"]

class Receive:
    """
    Class to handle the generation of QR codes for receiving payments via Stellar network.
    The class provides methods to generate a QR code based on transaction details like 
    asset code, amount, and destination account.

    Attributes:
        network (str): The network used (e.g., 'testnet' or 'public').
        keypair (str): The Stellar keypair of the receiving account.
        seed (str): The seed phrase of the Stellar account.
        text_memo (str): A memo that will be included with the payment.
        amount_receive (float): The amount of asset to be received.
        asset_code (str): The code of the asset (e.g., 'XLM', 'USDC') to be received.
    """

    def __init__(self, network, keypair, seed, text_memo, amount_receive, asset_code):
        """
        Initializes the Receive object with the required attributes.

        Args:
            network (str): The network to use (e.g., 'testnet', 'public').
            keypair (str): The Stellar keypair for the receiving account.
            seed (str): The seed phrase for the Stellar account.
            text_memo (str): The memo text to be included in the transaction.
            amount_receive (float): The amount of asset to be received.
            asset_code (str): The asset code (e.g., 'XLM', 'USDC') to be received.
        """
        self.network = network
        self.keypair = keypair
        self.seed = seed
        self.text_memo = text_memo
        self.amount_receive = amount_receive
        self.asset_code = asset_code

    def execute(self):
        """
        Generates a QR code for the given receiving details, including the amount, asset code, 
        and destination account. Depending on the asset type, it generates a URL either for 
        a Stellar payment request (for native XLM) or a transaction request (for other assets).

        The generated QR code contains a link with relevant parameters for the transaction.

        Returns:
            tuple: A tuple containing:
                - qr_code_base64 (str): The base64-encoded QR code image.
                - message (str): The HTML message with the details of the transaction.
                - qr_data (str): The URL encoded in the QR code.
        """
        # Format the text memo containing the keypair, amount, and asset code
        text_memo = (f"{self.keypair},{self.amount_receive},{self.asset_code}")

        if self.asset_code == "USDC":
            settings = settings_collection.find_one({"withdraw_type": "USD"})

        elif self.asset_code == 'EURC':
            settings = settings_collection.find_one({"withdraw_type": "EUR"})

        else:
            print(f"Error defining settings")

        try:
            min_perc_receive = settings["fee"]
            min_perc_receive_value = Decimal(self.amount_receive) * Decimal(min_perc_receive)

        except (ValueError, TypeError) as e:
            message = (f"<br>Error applying fee for withdraw<br>")
            return message

        min_amount_sell = Decimal(self.amount_receive) + (Decimal(self.amount_receive) * min_perc_receive_value) # Calculate minimum amount for selling asset
        qr_data = f"http://www.pocketblock.io/transaction?asset_code={self.asset_code}&destination_account={self.keypair}&amount_sell={self.amount_receive}&min_amount_sell={min_amount_sell}"
        qr_img = qrcode.make(qr_data) # Create the QR code from the data
        qr_img = qrcode.make(qr_data, box_size=10, border=1)  # Adjust box_size for larger QR code # Resize the QR code (larger box_size and border)
        qr_img = qr_img.convert("RGB")  # Convert to RGB mode for Pillow compatibility # Ensure the image is compatible with Pillow
        img_byte_arr = BytesIO() # Save the QR code image to memory and prepare for sending
        qr_img.save(img_byte_arr, format='PNG')  # Save as PNG
        img_byte_arr.seek(0)
        qr_code_base64 = base64.b64encode(img_byte_arr.getvalue()).decode("utf-8") # Encode the image as base64 (if required by the application)

        # Generate an HTML message with the payment details and the QR code link
        message = (
            f"<br><strong>QR Code: </strong><br>"
            f"Receive {self.amount_receive} {self.asset_code} <br> at account {self.keypair} <br>"
            f"<strong>Link:</strong> <a href='{qr_data}' target='_blank'>{qr_data}</a><br>"
        )
        return qr_code_base64, message, qr_data
