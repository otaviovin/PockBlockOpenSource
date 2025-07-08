import requests
from io import BytesIO
from flask import send_file
from stellar_sdk import Keypair, Server, TransactionBuilder, Network, Asset
import qrcode
from io import BytesIO
from PIL import Image 
import base64
import os
from dotenv import load_dotenv
from decimal import Decimal, ROUND_DOWN
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
        print(f"text_memo: {text_memo}")

        if self.asset_code == "USDC":
            settings = settings_collection.find_one({"withdraw_type": "USD"})
        elif self.asset_code == 'EURC':
            settings = settings_collection.find_one({"withdraw_type": "EUR"})
        else:
            print(f"Error defining settings")
                    
        print(f"Settings: {settings}")

        try:
            min_perc_receive = settings["fee"]
            min_perc_receive_value = Decimal(self.amount_receive) * Decimal(min_perc_receive)

        except (ValueError, TypeError) as e:
            print(f"Error applying fee_withdraw: {e}")
            message = (
                f"Error applying fee for withdraw"
            )
            return message

        # Calculate minimum amount for selling asset
        min_amount_sell = Decimal(self.amount_receive) + (Decimal(self.amount_receive) * min_perc_receive_value) 
        print(min_amount_sell)
        qr_data = f"http://www.pocketblock.io/transaction?asset_code={self.asset_code}&destination_account={self.keypair}&amount_sell={self.amount_receive}&min_amount_sell={min_amount_sell}"
        print(qr_data)

        # Create the QR code from the data
        qr_img = qrcode.make(qr_data)

        # Resize the QR code (larger box_size and border)
        qr_img = qrcode.make(qr_data, box_size=10, border=1)  # Adjust box_size for larger QR code

        # Ensure the image is compatible with Pillow
        qr_img = qr_img.convert("RGB")  # Convert to RGB mode for Pillow compatibility

        # Save the QR code image to memory and prepare for sending
        img_byte_arr = BytesIO()
        qr_img.save(img_byte_arr, format='PNG')  # Save as PNG
        img_byte_arr.seek(0)

        # Encode the image as base64 (if required by the application)
        qr_code_base64 = base64.b64encode(img_byte_arr.getvalue()).decode("utf-8")

        # Generate an HTML message with the payment details and the QR code link
        message = (
            f"<br>"
            f"<strong>QR Code: </strong>"
            f"Receive {self.amount_receive} {self.asset_code} at account <br> {self.keypair} <br>"
            f"<strong>Link:</strong> <a href='{qr_data}' target='_blank'>{qr_data}</a><br>"
            f"<br>"
        )

        print(message)
        return qr_code_base64, message, qr_data
