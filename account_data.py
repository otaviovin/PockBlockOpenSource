# ========================
# Imports and Dependencies
# ========================

# Module for reading from and writing to CSV files
import csv

# Module for interacting with the operating system (e.g., environment variables, file paths)
import os

# Function from Flask to render HTML templates
from flask import render_template

# Stellar SDK components for accessing the network and submitting transactions
from stellar_sdk import Network, Server

# Loads environment variables from a .env file into the environment
from dotenv import load_dotenv

# MongoDB client for accessing and interacting with a MongoDB database
from pymongo import MongoClient

# Module from the cryptography package for symmetric encryption and decryption
from cryptography.fernet import Fernet


# Load environment variables from .env file
load_dotenv()

# Connecting to MongoDB using the URI defined in environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI is not defined in the .env file")

# 
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

# Initializing the MongoDB client using the MongoDB URI with TLS encryption enabled
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)
data_db = client["datapocketblock"]
wallet_data_collection = data_db["wallet_data"]

fernet = Fernet(ENCRYPTION_KEY.encode())

# Get network type and Horizon server URL from environment variables
GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

class AccountData:
    """
    Class to retrieve and manage Stellar account data, such as transactions, balances,
    and trustlines.
    """
    def __init__(self, account, network):
        """
        Initializes the AccountData object.

        :param account: Stellar account ID (public key)
        :param network: Network type ("mainnet" or "testnet")
        """
        self.account = account
        self.network = network
        self.transaction_list = []  # List to store account transactions
        self.balance_list = []  # List to store account balances
        self.trustlines = {"USDC": False, "EURC": False, "BRLC": False}  # Trustline status

    def get_trustlines(self, account_data_transaction):
        """
        Retrieves trustline information from account data.

        :param account_data_transaction: JSON object containing balances
        :return: Dictionary showing which trustlines exist
        """
        for balance in account_data_transaction['balances']:
            asset_code = balance.get('asset_code')
            if asset_code in self.trustlines:
                self.trustlines[asset_code] = True
        return self.trustlines
    
    def get_account_info_from_db(self, account):
        """
        Retrieves account metadata from MongoDB (seed phrase, hexadecimal, password),
        decrypting the stored values.

        :param account: Stellar account ID (public key)
        :return: Tuple (passphrase, hexadecimal, password) or "Not Found" if not available
        """
        passphrase, hexadecimal, password = "Not Found", "Not Found", "Not Found"
        
        try:
            # Busca o documento pelo public_key
            wallet = wallet_data_collection.find_one({"keypair": account})

            if wallet:
                passphrase = fernet.decrypt(wallet["seed_phrase"].encode()).decode()
                hexadecimal = fernet.decrypt(wallet["hexadecimal"].encode()).decode()
                password = fernet.decrypt(wallet["password"].encode()).decode()

        except Exception as e:
            print(f"Error while fetching account from MongoDB or decoding data: {e}")
        
        return passphrase, hexadecimal, password
        
    def execute(self):
        """
        Executes the process of retrieving account details, transactions, balances,
        and checking the existence of the account in the Stellar network.
        
        :return: HTML-formatted message containing account details
        """
        try:
            # Configure the Stellar network and Horizon URL
            horizon_url = HORIZON_URL
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            server = Server(horizon_url=horizon_url)
            account = self.account
            account_data_transaction = server.accounts().account_id(self.account).call() # Retrieve account data
            transactions = server.transactions().for_account(self.account).limit(25).order(desc=True).call()['_embedded']['records']# Retrieve last 25 transactions
            
            self.transaction_list = [
                {
                    "id": tx["id"],
                    "created_at": tx["created_at"],
                    "operation_count": tx["operation_count"],
                    "memo": tx.get("memo", "No memo")
                }
                for tx in transactions
            ] # Process transactions

            self.balance_list = account_data_transaction['balances'] # Retrieve balance list
            self.trustlines = self.get_trustlines(account_data_transaction) # Retrieve trustlines

            # Check if account exists on the selected network
            try:
                account_data_transaction = server.accounts().account_id(account).call()
                passphrase, hexadecimal, password = self.get_account_info_from_db(account)

                message = (
                        f"<br>"
                        f"<strong>Account Information.</strong><br><br>"
                        f"<strong>Seed Phrase:</strong> <br> {passphrase} <br><br>"
                        f"<strong>Hexadecimal:</strong> <br> {hexadecimal} <br><br>"
                        f"<strong>Password:</strong> <br> {password} <br><br>"
                        f"<br>"
                    )

                return message
            
            except Exception:
                # Conta não encontrada na rede principal, tentar na testnet
                if self.network == 'mainnet':
                    try:
                        testnet_server = Server(horizon_url="https://horizon-testnet.stellar.org")
                        testnet_server.load_account(account)

                        message = (f"<br>Account does not exist in mainnet, but exists in testnet.<br>Please activate the account on mainnet!<br>")

                        return message
                    
                    except Exception:
                        message = (f"<br>Account does not exist in any network.<br>Please logout and generate a new account.<br>")
                        return message
                    
                else:
                    message = (f"<br>Account not found in the testnet.<br>Please logout and generate a new account.<br>")
                    return message
            
        except Exception as e:
            message = (f"<br>Error generating account data: {e}<br>")
            return message