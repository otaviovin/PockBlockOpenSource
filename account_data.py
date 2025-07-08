import csv
import os
from flask import render_template
from stellar_sdk import Network, Server
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get network type and Horizon server URL from environment variables
GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

def generate_buttons():
    """
    Generates HTML buttons for closing, copying, and sharing a notification.
    
    :return: HTML string with buttons
    """
    return (
        f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
        f"<button id='copyBtn' onclick='copyToClipboard()'><i class='fas fa-copy'></i> Copy</button>"
        f"<button id='shareBtn' onclick='shareNotification()'><i class='fas fa-share-alt'></i> Share</button>"
    )

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
    
    def get_account_info_from_csv(self, account):
        """
        Retrieves account metadata from a CSV file (seed phrase, hexadecimal, password).

        :param account: Stellar account ID
        :return: Tuple (passphrase, hexadecimal, password) or "Not Found" if not available
        """
        passphrase, hexadecimal, password = "Not Found", "Not Found", "Not Found"
        file_path = 'wallet_data.csv'
        try:
            with open(file_path, mode='r', newline='') as file:
                reader = csv.reader(file)
                for row in reader:
                    if len(row) >= 5 and row[0] == account:
                        passphrase, hexadecimal, password = row[2], row[3], row[4]
                        break

        except FileNotFoundError:
            print("CSV file not found.")
            
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
                passphrase, hexadecimal, password = self.get_account_info_from_csv(account)

                message = (
                        f"<br>"
                        f"<strong>Account Information.</strong><br><br>"
                        f"<strong>Seed Phrase:</strong> <br> {passphrase} <br><br>"
                        f"<strong>Hexadecimal:</strong> <br> {hexadecimal} <br><br>"
                        f"<strong>Password:</strong> <br> {password} <br><br>"
                        f"<br>"
                        + generate_buttons()
                    )

                return message
            
            except Exception:
                # Conta não encontrada na rede principal, tentar na testnet
                if self.network == 'mainnet':
                    try:
                        testnet_server = Server(horizon_url="https://horizon-testnet.stellar.org")
                        testnet_server.load_account(account)

                        message = (
                            "<br>Account does not exist in mainnet, but exists in testnet.<br>"
                            "Please activate the account on mainnet!<br><br>"
                            + generate_buttons()
                        )

                        return message
                    
                    except Exception:
                        message = (
                            "<br>Account does not exist in any network.<br>"
                            "Please logout and generate a new account.<br><br>"
                            + generate_buttons()
                        )
                        return message
                    
                else:
                    message = (
                        "<br>Account not found in the testnet.<br>"
                        "Please logout and generate a new account.<br><br>"
                        + generate_buttons()
                    )
                    return message
            
        except Exception as e:
            message = (
                f"<br>"
                f"Error generating account data: {e}<br>"
                f"<br>"
            )
            return message