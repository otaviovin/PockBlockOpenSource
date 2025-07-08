from flask import request, jsonify
from stellar_sdk import Keypair, Asset, Server, Network, TransactionBuilder
import csv
import requests
import base64
import binascii
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import timedelta
import datetime

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

# Connecting to MongoDB using the URI defined in environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI is not defined in the .env file")

# Initializing the MongoDB client using the MongoDB URI with TLS encryption enabled
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)
data_db = client["datapocketblock"]
data_collection = data_db["userdata"]

class GenerateAccount:
    """
    A class for generating Stellar accounts, funding them, creating trustlines,
    converting keys to mnemonic passphrases and hex, and saving account data to a CSV file.

    Attributes:
        public_key (str): The generated Stellar public key.
        secret_key (str): The corresponding Stellar secret key.
        passphrase (str): Passphrase derived from the secret key.
        hexadecimal (str): Hexadecimal representation of the secret key.
        keys_match (bool): Flag indicating if keys match specific criteria.
    """

    def __init__(self, public_key=None, secret_key=None, passphrase=None, hexadecimal=None, keys_match=None):
        self.public_key = public_key
        self.secret_key = secret_key
        self.passphrase = passphrase
        self.hexadecimal = hexadecimal
        self.keys_match = keys_match

    # Enviar XLM de uma conta que já tenha saldo na mainnet
    def fund_new_account(self, destination_public_key):
        """
        Funds a new Stellar account on the mainnet using the configured funder account.

        Args:
            destination_public_key (str): The public key of the account to fund.

        Returns:
            dict: Transaction response from the Stellar network.
        """
        source_secret = os.getenv("MAINNET_FUNDER_SECRET")
        source_keypair = Keypair.from_secret(source_secret)
        server = Server(horizon_url=HORIZON_URL)
        source_account = server.load_account(source_keypair.public_key)

        transaction = (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
                base_fee=100
            )
            .append_create_account_op(
                destination=destination_public_key, 
                starting_balance="1"
            )
            .set_timeout(30)
            .build()
        )

        transaction.sign(source_keypair)
        response = server.submit_transaction(transaction)
        return response

    def create_trustlines(self, server, public_key, secret_key, network_passphrase):
        """
        Creates trustlines for the assets USDC, EURC, and BRLC.

        Args:
            server (Server): The Stellar server.
            public_key (str): The account's public key.
            secret_key (str): The account's secret key.
            network_passphrase (str): The Stellar network passphrase.

        Returns:
            str: Success or failure message.
        """
        try:
            print("Initiating creation of trustlines for USDC, EURC, and BRLC...")

            # Define assets (USDC, EURC, BRLC)
            usdt_asset = Asset("USDC", os.getenv("USDC_ADDRESS"))  # USDC Issuer
            eurc_asset = Asset("EURC", os.getenv("EURC_ADDRESS"))  # EURC Issuer
            brl_asset = Asset("BRLC", os.getenv("BRLC_ADDRESS"))   # BRLC Issuer
            destination_account = server.load_account(account_id=public_key) # Load account on Stellar server
            pair = Keypair.from_secret(secret_key)

            transaction = (
                TransactionBuilder(
                    source_account=destination_account,
                    network_passphrase=network_passphrase,
                    base_fee=100
                )
                .append_change_trust_op(asset=usdt_asset)
                .append_change_trust_op(asset=eurc_asset)
                .append_change_trust_op(asset=brl_asset)
                .set_timeout(30)
                .build()
            )

            transaction.sign(pair)
            response = server.submit_transaction(transaction)

            message = (
                f"Trustlines created successfully."
            )

            return message

        except Exception as e:
            message = (
                f"Trustlines creation failed."
            )

            return message

    def load_word_list(self, file_path): 
        """
        Loads a word list from a CSV file to be used in passphrase generation.

        Args:
            file_path (str): The path to the CSV file.

        Returns:
            list: List of dictionaries with letter-word pairs.

        Raises:
            ValueError: If file is missing or contains invalid data.
        """
        print(f"Loading word list from file: {file_path}...")
        word_list = []
        try:
            with open(file_path, mode='r', encoding='utf-8') as file:
                reader = csv.reader(file)
                for row in reader:
                    if len(row) == 2:
                        letter = row[0].strip()
                        word = row[1].strip()
                        word_list.append({"letter": letter, "word": word})
                    else:
                        raise ValueError(f"Invalid row in file: {row}")
                    
        except FileNotFoundError:
            raise ValueError(f"File {file_path} not found.")
        
        except Exception as e:
            raise ValueError(f"Error reading file: {str(e)}")

        return word_list

    def secret_key_to_passphrase(self, secret_key):
        """
        Converts a Stellar secret key into a mnemonic passphrase.

        Args:
            secret_key (str): The Stellar secret key.

        Returns:
            str: The mnemonic passphrase.

        Raises:
            ValueError: If a word for a key pair is not found.
        """
        word_list = self.load_word_list('words_phrase.csv')
        secret_key_div2 = [secret_key[i:i+2] for i in range(0, len(secret_key), 2)] # Split secret key into 2-character pairs
        passphrase = [] # Convert secret key to passphrase

        for pair in secret_key_div2:
            match = next((item['word'] for item in word_list if item['letter'] == pair), None)
            if match:
                passphrase.append(match)
            else:
                raise ValueError(f"No word found for pair: {pair}")

        return " ".join(passphrase)

    def save_to_csv(self, public_key, secret_key, passphrase, hexadecimal, password=None):
        """
        Saves account information to a CSV file.

        Args:
            public_key (str): Stellar public key.
            secret_key (str): Stellar secret key.
            passphrase (str): Mnemonic passphrase.
            hexadecimal (str): Hexadecimal secret key.
            password (str, optional): Associated password.
        """
        file_path = os.path.join(os.path.dirname(__file__), 'wallet_data.csv')
        rows = []

        try:
            with open(file_path, mode='r', newline='') as file:
                reader = csv.reader(file)
                rows = list(reader)

        except FileNotFoundError:
            rows = []

        for row in rows:
            if public_key in row or secret_key in row:
                print(f"Duplicate found: Public Key: {public_key} or Secret Key: {secret_key}")
                return
        
        try:
            absolute_path = os.path.abspath(file_path)

            if os.path.exists(absolute_path):
                print(f"File {absolute_path} exists.")

                with open(file_path, mode='a', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow([public_key, secret_key, passphrase, hexadecimal, password])
                    file.flush()

            else:
                print(f"File {absolute_path} does not exist. Creating file...")
                try:
                    with open(absolute_path, mode='w', newline='', encoding='utf-8') as file:
                        print(f"File {absolute_path} created successfully.")
                except Exception as e:
                    print(f"Error creating file {absolute_path}: {e}")

        except Exception as e:
            print(f"Error writing to CSV file: {e}")

    def execute(self):
        """
        Main method to generate a Stellar account, fund it, create trustlines,
        convert the secret key to passphrase and hexadecimal, and store the data.

        Returns:
            Flask JSON Response: JSON with account details or an error message.
        """
        try:
            data = request.json
            password = data.get('password', '')
            pair = Keypair.random()
            public_key = pair.public_key
            secret_key = pair.secret

            if len(secret_key) != 56:
                raise ValueError(f"Secret key must have 56 characters. Current length: {len(secret_key)} characters.")
            
            else:
                # Request funds from Friendbot
                if GLOBAL_NETWORK == "testnet":
                    print(f"Requesting funds from Friendbot for account {public_key}...")
                    url = "https://friendbot.stellar.org"
                    response = requests.get(url, params={"addr": public_key})
                    print(f"Friendbot response: {response.status_code}")
                    
                else:
                    print(f"Funding new account from mainnet funder to {public_key}...")
                    fund_response = self.fund_new_account(public_key)
                    print(f"Fund response: {fund_response}")

            passphrase = self.secret_key_to_passphrase(secret_key) # Convert secret key to passphrase
            secret_key_bytes = base64.b32decode(secret_key, casefold=True)
            hexadecimal = binascii.hexlify(secret_key_bytes).decode() # Decode secret key to bytes and convert to hexadecimal
            self.save_to_csv(public_key, secret_key, passphrase, hexadecimal, password)

            # Configure the Stellar network and Horizon URL
            horizon_url = HORIZON_URL
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            server = Server(horizon_url=horizon_url)
            trustline_status = self.create_trustlines(server, public_key, secret_key, network_passphrase) # Create trustlines for USDC, EURC, and BRL
            self.public_key = public_key
            self.secret_key = secret_key
            self.passphrase = passphrase
            self.hexadecimal = hexadecimal

            response = {
                'public_key': public_key,
                'secret_key': secret_key,
                'passphrase': passphrase,
                'hexadecimal': hexadecimal,
                'trustline_status': trustline_status
            }

            user_data = {
                "keypair": self.public_key,
                "name": None,
                "email": None,
                "phone_number": None,
                "resaddress": None,
                "user": "desactivated",
                "settings_datetime": datetime.datetime.utcnow()
            }

            data_collection.insert_one(user_data)

            return jsonify(response), 200

        except Exception as e:

            return jsonify({'error': str(e)}), 500
