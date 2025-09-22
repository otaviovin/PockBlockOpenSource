# ========================
# Imports and Dependencies
# ========================

# Stellar SDK components used to interact with the Stellar blockchain network
from stellar_sdk import Keypair, Network, Server, TransactionBuilder, Asset

# Module for reading and writing CSV files
import csv

# Module for encoding and decoding data in base64 format
import base64

# Module for interacting with the operating system environment variables
import os

# Loads environment variables from a .env file into the environment
from dotenv import load_dotenv

# MongoDB client used for connecting and interacting with a MongoDB database
from pymongo import MongoClient

# Module to work with time durations (used for expiration and scheduling)
from datetime import timedelta

# Module to work with dates and times
import datetime

# Fernet is part of the cryptography package; it provides symmetric encryption and decryption
from cryptography.fernet import Fernet

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

# Connecting to MongoDB using the URI defined in environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI is not defined in the .env file")

# 
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

# Initializing the MongoDB client using the MongoDB URI with TLS encryption enabled
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)
data_db = client["datapocketblock"]
data_collection = data_db["userdata"]

wallet_data_collection = data_db["wallet_data"]

fernet = Fernet(ENCRYPTION_KEY.encode())

class CreateAccount:
    """
    Handles the creation of Stellar accounts, including transaction submission, trustline setup,
    and data storage in a CSV file.
    """

    def __init__(self, amount, bfee, source_from_secret, network, password, asset_code):
        """
        Initializes the CreateAccount class.

        :param amount: The amount of XLM to fund the new account.
        :param bfee: Base fee for Stellar transactions.
        :param source_from_secret: Secret key of the source account.
        :param network: The Stellar network ('mainnet', 'testnet', 'futurenet').
        :param password: Password used to encrypt or store account data.
        """
        self.amount = amount
        self.bfee = bfee
        self.source_from_secret = source_from_secret
        self.network = network
        self.password = password
        self.asset_code = asset_code

    def calculate_minimum_balance(self, server):
        """
        Calcula o saldo mínimo necessário para criar uma conta nova na Stellar.
        """
        # Obtém o base_reserve diretamente da root do servidor Horizon
        try:
            root_info = server.root().call()
            if "base_reserve_in_stroops" in root_info:
                base_reserve_stroops = int(root_info['base_reserve_in_stroops'])
            elif "config" in root_info and "base_reserve" in root_info["config"]:
                # Fallback: usa base_reserve (em XLM), converte para stroops
                base_reserve_stroops = int(float(root_info["config"]["base_reserve"]) * 10_000_000)
            else:
                # Valor padrão de 0.5 XLM se não encontrado
                base_reserve_stroops = 5_000_000

            base_reserve_xlm = base_reserve_stroops / 10_000_000

            # 2 para a conta + 1 para a trustline (se necessário)
            num_entries = 2  # conta nova sem extra data ou offers
            guarantee_value = 1 #

            if self.asset_code != "XLM":
                num_entries += 1  # adiciona 1 trustline

            minimum_balance = (base_reserve_xlm * num_entries) + guarantee_value
            return round(minimum_balance, 7)  # boa prática: até 7 casas decimais
        
        except Exception as e:
            raise Exception(f"Failed to calculate minimum_balance: {e}")

    def create_trustlines(self, server, destination, bfee, network_passphrase):
        try:
            assets = {
                "USDC": Asset("USDC", os.getenv("USDC_ADDRESS")),
                "EURC": Asset("EURC", os.getenv("EURC_ADDRESS")),
            }

            if self.asset_code not in assets:
                return "No trustline required for XLM."

            asset_to_add = assets[self.asset_code]
            destination_account = server.load_account(destination.public_key)

            for balance in destination_account.balances:
                if balance.get("asset_type") == "credit_alphanum4" and \
                balance.get("asset_code") == asset_to_add.code and \
                balance.get("asset_issuer") == asset_to_add.issuer:
                    return f"Trustline for {asset_to_add.code} already exists."

            transaction = (
                TransactionBuilder(
                    source_account=destination_account,
                    network_passphrase=network_passphrase,
                    base_fee=bfee
                )
                .append_change_trust_op(asset=assets[self.asset_code])
                .set_timeout(30)
                .build()
            )

            transaction.sign(destination)
            server.submit_transaction(transaction)
            return f"Trustline for {asset_to_add.code} created successfully."

        except Exception as e:
            message = (f"<br>Trustline creation failed: {e}<br>")
            return message

    def transfer_asset(self, server, source, destination, bfee, network_passphrase):
        try:
            assets = {
                "USDC": Asset("USDC", os.getenv("USDC_ADDRESS")),
                "EURC": Asset("EURC", os.getenv("EURC_ADDRESS")),
            }

            source_account = server.load_account(source.public_key)

            transaction_builder = TransactionBuilder(
                source_account=source_account,
                network_passphrase=network_passphrase,
                base_fee=bfee
            )

            if self.asset_code in assets:
                transaction_builder.append_payment_op(
                    destination=destination.public_key, 
                    amount=self.amount, 
                    asset=assets[self.asset_code]
                )

            else:
                return f"Asset {self.asset_code} not supported."

            transaction = transaction_builder.set_timeout(30).build()
            transaction.sign(source)
            server.submit_transaction(transaction)
            message = (
                f"<br>Asset transferred successfully.<br><br>"
                f"<strong>From account:</strong> <br> {source_account} <br><br>"
                f"<strong>To account:</strong> <br> {destination.public_key} <br><br>"
                f"<strong>Value:</strong> <br> {self.amount} {self.asset_code} <br>"
            )
            return message
        
        except Exception as e:
            message = (f"<br>Asset transfer failed: {e}<br>") 

    def save_wallet_to_db(self, public_key, secret_key, seed_phrase, hexadecimal, password):
        """
        Salva os dados da carteira no MongoDB com os valores criptografados usando Fernet.
        """
        try:
            encrypted_data = {
                "keypair": fernet.encrypt(public_key.encode()).decode(),
                "seed": fernet.encrypt(secret_key.encode()).decode(),
                "seed_phrase": fernet.encrypt(seed_phrase.encode()).decode(),
                "hexadecimal": fernet.encrypt(hexadecimal.encode()).decode(),
                "password": fernet.encrypt(password.encode()).decode()
            }

            wallet_data_collection.insert_one(encrypted_data)
            
        except Exception as e:
            print(f"Failed to save encrypted wallet to MongoDB: {e}")

    def generate_seed_phrase(self, secret_key):
        """
        Converts a Stellar secret key into a human-readable seed phrase.
        
        :return: Seed phrase and its hexadecimal equivalent.
        """
        try:
            with open('words_phrase.csv', mode='r', encoding='utf-8') as file:
                word_list = {row[0]: row[1] for row in csv.reader(file) if len(row) == 2}
            
            passphrase = [word_list.get(secret_key[i:i+2], "??") for i in range(0, len(secret_key), 2)]
            hexadecimal = base64.b32decode(secret_key, casefold=True).hex()
            return " ".join(passphrase), hexadecimal
        
        except Exception as e:
            raise ValueError(f"Error generating seed phrase: {e}")

    def execute(self):
        """
        Executes the process of creating a new Stellar account, setting up trustlines,
        and saving the account details.

        :return: A message detailing the results of the account creation.
        """
        try:
            # Configure the Stellar network and Horizon URL
            horizon_url = HORIZON_URL
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            server = Server(horizon_url=horizon_url)
            source = Keypair.from_secret(self.source_from_secret)
            destination = Keypair.random()
            source_account = server.load_account(account_id=source.public_key)
            minimum_balance = self.calculate_minimum_balance(server) # Calculate minimum_balance to create an account

            transaction = (
                TransactionBuilder(
                    source_account=source_account,
                    network_passphrase=network_passphrase,
                    base_fee=int(self.bfee),
                )
                .append_create_account_op(
                    destination=destination.public_key,
                    starting_balance=str(minimum_balance)
                )
                .set_timeout(30)
                .build()
            )

            transaction.sign(source) # Sign and submit the transaction
            response = server.submit_transaction(transaction)
            response_hash = response['hash']

            try:
                trustline_status = self.create_trustlines(server, destination, int(self.bfee), network_passphrase)
                
            except Exception as e:
                message = (f"<br>Error creating trustline: {e}<br>")
                return message

            try:
                transfer_status = self.transfer_asset(server, source, destination, int(self.bfee), network_passphrase)

            except Exception as e:
                message = (f"<br>Error transfer asset: {e}<br>")
                return message

            # Generate seed_phrase and save in the wallet_data in MongoDB
            seed_phrase, hexadecimal = self.generate_seed_phrase(destination.secret)
            self.save_wallet_to_db(destination.public_key, destination.secret, seed_phrase, hexadecimal, self.password)

            try:
                keypair = source_account
                existing_user = data_collection.find_one({"keypair": keypair})
                
                user_data = {
                        "keypair": destination.public_key,
                        "name": existing_user.get("name", ""),
                        "email": existing_user.get("email", ""),
                        "phone_number": existing_user.get("phone_number", ""),
                        "resaddress": existing_user.get("resaddress", ""),
                        "user": "activated",
                        "settings_datetime": datetime.datetime.utcnow()
                    }

                data_collection.insert_one(user_data)

            except Exception as e:
                message = (f"<br>Create account filling all setting fields<br>")
                return message

            message = (
                f"<br>Account created successfully.<br><br>"
                f"<strong>From account:</strong> <br> {source_account} <br><br>"
                f"<strong>To account:</strong> <br> {destination.public_key} <br> <br> {destination.secret} <br><br>"
                f"<strong>Seed Phrase:</strong> <br> {seed_phrase} <br><br>"
                f"<strong>Value:</strong> <br> {self.amount} {self.asset_code} <br><br>"
                f"<strong>Transaction Hash:</strong> <br> {response_hash}, {trustline_status} <br>"
            )
            return message
        
        except Exception as e:
            message = (f"<br>Error creating account: {e}<br>")
            return message