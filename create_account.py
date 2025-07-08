from stellar_sdk import Keypair, Network, Server, TransactionBuilder, Asset
import csv
import base64
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

def generate_buttons():
    return (
        f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
        f"<button id='copyBtn' onclick='copyToClipboard()'><i class='fas fa-copy'></i> Copy</button>"
        f"<button id='shareBtn' onclick='shareNotification()'><i class='fas fa-share-alt'></i> Share</button>"
    )

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

            print(f"base_reserve_stroops: {base_reserve_stroops}")

            base_reserve_xlm = base_reserve_stroops / 10_000_000

            print(f"root_info: {root_info}")
            print(f"base_reserve_stroops: {base_reserve_stroops}")
            print(f"base_reserve_xlm: {base_reserve_xlm}")

            # 2 para a conta + 1 para a trustline (se necessário)
            num_entries = 2  # conta nova sem extra data ou offers
            guarantee_value = 1 #

            if self.asset_code != "XLM":
                num_entries += 1  # adiciona 1 trustline

            minimum_balance = (base_reserve_xlm * num_entries) + guarantee_value
            print(f"minimum_balance: {minimum_balance}")
            return round(minimum_balance, 7)  # boa prática: até 7 casas decimais
        
        except Exception as e:
            raise Exception(f"Erro ao calcular minimum_balance: {e}")

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
            message = (
                f"<br>"
                f"Trustline creation failed: {e}<br>"
                f"<br>"
                + generate_buttons()
            )
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
                f"<br>"
                f"Asset transferred successfully."
                f"<strong>From account:</strong> <br> {source_account} <br>"
                f"<strong>To account:</strong> <br> {destination.public_key} <br>"
                f"<strong>Value:</strong> <br> {self.amount} {self.asset_code} <br>"
                f"<br>"
                + generate_buttons()
            )
            return message
        
        except Exception as e:
            message = (
                f"<br>"
                f"Asset transfer failed: {e}<br><br"
                f"<br>"
                + generate_buttons()
            ) 

    def save_to_csv(self, public_key, secret_key, seed_phrase, hexadecimal, password):
        """
        Saves account information to a CSV file.
        """
        try:
            with open('wallet_data.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([public_key, secret_key, seed_phrase, hexadecimal, password])
        except Exception as e:
            print(f"Failed to save to CSV: {e}")

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
            print("Connecting to Stellar Testnet server...")
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
                print(f"trustline_status: {trustline_status}")
                
            except Exception as e:
                message = (
                    f"<br>"
                    f"Error creating trustline: {e}<br><br"
                    f"<br>"
                    + generate_buttons()
                )
                return message

            try:
                transfer_status = self.transfer_asset(server, source, destination, int(self.bfee), network_passphrase)
                print(f"transfer_status: {transfer_status}")

            except Exception as e:
                message = (
                    f"<br>"
                    f"Error transfer asset: {e}<br><br"
                    f"<br>"
                    + generate_buttons()
                )
                return message

            # Generate seed_phrase and save in the wallet_data.csv
            seed_phrase, hexadecimal = self.generate_seed_phrase(destination.secret)
            self.save_to_csv(destination.public_key, destination.secret, seed_phrase, hexadecimal, self.password)

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
                message = (
                    f"<br>"
                    f"Create account filling all setting fields<br><br"
                    f"<br>"
                    + generate_buttons()
                )
                return message

            message = (
                f"<br>"
                f"Account created successfully.<br>"
                f"<strong>From account:</strong> <br> {source_account} <br>"
                f"<strong>To account:</strong> <br> {destination.public_key} <br> <br> {destination.secret} <br>"
                f"<strong>Seed Phrase:</strong> <br> {seed_phrase} <br>"
                f"<strong>Value:</strong> <br> {self.amount} {self.asset_code} <br>"
                f"<strong>Transaction Hash:</strong> <br> {response_hash}, {trustline_status} <br>"
                f"<br>"
                + generate_buttons()
            )
            return message
        
        except Exception as e:
            message = (
                f"<br>"
                f"Error creating account: {e}<br><br"
                f"<br>"
                + generate_buttons()
            )
            return message