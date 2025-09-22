# ========================
# Imports and Dependencies
# ========================

# Provides classes for manipulating dates and times.
# Used for timestamping and time-based logic.
import datetime

# 'random': used for generating random values (e.g., keys, codes)
# 'string': provides constants like string.ascii_letters for generating random strings
import random
import string

# MongoDB client for connecting to and interacting with a MongoDB database.
from pymongo import MongoClient

# Core components from the Stellar SDK for working with accounts, transactions, and assets.
# - Server: Connects to the Stellar Horizon API server
# - Keypair: Handles key generation and signing
# - TransactionBuilder: Builds transactions on the Stellar network
# - Asset: Represents a Stellar asset (e.g., USDC, EURC)
# - Network: Defines the Stellar network being used (testnet or mainnet)
# - exceptions: Handles general SDK exceptions during Stellar operations
from stellar_sdk import Server, Keypair, TransactionBuilder, Asset, Network, exceptions

# Specific exception for invalid Stellar secret keys (e.g., wrong format or checksum)
from stellar_sdk.exceptions import Ed25519SecretSeedInvalidError

# 'os': Provides access to environment variables and file system
# 'load_dotenv': Loads environment variables from a .env file into the Python environment
import os
from dotenv import load_dotenv

# Provides high-precision decimal arithmetic, useful for financial transactions.
# - Decimal: For representing exact values (e.g., account balances)
# - ROUND_DOWN: Ensures rounding behavior that avoids exceeding balances
from decimal import Decimal, ROUND_DOWN

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

# MongoDB Configuration
mongo_client = MongoClient(os.getenv("MONGODB_URI"))
data_db_withdraw = mongo_client["withdrawpocketblock"]
transactions_collection = data_db_withdraw["withdraws"]
settings_collection = data_db_withdraw["settings_value_fiat"]

class Withdraw:
    """
    A class to handle asset withdrawals and conversions to fiat using the Circle API.
    
    Attributes:
        network (str): The network type ('testnet' or 'mainnet').
        keypair (Keypair): The Stellar keypair associated with the account.
        seed (str): The secret seed for the Stellar account.
        withdraw_asset_code (str): The asset being withdrawn (e.g., 'XLM', 'USDC').
        withdraw_amount (float): The amount of the asset to be withdrawn.
        withdraw_fiat (str): The fiat currency for conversion.
    """

    def __init__(self, network, keypair, seed, withdraw_asset_code, withdraw_amount, withdraw_fiat):
        """
        Initializes the Withdraw object with user and transaction details.
        
        Args:
            network (str): The Stellar network ('testnet' or 'mainnet').
            keypair (Keypair): The Stellar keypair linked to the transaction.
            seed (str): The secret seed of the account.
            withdraw_asset_code (str): The asset code to be withdrawn.
            withdraw_amount (float): The amount to withdraw.
            withdraw_fiat (str): The fiat currency to convert the asset into.
        """
        self.network = network
        self.keypair = keypair
        self.seed = seed
        self.withdraw_asset_code = withdraw_asset_code
        self.withdraw_amount = withdraw_amount
        self.withdraw_fiat = withdraw_fiat

    def get_balance(self):
        """
        Fetches the balance of the specified asset from the Stellar trustline.

        Returns:
            float: The available balance of the asset, or 0 if not found.
        """
        
        # Determine the Horizon server URL based on the selected network
        server_url = HORIZON_URL
        
        try:
            # Connect to Stellar's Horizon server
            server = Server(horizon_url=server_url)
            account = server.accounts().account_id(self.keypair).call()
            asset_balance = "0" # Default asset balance

            # Loop through account balances to find the requested asset
            for balance in account["balances"]:
                # if (self.withdraw_asset_code == "XLM" and balance["asset_type"] == "native") or (balance.get("asset_code") == self.withdraw_asset_code):
                if (balance.get("asset_code") == self.withdraw_asset_code):
                    asset_balance = float(balance["balance"])
                    return asset_balance  # Return balance immediately

            return asset_balance  # If asset is not found, return 0

        except Exception as e:
            return f"Error fetching Stellar balance: {str(e)}"
    
    def has_trustline(self, account_id, asset_code, issuer):
        """
        Checks whether the given account has an existing trustline for a specific asset.

        Args:
            account_id (str): The public key of the account.
            asset_code (str): The asset code (e.g., 'XLM', 'USDC').
            issuer (str): The issuer of the asset.

        Returns:
            bool: True if a trustline exists, False otherwise.
        """
        try:
            # Configure the Stellar network and Horizon URL
            horizon_url = HORIZON_URL
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            server = Server(horizon_url=horizon_url)
            account_id_clean = account_id.split("#")[0].strip()
            account = server.load_account(account_id_clean)
            
            # Checks for the trustline
            for balance in account.balances:              
                if (
                    balance.get("asset_code") == asset_code and
                    balance.get("asset_issuer") == issuer and
                    balance.get("is_authorized", True) 
                ):
                    return True
                
            return False
        
        except Exception as e:
            message = (f"<br>Error checking trustline: {e}<br>")
            return False
    
    def create_trustline(self, account_id, asset_code, issuer):
        """
        Creates a trustline for the given asset if it does not exist.

        Args:
            account_id (str): The Stellar public key of the account.
            asset_code (str): The asset code for the trustline.
            issuer (str): The issuing account of the asset.

        Returns:
            dict: The response from Stellar if the trustline creation succeeds.
        """
        try:
            if not self.seed:
                raise ValueError("Secret key is required.")
            
            # Validate the secret key
            try:
                keypair = Keypair.from_secret(self.seed)
            except Ed25519SecretSeedInvalidError:
                raise ValueError("Invalid secret key.")
            
            public_key = keypair.public_key
            self.horizon_url = HORIZON_URL # Set the network's Horizon URL
            server = Server(horizon_url=HORIZON_URL)
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            source_account = server.load_account(public_key) # Load the Stellar account and prepare the trustline transaction
            asset = Asset(asset_code, issuer)

            transaction = (
                TransactionBuilder(
                    source_account=source_account,
                    network_passphrase=network_passphrase,
                    base_fee=100
                )
                .append_change_trust_op(asset=asset)
                .set_timeout(30)
                .build()
            )
            
            # Sign and submit the transaction
            transaction.sign(keypair)
            response = server.submit_transaction(transaction)
            return response
        
        except Exception as e:
            message = (f"<br>Error creating trustline: {e}<br>")
            return None
    
    def check_liquidity(self, send_asset, dest_asset, send_amount):
        """
        Checks if liquidity paths are available for a specific transaction.

        Args:
            send_asset (Asset): The asset being sent.
            dest_asset (Asset): The asset to be received.
            send_amount (float): The amount of the sending asset.

        Returns:
            bool: True if liquidity paths exist, False otherwise.
        """
        try:
            horizon_url = HORIZON_URL # Server url
            server = Server(horizon_url=horizon_url)
            paths = server.strict_send_paths(
                source_asset=send_asset,
                source_amount=str(send_amount),
                destination=[dest_asset]
            ).call()

            if len(paths['_embedded']['records']) > 0:
                return True
            
            else:
                return False
            
        except Exception as e:
            message = (f"Error checking liquidity: {e}")
            return False
        
    def withdraw_transaction(self, withdraw_amount, withdraw_name, withdraw_asset, withdraw_idnumber, description_withdraw, withdraw_type, withdraw_bank, withdraw_bank_ag, withdraw_bank_cc, withdraw_country, withdraw_pix, withdraw_fiat):
        """
        Executes the transaction based on the provided parameters and network settings.

        This method performs the following actions:
        - Checks if the sender's account has the necessary trustline.
        - Creates a trustline if it doesn't exist.
        - Sends the specified amount of the asset from the sender's account to the destination account.
        
        Returns:
            str: A message with the transaction result.
        """

        current_balance = self.get_balance()
        if Decimal(current_balance) < Decimal(self.withdraw_amount):
            return f"Erro: Saldo insuficiente. Saldo atual: {current_balance}, valor solicitado: {self.withdraw_amount}"

        try:
            horizon_url = HORIZON_URL
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            secret_key = self.seed

            if not secret_key:
                raise ValueError("Secret key is not provided.")

            source_keypair = Keypair.from_secret(secret_key)
            server = Server(horizon_url=horizon_url)
            source_account = server.load_account(account_id=source_keypair.public_key)

            # Consulta para encontrar o 'withdraw_account' pela 'withdraw_asset'
            accounts_collection = mongo_client["withdrawpocketblock"]["accounts_withdraw"]
            destination_account_data = accounts_collection.find_one({"withdraw_asset": self.withdraw_asset_code})

            if not destination_account_data:
                message = (f"<br>Erro: Destination account for asset {self.withdraw_asset_code} not found in database.<br>")
                return message

            # Atribuindo a 'withdraw_account' da conta de destino encontrada
            destination_account = destination_account_data["withdraw_account"]           
                        
            if self.withdraw_asset_code == 'USDC' or self.withdraw_asset_code == 'EURC':

                if self.withdraw_asset_code == "USDC":
                    settings = settings_collection.find_one({"withdraw_type": "USD"})

                elif self.withdraw_asset_code == 'EURC':
                    settings = settings_collection.find_one({"withdraw_type": "EUR"})

                else:
                    message = (f"<br>Error defining settings.<br>")

                try:
                    fee_withdraw = settings["fee"]
                    withdraw_amount = Decimal(self.withdraw_amount) + (Decimal(self.withdraw_amount) * Decimal(fee_withdraw))
                    withdraw_amount_value = withdraw_amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
                    withdraw_fee = Decimal(self.withdraw_amount) * Decimal(fee_withdraw)

                except (ValueError, TypeError) as e:
                    message = (f"<br>Error applying fee_withdraw: {e}<br>")
                
                # Definir o sender e o ativo com base na escolha do usuário
                if self.withdraw_asset_code == 'USDC':
                    send_asset = Asset("USDC", os.getenv("USDC_ADDRESS"))
                    asset = Asset("USDC", os.getenv("USDC_ADDRESS"))

                elif self.withdraw_asset_code == 'EURC':
                    send_asset = Asset("EURC", os.getenv("EURC_ADDRESS"))
                    asset = Asset("EURC", os.getenv("EURC_ADDRESS"))

                else:
                    message = (f"<br>Error: Sender asset invalid.<br>")
                    return message

                # Verificar se a conta tem a trustline
                has_trust = self.has_trustline(source_account, self.withdraw_asset_code, asset.issuer)

                if not has_trust:
                    trustline_response = self.create_trustline(destination_account, self.withdraw_asset_code, asset.issuer)

                    if trustline_response is None:
                        message = (f"<br>Criation of trustline break for {self.withdraw_asset_code}. Quiting.<br>")
                        return message

                source_account = server.load_account(account_id=source_keypair.public_key)

                try:

                    withdraw_amount = withdraw_amount_value
                    balance = self.get_balance()
                    balance = Decimal(balance)
                    min_length = 26
                    max_length = 35
                    txid_base = self.keypair[:10]
                    total_length = random.randint(min_length, max_length)
                    random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=total_length - len(txid_base)))
                    self.txid = txid_base + random_chars

                    transaction = (
                        TransactionBuilder(
                            source_account=source_account,
                            network_passphrase=network_passphrase,
                            base_fee=100
                        )
                        .append_path_payment_strict_send_op(
                            destination=destination_account,
                            send_asset=send_asset,
                            send_amount=str(withdraw_amount),
                            dest_asset=asset,
                            dest_min=str(withdraw_amount),
                            path=[]
                        )
                        .add_text_memo(self.txid[:16])
                        .set_timeout(30)
                        .build()
                    )

                    transaction.sign(source_keypair)
                    response = server.submit_transaction(transaction)
                    
                    try:
                        # Verifica se a transação foi bem-sucedida antes de salvar no MongoDB
                        if response and response.get("successful", False):

                            withdraw_fiat = withdraw_asset[:3]

                            withdraw_data = {
                                "txid": self.txid,
                                "withdraw_address": self.keypair,
                                "withdraw_name": withdraw_name,
                                "withdraw_idnumber": str(withdraw_idnumber).zfill(11).strip(),
                                "withdraw_type": withdraw_type,
                                "withdraw_description": description_withdraw,
                                "withdraw_asset": withdraw_asset,
                                "withdraw_fiat": withdraw_fiat,
                                "withdraw_amount": f"{float(withdraw_amount):.2f}",
                                "withdraw_fee": f"{float(withdraw_fee):.2f}",
                                "withdraw_pix": str(withdraw_pix).strip(),
                                "withdraw_bank": str(withdraw_bank).zfill(3).strip(),
                                "withdraw_bank_ag": str(withdraw_bank_ag).zfill(4).strip(),
                                "withdraw_bank_cc": str(withdraw_bank_cc).strip(),
                                "withdraw_country": str(withdraw_country).strip(),
                                "withdraw_response_blockchain": response,
                                "withdraw_blockchain_status": "SUCCESSFUL",
                                "withdraw_status": "PENDENTE",
                                "transaction_datetime": datetime.datetime.utcnow(),
                                "withdraw_envioid": None,
                                "withdraw_e2eid": None,
                                "withdraw_stark_bank_id": None,
                                "updated_idenvio_at": datetime.datetime.utcnow(),
                                "updated_at": datetime.datetime.utcnow()
                            }

                            try:
                                result = transactions_collection.insert_one(withdraw_data)
                                
                            except Exception as e:
                                import traceback
                                message = ("<br>Database error:<br>", traceback.format_exc()) # Error inserting into MongoDB

                            if result.acknowledged:
                                if withdraw_type == 'pix':
                                    message = (
                                        f"<br><strong>Withdrawal requested via PIX:</strong> <br><br>"
                                        f"<strong>Withdraw from account:</strong> <br> {self.keypair} <br><br>"
                                        f"<strong>Name:</strong> <br>{withdraw_name} <br><br>"
                                        f"<strong>ID Number:</strong> <br>{withdraw_idnumber} <br><br>"
                                        f"<strong>Received:</strong> <br> {str(self.withdraw_amount)} {self.withdraw_asset_code} <br><br>"
                                        f"<strong>Fee:</strong> <br> {str(withdraw_fee)} {self.withdraw_asset_code} <br><br>"
                                        f"<strong>PIX sent to key:</strong> <br> {str(withdraw_pix)} <br><br>"
                                        f"<strong>Descrição:</strong> <br>{description_withdraw} <br>"
                                    )

                                elif withdraw_type == 'bank_transfer':
                                    message = (
                                        f"<br><strong>Withdrawal requested via Bank Transfer:</strong> <br><br>"
                                        f"<strong>Withdraw from account:</strong> <br> {self.keypair} <br><br>"
                                        f"<strong>Name:</strong> <br>{withdraw_name} <br><br>"
                                        f"<strong>ID Number:</strong> <br>{withdraw_idnumber} <br><br>"
                                        f"<strong>Received:</strong> <br> {str(self.withdraw_amount)} {self.withdraw_asset_code} <br><br>"
                                        f"<strong>Fee:</strong> <br> {str(withdraw_fee)} {self.withdraw_asset_code} <br><br>"
                                        f"<strong>Bank:</strong> <br> {str(withdraw_bank)} <br><br>"
                                        f"<strong>AG:</strong> <br> {str(withdraw_bank_ag)} <br><br>"
                                        f"<strong>CC:</strong> <br> {str(withdraw_bank_cc)} <br><br>"
                                        f"<strong>Country:</strong> <br> {str(withdraw_country)} <br><br>"
                                        f"<strong>Description:</strong> <br>{description_withdraw} <br>"
                                    )

                                else:
                                    message = (f"<br>Invalid withdrawal type.<br>")

                                return message
                            
                            else:
                                message = (f"<br>Error saving data<br>")
                                return message
                        
                        else:
                            message = (f"<br>Transaction was not confirmed: {response}")
                            return message
                    
                    except Exception as e:
                        message = (f"<br>Error processing transaction: {str(e)}<br>")
                        return message

                except exceptions.BadRequestError as e:
                    message = (f"<br>Check your transaction parameters.<br>")
                    return message
                
        except Exception as e:
            message = (f"<br>Error during transaction.<br>")
            return message
